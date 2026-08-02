# Deploying Cyclowareness Sandbox

The whole product ships as one Docker image: a Node stage builds the SPA, the
Python image serves it same-origin with the API. Two ways to run it.

## Local (Docker)

```bash
docker compose up --build      # http://localhost:8000
```

`docker-compose.yml` also brings up the optional native-engine worker, Prometheus
and Grafana. For just the app: `docker build -t cyclowareness-sandbox . &&
docker run --rm -p 8000:8000 cyclowareness-sandbox`.

Verified from a clean clone on 2026-07-29: build, run, log in with
`analyst` / `analyst`, submit nine files of different shapes, and read every one
back through all five exports — no configuration of any kind.

### Working on the interface

The image serves the compiled SPA, so a change to `frontend/` needs a rebuild to
appear. For a live-reloading loop instead, run the API on :8000 and Vite in front
of it:

```bash
npm --prefix frontend run dev      # :5173, proxies /api to :8000
```

`vite.config.ts` reads `PORT` and `VITE_API_TARGET`, so a second checkout can run
its own pair without colliding.

### Where samples live

`SANDBOX_QUARANTINE` sets the quarantine root — the directory holding submitted
bytes, addressed by content hash and never executed by this service. It defaults
to a path inside the container, so **mount it if you want samples to survive a
restart**, and put it on a volume you are willing to have hostile files sitting
in. Retention deletes from it on a schedule; see `/api/admin/retention`.

**If you bind-mount it, give it to the container's user.** The image runs as
uid 10001, so a directory the host owns as root is unwritable and every
submission fails:

```bash
mkdir -p /var/lib/cyclowareness/quarantine
chown -R 10001:10001 /var/lib/cyclowareness/quarantine
```

The service refuses to start with a message naming the path and the uid if it
cannot write there. It used to start healthy and answer uploads with a bare
`500`, with the real cause only in the container log.

| Variable | Default | Notes |
|---|---|---|
| `SANDBOX_QUARANTINE` | in-container path | Quarantine root. Mount for persistence, and `chown` it to 10001. |
| `MAX_SAMPLE_MB` | `32` | Rejects larger uploads, and refuses a URL fetch whose content-length exceeds it. Not truncated — half an artefact analysed as if whole is a worse answer than none. Keep CAPE's `conf/web.conf` `max_sample_size` equal to it; `02-cape-repair.sh` step 5 does that from this value. |
| `DATABASE_URL` | SQLite file | PostgreSQL in production; Alembic owns the schema. |
| `TRUST_PROXY_HEADERS` | `false` | See below. Turn on **only** behind a proxy you control. |
| `PROXY_CLIENT_HEADER` | *(unset)* | Which header that proxy **writes**: `x-real-ip` or `x-forwarded-for`. Required with the above. |
| `METRICS_TOKEN` | *(unset)* | Bearer token for `/metrics`. Unset in production, `/metrics` is `404`. |
| `METRICS_PUBLIC` | `false` | Say out loud that `/metrics` may be read by anyone. |

### Behind a reverse proxy

Set `TRUST_PROXY_HEADERS=true` when — and only when — this process is reachable
*exclusively* through a proxy you control that overwrites or appends
`X-Forwarded-For`. It decides two things:

- the address written into the **chain of custody** (without it, every audit row
  records the proxy: measured, `172.17.0.1` on all 275 rows of one deployment);
- one of the identities the **rate limiter** charges.

Left off behind a proxy, every caller shares one address bucket — a limit that is
too strict. Turned on while the process is *directly* reachable, a caller can
forge the header, which lets them both mislabel their own audit trail and mint a
fresh rate-limit budget for every request. Off is the safe default; the failure
it causes is over-counting, and the failure the other way is no counting at all.

**You must also name the header your proxy writes**, with
`PROXY_CLIENT_HEADER`. There is no safe default, and this document used to bless
both configurations while the code guessed:

| Your proxy | Set |
|---|---|
| nginx with `proxy_set_header X-Real-IP $remote_addr` | `PROXY_CLIENT_HEADER=x-real-ip` |
| nginx with `proxy_add_x_forwarded_for`, AWS ALB, Cloudflare, Render, Heroku | `PROXY_CLIENT_HEADER=x-forwarded-for` |

Only the named header is read; the other is treated as client-written text, which
is what it is. Guessing broke both deployments in turn. `X-Real-IP` is a single
value a proxy *overwrites*, so preferring it is correct behind the first row —
and against the second, which sets no `X-Real-IP` at all, the client's own
`X-Real-IP` arrives untouched and is believed. Preferring the list is wrong in
the mirror case: reproduced with a real nginx in front of this image, a rotating
`X-Forwarded-For` walked thirty login attempts with **zero** 429s where the
control produced twenty, and wrote an address of the attacker's choosing into the
hash-chained chain of custody.

`X-Forwarded-For` is read **right to left**, because conventional proxies append
the peer they saw, so a client forging `X-Forwarded-For: 1.2.3.4` produces
`1.2.3.4, <real client>` and the last entry is what the proxy actually observed.
Every candidate must parse as an IP address; anything else falls back to the
socket peer.

Left unset — or set to anything other than those two values — nothing is believed,
the socket peer is used, and a warning naming both options is logged at startup of
the first such request. That is the same over-counting failure as leaving the
switch off, which is the direction to be wrong in.

### Configuration an operator has to know exists

Eleven settings were readable only from `backend/app/config.py`: absent from
every document here and from `.env.example`. `/api/capabilities` printed *"Set
`SAMPLE_RETENTION_DAYS` to bound the malware held on disk"* while naming a
variable the operator could not look up. They are all in `.env.example` now,
and the ones that change what the product PROMISES are here.

| variable | default | what it decides |
|---|---|---|
| `SIGNING_KEY` | *(empty)* | Whether the evidence is signed at all. |
| `SAMPLE_RETENTION_DAYS` | `0` | Days before the quarantined sample is deleted. `0` keeps it forever. |
| `REPORT_RETENTION_DAYS` | `0` | Days before the report row is deleted. `0` keeps it forever. |
| `RETENTION_SWEEP_HOURS` | `6` | How often the retention sweep runs. |
| `SOVEREIGN_MODE` | `true` | The core promise: no analysis data leaves this deployment. |
| `SOVEREIGN_ALLOW_URL_FETCH` | `true` | The one deliberate exception — see below. |
| `ENTITY_NAME` / `_COUNTRY` / `_SECTOR` / `_CONTACT` | *(empty)* | Copied verbatim into NIS2 Article 23 and DORA Article 19 records. |
| `DEFAULT_TENANT` / `ANALYST_TENANT` | `default` | Which tenant owns evidence submitted without one. |

**`SIGNING_KEY` is the sharp one.** It signs two different things: every
exported report's attestation, and the audit chain's **checkpoints** — the
signed anchors that make a re-chained audit table detectable. Unset is a real
state and nothing pretends otherwise: reports are stamped `UNSIGNED`, and
`GET /api/audit/verify` answers `anchored: false` with the reason beside a
still-`true` `ok`, because a self-consistent chain with nothing vouching for it
is exactly what that pair of fields is there to distinguish.

The consequence worth planning around: **a key added later cannot sign what was
already recorded.** Set it before the deployment takes its first sample.

```bash
python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"
```

**Retention is opt-in, and `0` means keep forever.** An unset policy must never
delete a customer's data, so nothing is removed until a number is chosen. The
sample and the report are separate: the sample is live malware on the operator's
disk, needed after the analysis only for a re-run, while the report is the
evidence the customer bought and normally outlives it by a long way. Every
deletion is written to the audit chain (`retention.sample_purged`,
`retention.report_purged`) — a deletion nobody can prove happened is not one an
auditor accepts.

**`SOVEREIGN_ALLOW_URL_FETCH` is the only hole in the sovereignty promise, and
it is not an exfiltration path**: submitting a URL for analysis *is* a request
to fetch it. It is separately controllable because an air-gapped deployment must
be able to close it.

**The entity fields identify the notifier, not the analyst.** The engine cannot
know who is running it; left empty, the incident record says operator input is
still required rather than inventing an entity.

### Health checks

`GET /api/health` (also `HEAD`) performs one database round-trip and answers
**503** with `{"status": "degraded", "database": "unreachable"}` when it fails.
It is the Docker `HEALTHCHECK` and render.yaml's `healthCheckPath`, and it used
to return constants — so a process that could not reach its database reported
healthy to both while answering 500 to every real request.

### Rate limits

In-process, sliding window, no external store. `X-RateLimit-Limit`,
`X-RateLimit-Remaining` and `X-RateLimit-Scope: process` on every response; a
`429` carries `Retry-After`.

| Path | Per credential | Per address |
|---|---|---|
| `POST /api/analyze*` | 20 / 60s | 100 / 60s |
| `POST /api/auth/login` | 10 / 300s | **10 / 300s** |
| `/api/jobs*` | 60 / 60s | 600 / 60s |
| everything else | 240 / 60s | 2400 / 60s |

Each request is charged to **every** identity it carries — its address, and its
API key or session token if it has one — and refused when any of them is out. A
caller who supplies a credential therefore cannot escape the address budget by
rotating it, which is how the login limit was previously worth nothing.

The two columns differ because the two buckets do different jobs. The credential
column is the product's limit. The address column is only a backstop against
credential rotation, so it is several times looser — with `TRUST_PROXY_HEADERS`
off every analyst shares one address, the Queue page polls every three seconds,
and a single shared 60/60s ceiling would have started refusing the third analyst
to open it. **Authentication is the exception and keeps them equal**: stopping a
password list from one address is the entire reason the address bucket exists.

Exempt: `GET /api/health`, `GET /metrics`, and `/api/dynamic/*` **only** when the
request carries the configured `X-Worker-Token`. `X-RateLimit-Scope: process`
means one instance is one budget: several replicas behind a load balancer each
permit the full rate, and a deployment that does that needs a shared store.

## Cloud (Render, from GitHub)

The service reads live in seconds; the only manual step is putting the repo on
GitHub, because that needs your account.

1. **Create the GitHub repo** (empty — no README/.gitignore): a new repository
   named `cyclowareness-sandbox` under your account.
2. **Push** (an SSH key for the account is already configured):

   ```bash
   git remote add origin git@github.com:<you>/cyclowareness-sandbox.git
   git push -u origin main
   ```

3. **Connect to Render**: at <https://dashboard.render.com/blueprints> choose
   *New Blueprint Instance* and point it at the repo. Render reads
   [`render.yaml`](render.yaml) and builds the Dockerfile.
   - The service is pinned to the **Standard (2 GB)** instance — required, because
     the analysis stack (YARA + oletools + pefile) exceeds the 512 MB tiers.
   - `SECRET_KEY` is generated by Render. To enable live features, set
     `ANTHROPIC_API_KEY`, `VT_API_KEY`, or a `DYNAMIC_WORKER_TOKEN` on the service
     (they are `sync: false`, never in git).
4. `autoDeploy` is on, so every push to the branch redeploys.

## The dynamic tier

The web service never detonates a sample. To run the native engine / open-source
sandboxes, deploy the [`worker/`](worker) image on a **disposable, network-isolated
Linux box you control** (see [`worker/README.md`](worker/README.md)), give it the
same `DYNAMIC_WORKER_TOKEN` and the API's URL, and it will claim jobs, detonate
off-host, and post behaviour back. Never run the worker on shared infrastructure.

**Three variables.** They do different jobs:

| Variable | Set on | Effect |
|---|---|---|
| `DYNAMIC_WORKER_TOKEN` | API **and** worker | The shared secret for `/api/dynamic/*`. Without it the seam returns 503 and no worker can attach. |
| `SANDBOX_DYNAMIC_WORKER` | API only | Declares that a worker is EXPECTED. It does not gate what a report says: a worker that posts a report is recorded as having detonated the sample either way. What the flag changes is whether "not detonated" reads as a finding or as this deployment simply not having a dynamic tier. |
| `CONTAINMENT_CHECK` | worker only | A command answering "is this host safe to detonate on, right now?". Exit 0 means contained. **Set this on any host that runs real samples.** |

The second is deliberately a declaration rather than a probe: claiming
behavioural analysis is a statement about hardware someone owns, so it should be
switched on by whoever owns it and never inferred. It was also undocumented until
now, which meant an operator could follow this page exactly and still see "no
dynamic worker attached" on every report.

The third is the gate that used to be a procedure. Containment was verified by
remembering to run a script before a run, which is not containment — and it could
not have worked anyway, because the rules lived where CAPE's rooter inserts an
ACCEPT above them, so a host verified at one moment could be open the next. The
worker now checks before every batch and **fails closed**: a timeout, a missing
command, a crash, a non-zero exit or an unparseable answer all mean *not
contained*, and the whole batch is reported as blocked rather than detonated.

On the reference host:

    CONTAINMENT_CHECK=/usr/local/sbin/cyclo-containment-status.sh

Leaving it unset is allowed — a Qiling-only laptop confines by construction — but
it is never silent: the worker logs `containment gate: NOT CONFIGURED` at startup,
because "no gate" and "gate passing" must not read the same way in a log.
`CONTAINMENT_CHECK_TIMEOUT_SECONDS` (default 15) bounds it; a gate that hangs is a
gate that gets removed.

For a full detonation host — Windows guest, containment, golden snapshot — see
[`infra/detonation-host/README.md`](infra/detonation-host/README.md), and run its
`verify-containment.sh` before any real sample.
