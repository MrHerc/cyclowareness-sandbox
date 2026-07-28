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
| `MAX_SAMPLE_MB` | `32` | Rejects larger uploads and truncates URL fetches. |
| `DATABASE_URL` | SQLite file | PostgreSQL in production; Alembic owns the schema. |
| `TRUST_PROXY_HEADERS` | `false` | See below. Turn on **only** behind a proxy you control. |

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

The value taken is the **last** entry of `X-Forwarded-For`, because conventional
proxies append the peer they saw (nginx's `proxy_add_x_forwarded_for`). A client
that forges `X-Forwarded-For: 1.2.3.4` therefore produces `1.2.3.4, <real
client>`, and the last entry is still what the proxy actually observed.

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

| Path | Limit |
|---|---|
| `POST /api/analyze*` | 20 / 60s |
| `POST /api/auth/login` | 10 / 300s |
| `/api/jobs*` | 60 / 60s |
| everything else | 240 / 60s |

Each request is charged to **every** identity it carries — its address, and its
API key or session token if it has one — and refused when any of them is out. A
caller who supplies a credential therefore cannot escape the address budget by
rotating it, which is how the login limit was previously worth nothing.

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
| `SANDBOX_DYNAMIC_WORKER` | API only | Declares that a worker exists. Until it is `1`/`true`/`yes`, every report states the sample was not detonated — even with a worker attached and posting. |
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
