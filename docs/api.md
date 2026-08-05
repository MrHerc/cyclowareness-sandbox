# API reference

Every endpoint of the Cyclowareness Sandbox service. The API and the SPA are one
process on one origin; examples below assume `http://localhost:8000`.

## Authentication

Analyst-facing routes accept **either** credential:

- **Session token** — `Authorization: Bearer <token>`, obtained from
  `POST /api/auth/login`. Used by the web UI. HMAC-signed, expiring.
- **API key** — `X-API-Key: <key>`. For programmatic access. In the demo build
  the key is `demo-key`.

Worker-facing routes (`/api/dynamic/*`) use a separate shared secret:
`X-Worker-Token: <DYNAMIC_WORKER_TOKEN>`. Public routes (`/api/health`,
`/api/capabilities/public`, `/metrics`) need no auth.

`GET /api/capabilities` — the FULL descriptor — requires a credential. Read
together, its fields are a map for getting a sample past the deployment: the
exact upload ceiling, the exact extension allowlist, and which analyzers are not
running today. The sovereignty posture a buyer reads before they have an account
stayed public, on `/api/capabilities/public`.

Implementation: [`backend/app/auth.py`](../backend/app/auth.py).

---

## Auth

### `POST /api/auth/login`
Auth: none. Body `{ "username": str, "password": str }`.
Returns `{ "token": str, "expires_at": <epoch>, "subject": str }`. `401` on bad
credentials (same message for wrong-user and wrong-password — no enumeration).

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst","password":"analyst"}'
```

### `POST /api/auth/logout`
Auth: required. Ends **every** session for the authenticated subject and returns
`204`.

The token is stateless, so this is what makes revocation possible at all:
logging out used to clear the browser's `localStorage` and nothing else, leaving
a token that had already left the browser valid for its full TTL. It bumps a
per-subject epoch that every later `_verify_token` compares against.

Every session, not just the presented one — there is a single analyst account,
so "log me out" and "log out everything I am" are the same intent, and the
narrower reading would leave a stolen token alive while the person who noticed
believes they have acted. Recorded in the chain of custody as `login.logout`.

```bash
curl -X POST http://localhost:8000/api/auth/logout   -H "Authorization: Bearer $TOKEN"
```

---

## Analysis

### `POST /api/analyze`
Auth: required. `multipart/form-data`: `file` (required), `password` (optional,
for an encrypted archive). Streams into quarantine, hashed as it goes. Returns
**`201`** with a `JobDetail`; analysis runs in the background — poll
`/api/result/{id}`. Errors: `413` too large, `422` empty.

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "X-API-Key: demo-key" \
  -F "file=@suspicious.ps1"
```

### `POST /api/analyze/url`
Auth: required. Body `{ "url": str }`. The server downloads the URL behind the
SSRF guard (refuses private/loopback/metadata addresses, re-checks every redirect
hop). Returns **`201`** with a `JobDetail`. Errors: `422` unsafe URL, `413` too
large, `502` fetch failed.

```bash
curl -X POST http://localhost:8000/api/analyze/url \
  -H "X-API-Key: demo-key" -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/sample.bin"}'
```

### `GET /api/result/{public_id}`
Auth: required. Returns the full `JobDetail` — verdict, per-analyzer results,
IOCs, score breakdown, tier record, and any archive-member child jobs. `404` if
unknown.

The `impact` object carries the Cyclowareness Impact Rating (CIR v1): `rating`,
`vector`, `base_score` (0-10), `severity`, the per-metric `metrics`, the
per-metric `rationale`, and a `disclaimer` stating what the number is. It is
derived from observed capability — **not a vulnerability score, and not CVSS**.
The full rubric is published in [impact-rating.md](./impact-rating.md).

```bash
curl http://localhost:8000/api/result/<public_id> -H "X-API-Key: demo-key"
```

### `GET /api/jobs`
Auth: required. Query: `status` (optional filter), `limit` (default 50, max 200),
`cursor` (preferred) or `offset` (default 0). Returns one page:

```json
{ "items": [ /* JobSummary */ ], "total": 269, "limit": 50, "offset": 0,
  "next_cursor": "1769683623.481000:412" }
```

**Page by `cursor`, not by `offset`.** Pass `next_cursor` back as `?cursor=` to
get the following page; `null` means there is no next page. OFFSET counts rows
from the top, so it is only correct while the top does not move — and this table
receives submissions continuously and has rows deleted by retention. Reproduced:
read page one, let one submission arrive, read page two by offset, and the last
row of page one is the first row of page two; delete one instead and a row is
served on no page at all. A cursor names the last row seen, so rows arriving
above it cannot shift the page.

`offset` still works and is still bounded, for a caller that wants page seven
directly.

Top-level jobs only; archive members nest under their parent, and summaries omit
the heavy analysis payload. `total` is the count after filtering and tenant
scoping and **before** `limit`/`offset`, so a caller can page to the end without
guessing: keep going until `offset + len(items) >= total`.

```bash
curl "http://localhost:8000/api/jobs?limit=20&offset=20" -H "X-API-Key: demo-key"
```

### `GET /api/jobs/stats`
Auth: required. Counts over every job the caller can see, rather than over one
page — which is what a dashboard needs and what paging cannot give it once the
table is larger than the maximum limit.

| Field | Meaning |
|---|---|
| `total` | every top-level job |
| `completed` | jobs in `completed` |
| `in_flight` | jobs in `queued` or `running` |
| `verdicts` | completed jobs by verdict; always carries `malicious`, `suspicious`, `clean` and `unclassified`, and always sums to `completed` |
| `needs_attention` | completed jobs whose verdict is malicious or suspicious — or, where there is no verdict, that scored 30 or more |
| `average_score` | mean `final_score` over completed jobs, to one decimal |
| `families` | `[{family, count}]` over all top-level jobs, largest first |
| `top_risk` | up to five `JobSummary`, worst verdict first and then worst score |

```bash
curl http://localhost:8000/api/jobs/stats -H "X-API-Key: demo-key"
```

---

## Job actions

### `POST /api/jobs/{public_id}/password`
Auth: required. Body `{ "password": str }`. Supplies the password for an
encrypted archive whose job parked in `AWAITING_PASSWORD`. Used once, never
stored; the engine never brute-forces. `409` if the job is not awaiting a
password.

```bash
curl -X POST http://localhost:8000/api/jobs/<id>/password \
  -H "X-API-Key: demo-key" -H "Content-Type: application/json" \
  -d '{"password":"infected"}'
```

### `POST /api/jobs/{public_id}/reanalyze`
Auth: required. Re-runs analysis on the same quarantined bytes (e.g. after new
YARA rules). `409` if already running.

```bash
curl -X POST http://localhost:8000/api/jobs/<id>/reanalyze -H "X-API-Key: demo-key"
```

### `POST /api/jobs/{public_id}/feedback`
Auth: required. Body `{ "verdict": "false_positive" | "true_positive", "note": str? }`.
Records an analyst's dispute of a verdict (the feedback loop). `422` on an
invalid verdict.

```bash
curl -X POST http://localhost:8000/api/jobs/<id>/feedback \
  -H "X-API-Key: demo-key" -H "Content-Type: application/json" \
  -d '{"verdict":"false_positive","note":"known-good internal tool"}'
```

---

## Exports

All auth: required; all take a job `public_id`. Implementation:
[`backend/app/engine/report.py`](../backend/app/engine/report.py).

### `GET /api/jobs/{public_id}/export.json`
Full analysis as JSON. Carries `submitted_at`, `started_at`, `completed_at`,
`duration_ms` and `generated_at` — every timestamp **UTC with an explicit
offset**, so a reader never has to guess whether a naive string is local time.
`generated_at` alone used to be the only time in the document, which made it a
report that could not say when the sample arrived.

### `GET /api/jobs/{public_id}/export.stix`
STIX 2.1 bundle of the extracted indicators (bounded). Always contains an
`observed-data` object carrying `first_observed` / `last_observed` — the bundle's
only timestamp, and previously emitted only when the sample was **not**
malicious. A malicious sample ships `indicator` objects (accusations) and a
non-malicious one ships the values as observables (sightings, no claim
attached); both now say when.

### `GET /api/jobs/{public_id}/export.pdf`
Rendered PDF report; `Content-Disposition: attachment`.

```bash
curl -OJ http://localhost:8000/api/jobs/<id>/export.pdf -H "X-API-Key: demo-key"
curl http://localhost:8000/api/jobs/<id>/export.stix -H "X-API-Key: demo-key"
```

### `GET /api/jobs/{public_id}/export.signed`
The Ed25519-attested evidence copy: the report, plus a detached signature over a
canonical subset of it, plus the public key id. A recipient verifies it without
trusting this deployment or its operator — which is the point, and the reason
`attestation.py` exists.

The signed half is built by subtraction from `export.json`, so anything that
export scrubs (the detonation host's name, the guest's address) is absent here
too. `reproducible_digest` is a single string that changes whenever any scored
input changes, so two copies of "the same job" taken either side of a
re-analysis will not compare equal — that is intended.

```bash
curl http://localhost:8000/api/jobs/<id>/export.signed -H "X-API-Key: demo-key"
```

### `GET /api/jobs/{public_id}/export.incident`
The regulator-facing record: NIS2 Article 23(4) stages with the deadlines the
Directive itself states, and the DORA Article 18/19 classification fields. Every
determination the tool cannot make — whether the incident is "significant" or
"major", the client counts, the economic exposure — is emitted as `null` and
named in `operator_input_required`, and the record carries a disclaimer saying
it is evidence to be completed and filed, not a filing.

`evidence.limitations` lists every reason not to read it at face value,
including a tier that ran and may not be concluded from.

```bash
curl http://localhost:8000/api/jobs/<id>/export.incident -H "X-API-Key: demo-key"
```

---

## Meta

### `GET /api/capabilities/public`
Auth: none. The two facts a browser needs before anyone has logged in: whether
this is a demo build (the login screen prints the seeded credentials from it)
and the sovereignty posture with its refusal tally.

The posture is public deliberately — an auditor asked to accept "your files
never leave the building" can read the switch, the destinations it governs and
the number of times it fired without an account. The refusal *list* is not here:
each entry carries what was refused (a submitted URL, a sample's SHA-256), so
the proof would itself be a disclosure.

```bash
curl http://localhost:8000/api/capabilities/public
```

### `GET /api/capabilities`
Auth: analyst session or API key. The full descriptor: the upload ceiling, the
extension allowlist, the static analyzers and which of them are unavailable, the
YARA rule count, the dynamic tier's state and reason, the configured
integrations, and whether the quarantine is mounted `noexec`.

It requires a credential because, read together, those fields are a map for
getting a sample past this deployment — the exact size to exceed, the exact
extension to avoid, and which analyzers are not running today.

```bash
curl http://localhost:8000/api/capabilities -H "X-API-Key: demo-key"
```

### `GET /api/health`
Auth: none. `GET` and `HEAD`. Performs one database round-trip.

`200` → `{ "status": "ok", "service", "env", "ai_provider", "database": "ok" }`
`503` → `{ "status": "degraded", …, "database": "unreachable" }`

The Docker `HEALTHCHECK` and render.yaml's `healthCheckPath` both call it, so it
has to be able to fail: returning constants meant a process that could not reach
its database reported healthy while answering 500 to every real request.

### Rate limiting

Every response carries `X-RateLimit-Limit`, `X-RateLimit-Remaining` and
`X-RateLimit-Scope: process`. A `429` carries `Retry-After` and the usual
`{"detail": str}`.

Each rule has TWO ceilings, and a request is charged to both:

| Path | Per credential | Per address |
| --- | --- | --- |
| `POST /api/analyze*` | 20 / 60s | 100 / 60s |
| `POST /api/auth/login` | 10 / 300s | 10 / 300s |
| `/api/jobs*` | 60 / 60s | 600 / 60s |
| everything else | 240 / 60s | 2400 / 60s |

The credential ceiling is the product's limit — how much one API key or session
may do. The address ceiling only stops a caller minting a fresh credential
bucket per request, so it is deliberately looser: with `TRUST_PROXY_HEADERS`
off (the default), every analyst in an organisation shares one address, and a
tight one would throttle the third person to open the Queue page. Login keeps
them equal on purpose.

`X-RateLimit-Limit` reports the ceiling of whichever bucket is **tightest for
this caller**, which is not always the credential one — an anonymous caller on a
read path is bounded by the address bucket. Do not assume the header always
matches the credential column above; it is the number that will actually stop
you.

Exempt: `GET /api/health`, `GET /metrics`, and `/api/dynamic/*` with a valid
worker token. See DEPLOY.md for how a request's identity is decided.

### `GET /api/capabilities`
Auth: none. What this deployment can honestly do: YARA rules loaded, static
analyzers imported (and any that failed to import), whether a dynamic worker is
attached, the scoring model and live weights, the integration matrix
(`configured` per engine — no secrets), supported extensions, and whether metrics
are enabled.

It also carries the sovereignty posture and the running **count** of refused
outbound calls, per destination. The count is the auditable claim, and it is
deliberately readable without an account so a buyer can check the posture before
they have one.

```bash
curl http://localhost:8000/api/capabilities
```

### `GET /api/sovereignty/refusals`
Auth: analyst. The refusals **in full** — when, which destination, and what was
refused.

Split off `/api/capabilities` because the two answer different questions. "How
many outbound calls did you refuse" is a posture; "which URLs and which sample
hashes" is analysis data. Each entry's `detail` is the thing itself — for
`url_fetch` the submitted URL verbatim, for `virustotal` the sample's SHA-256 —
so on the unauthenticated endpoint the proof that nothing left the building was
a live feed of what every tenant had been analysing.

```bash
curl -H "X-API-Key: demo-key" http://localhost:8000/api/sovereignty/refusals
```

### `GET /metrics` (closed by default in production)
Auth: `METRICS_TOKEN` as a bearer token, unless `METRICS_PUBLIC=true` or this is
a demo build. With neither set, `APP_ENV=production` answers **404**: these
counters are a customer's daily volume, malicious share and analysis latency, and
an open endpoint publishes them to anyone with no credential and no trace.
Deliberately not the analyst session — a Prometheus scraper cannot log in.

Prometheus exposition. Degrades to a stub line if `prometheus_client`
is not installed. Metrics include `sandbox_uploads_total`,
`sandbox_upload_rejects_total`, `sandbox_url_fetch_*`, `sandbox_jobs_*`,
`sandbox_yara_hits_total`, `sandbox_dynamic_reports_total`,
`sandbox_reports_generated_total`. Source: [`backend/app/metrics.py`](../backend/app/metrics.py).

---

## Dynamic tier (worker-only)

All require `X-Worker-Token: <DYNAMIC_WORKER_TOKEN>`. When no token is configured
the whole seam returns `503`. Implementation:
[`backend/app/api/dynamic.py`](../backend/app/api/dynamic.py).

### `GET /api/dynamic/queue`
Query: `limit` (default 20, max 100). Completed jobs of a detonatable family
whose dynamic tier has not run yet. Each item:
`{ public_id, sha256, family, size_bytes, sample_url, suffix }`.

`suffix` is the submitted file's extension, sanitised to one dot plus 1–8 ASCII
alphanumerics (`".ps1"`, `".exe"`, or `""`). Write the sample to a path ending in
it. It is not cosmetic: a detonation sandbox picks its analysis package from the
file name, and CAPEv2 handed a `.sample` falls back to `generic`. Measured on one
PowerShell sample, that was the difference between 250s / 4 processes / 38
signatures and 28s / 1 process / 8 signatures — with no error either way.

```bash
curl http://localhost:8000/api/dynamic/queue -H "X-Worker-Token: $DYNAMIC_WORKER_TOKEN"
```

### `GET /api/dynamic/sample/{public_id}`
Returns the raw quarantined bytes (`application/octet-stream`) for the worker to
detonate. Path is derived from the content hash. `404` unknown job, `410` sample
purged. (Production should upgrade this to a signed, single-use URL.)

```bash
curl -o sample.bin http://localhost:8000/api/dynamic/sample/<id> \
  -H "X-Worker-Token: $DYNAMIC_WORKER_TOKEN"
```

### `POST /api/dynamic/report/{public_id}`
Body: `DynamicReportIn`. Merges the worker's behavioural findings into the job and
re-scores. Returns the updated `JobDetail`.

```jsonc
{
  "engine": "native",              // native | cuckoo | capev2 | firejail | qiling | ...
  "worker": "lab-worker-1",
  "ran": true,
  "unavailable_reason": null,
  "signals": [
    { "id": "sandbox.native.process_injection",
      "title": "Injected into a remote process",
      "severity": "high", "detail": "...", "evidence": {} }
  ],
  "facts": {},
  "iocs": { "urls": [], "domains": [], "ips": [], "emails": [],
            "hashes": [], "file_paths": [], "registry_keys": [], "mutexes": [] },
  "duration_ms": 4200,
  "timeline": [ { "t_ms": 120, "kind": "process", "detail": "CreateProcess cmd.exe" } ]
}
```

```bash
curl -X POST http://localhost:8000/api/dynamic/report/<id> \
  -H "X-Worker-Token: $DYNAMIC_WORKER_TOKEN" -H "Content-Type: application/json" \
  -d @report.json
```

---

## Admin

Auth: required (analyst). Runtime scoring weights; in-memory, reset on restart.
Implementation: [`backend/app/api/admin.py`](../backend/app/api/admin.py).

### `GET /api/admin/weights`
Returns `{ "rule": float, "model": float }` (the live split).

### `PUT /api/admin/weights`
Body `{ "rule_weight": float?, "ai_weight": float? }` — either may be omitted to
keep the current value. Normalised to sum to 1, so only the ratio matters.

`422` unless both values are **finite**, **non-negative**, **at most 1e6**, and
**sum to more than zero**. Every one of those is load-bearing rather than
defensive: `NaN` passed the old checks (it compares False to everything), left
the process weights non-finite, and made this endpoint, `/api/capabilities` and
the signed export all answer 500 while every new submission wrote a non-finite
score — which PostgreSQL stores, so the jobs list then failed for every analyst
until the row was deleted. `1e308` overflowed the sum to infinity and normalised
both weights to zero, which silently took every verdict to 0.0 / low.

Admin routes need an **interactive session**. `require_admin` answers 403 to an
API key, deliberately: a submit-only credential handed to a pipeline must not be
able to re-weight scoring for every user of the deployment.

```bash
# There is no cookie authentication in this API. Every authenticated route
# takes `Authorization: Bearer <token>`; the token is in the login response
# body. The previous examples used `-c cookies.txt` / `-b cookies.txt` and
# could not have worked as printed.
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst","password":"analyst"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["token"])')

curl -X PUT http://localhost:8000/api/admin/weights -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rule_weight":0.7,"ai_weight":0.3}'
```

### `POST /api/admin/weights/reset`
Restores the default `0.6 / 0.4`.

```bash
curl -X POST http://localhost:8000/api/admin/weights/reset -H "Authorization: Bearer $TOKEN"
```

### `GET /api/admin/retention`
The configured retention windows and what is currently past them: how many jobs
would have their sample bytes purged, how many their reports, and how many are
held because another in-window job shares the same content hash.

### `POST /api/admin/retention/run`
Applies the policy now rather than waiting for the scheduler. Returns the counts
actually deleted. Every deletion writes an audit receipt, so a run is
reconstructable afterwards from `/api/audit` alone.

---

## Chain of custody

Append-only, hash-chained. Each entry commits to its predecessor, so an entry
cannot be altered or removed without breaking every entry after it.

### `GET /api/audit`
Query: `limit`, `offset`, `object_id`, `action`. The recorded events —
submission, password supply, reanalysis, feedback, each export, and each
retention deletion — with actor, object, timestamp and chain hash. Contains no
sample content and no secrets.

### `GET /api/audit/verify`
Re-walks the whole chain and reports whether it is intact, plus the sequence
number of the first break if not. This is the endpoint an auditor runs.

**Read two fields, not one.** `ok` says the chain's links verify — and internal
consistency is precisely what an attacker holding UPDATE on the table can
restore, by editing a row and recomputing the tail. `anchored` says whether the
signed Ed25519 checkpoints back that up; when it is `false`, `anchor_reason`
gives the cause (no checkpoint written yet, or no public key on this deployment
to check the existing ones against). `anchor` carries the full detail, including
`covers`, which states in plain words what the newest checkpoint does *not*
reach: events after it rest on the chain alone, and whoever holds the signing
key can forge both.

`ok: true, anchored: false` is a real and reportable state — it means the chain
is self-consistent and nothing independent vouches for it. It is deliberately
not an error, because a deployment without a signing key has not detected
tampering; it has declined to make a claim.

    ~~it answers the only question that matters about an audit log~~

That sentence was wrong in the way that matters most: until 2026-08-03 this
endpoint returned `ok: true` for a chain with no anchor at all, because it only
lowered `ok` on `broken_at`, a key neither "not anchored" branch sets.

### `GET /api/audit/export`
The chain as newline-delimited JSON, for archiving or ingesting elsewhere.

### `GET /api/attestation/pubkey`
The Ed25519 public key that signs report attestations, so a recipient can verify
a signed report without contacting this deployment again. Pair it with
[`tools/verify_report.py`](../tools/verify_report.py).

---

## Status and family enums

Job `status`: `queued`, `running`, `awaiting_password`, `completed`, `failed`.
Job `source`: `upload`, `url`, `archive_member`. Detonatable families for the
dynamic queue: `pe`, `elf`, `script`, `office`, `pdf`. Risk bands: `low` (0–29),
`medium` (30–59), `high` (60–79), `critical` (80–100).

---

## Unknown endpoints

Any path under `/api` that no route above claims returns **`404`** with the same
`{"detail": str}` body as every other error, for every HTTP method.

This is worth stating because it was not true. In the Docker image the compiled
SPA is served by the same process, and its client-routing fallback answered for
every unclaimed path — so `GET /api/analyse` (one letter from `/api/analyze`)
returned `200 text/html` with the UI's `index.html` in the body. A client that
decides success from the status code got a parse error at best, and at worst
treated an empty page as an empty result.
