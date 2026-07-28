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
`/api/capabilities`, `/metrics`) need no auth.

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
`offset` (default 0). Returns one page:

```json
{ "items": [ /* JobSummary */ ], "total": 269, "limit": 50, "offset": 0 }
```

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
Full analysis as JSON.

### `GET /api/jobs/{public_id}/export.stix`
STIX 2.1 bundle of the extracted indicators (bounded).

### `GET /api/jobs/{public_id}/export.pdf`
Rendered PDF report; `Content-Disposition: attachment`.

```bash
curl -OJ http://localhost:8000/api/jobs/<id>/export.pdf -H "X-API-Key: demo-key"
curl http://localhost:8000/api/jobs/<id>/export.stix -H "X-API-Key: demo-key"
```

---

## Meta

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
`{"detail": str}`. Limits: 20/60s on `POST /api/analyze*`, 10/300s on
`POST /api/auth/login`, 60/60s on `/api/jobs*`, 240/60s elsewhere. Exempt:
`GET /api/health`, `GET /metrics`, and `/api/dynamic/*` with a valid worker
token. See DEPLOY.md for how a request's identity is decided.

### `GET /api/capabilities`
Auth: none. What this deployment can honestly do: YARA rules loaded, static
analyzers imported (and any that failed to import), whether a dynamic worker is
attached, the scoring model and live weights, the integration matrix
(`configured` per engine — no secrets), supported extensions, and whether metrics
are enabled.

```bash
curl http://localhost:8000/api/capabilities
```

### `GET /metrics`
Auth: none. Prometheus exposition. Degrades to a stub line if `prometheus_client`
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

```bash
curl -X PUT http://localhost:8000/api/admin/weights \
  -H "X-API-Key: demo-key" -H "Content-Type: application/json" \
  -d '{"rule_weight":0.7,"ai_weight":0.3}'
```

### `POST /api/admin/weights/reset`
Restores the default `0.6 / 0.4`.

```bash
curl -X POST http://localhost:8000/api/admin/weights/reset -H "X-API-Key: demo-key"
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
number of the first break if not. This is the endpoint an auditor runs; it
answers the only question that matters about an audit log.

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
