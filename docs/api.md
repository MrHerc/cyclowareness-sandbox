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
Auth: required. Query: `status` (optional filter), `limit` (default 50, max 200).
Returns a list of `JobSummary` (top-level jobs only; archive members nest under
their parent). Summaries omit the heavy analysis payload.

```bash
curl "http://localhost:8000/api/jobs?limit=20" -H "X-API-Key: demo-key"
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
Auth: none. `{ "status": "ok", "service", "env", "ai_provider" }`.

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
`{ public_id, sha256, family, size_bytes, sample_url }`.

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
keep the current value. Normalised to sum to 1. `422` if negative or both zero.

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

---

## Status and family enums

Job `status`: `queued`, `running`, `awaiting_password`, `completed`, `failed`.
Job `source`: `upload`, `url`, `archive_member`. Detonatable families for the
dynamic queue: `pe`, `elf`, `script`, `office`, `pdf`. Risk bands: `low` (0–29),
`medium` (30–59), `high` (60–79), `critical` (80–100).
