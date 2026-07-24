# Cyclowareness Sandbox

**Static-first file & URL threat analysis.** Upload a file or paste a URL; the
service quarantines the sample (**never executes it on the web server**),
analyses it with PE / Office / script / PDF / ELF parsers and a YARA engine,
extracts indicators, scores the risk with a transparent rule + model hybrid, and
exports the result as JSON, STIX 2.1 or PDF. Dynamic detonation — the native
engine and the open-source sandbox integrations — runs **off-host** through a
worker seam, so hostile code never runs on shared infrastructure.

Built to the national "Advanced Threat Protection" sandbox brief: file and URL
ingest, encrypted-archive password handling, static and dynamic analysis, a
rule + AI hybrid score, JSON / PDF / STIX export, a REST API, a feedback loop,
and an operator dashboard.

---

## Contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [The two halves: web service and worker](#the-two-halves-web-service-and-worker)
- [How the score works](#how-the-score-works)
- [Security model](#security-model)
- [Integration matrix](#integration-matrix)
- [REST API](#rest-api)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Further reading](#further-reading)

## What it does

1. **Ingest.** A file upload or a URL. URLs are downloaded server-side behind an
   SSRF guard that refuses private, loopback and cloud-metadata addresses.
2. **Quarantine.** The sample is written under its content hash, owner-read-only,
   never marked executable. The submitted filename is treated as data, never as
   a path.
3. **Identify & unpack.** Content-based type identification; archives are listed
   and their members promoted to child analyses. Encrypted archives pause and
   ask for a password — never brute-forced.
4. **Static analysis.** Per-family parsers (PE imports/entropy, Office macros,
   script obfuscation and IOCs, PDF actions, ELF sections) plus a YARA engine.
   Nothing here executes the sample.
5. **Score.** A rule component (severity-weighted, saturating) blended with a
   self-written expert-weighted logistic model over eight features. Every point
   is explainable.
6. **Report.** A UI verdict with drill-down, plus JSON, STIX 2.1 and PDF export.
7. **Feedback & re-analysis.** Analysts mark false/true positives and re-run.
8. **Dynamic tier (optional).** An off-host worker detonates the sample and posts
   behaviour back, which merges into the verdict and re-scores.

## Quick start

### With Docker (whole product, one image)

```bash
docker compose up --build        # API + UI on http://localhost:8000
```

The API also serves the compiled UI, so the whole thing is one origin. The
optional native-engine worker, Prometheus and Grafana come up with it — see
[`docker-compose.yml`](docker-compose.yml).

### Manual (development)

```bash
# backend
cd backend
python -m venv .venv && . .venv/Scripts/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
set APP_ENV=demo                                      # PowerShell: $env:APP_ENV="demo"
uvicorn app.main:app --port 8000

# frontend (separate shell)
cd frontend
npm ci
npm run dev                                           # http://localhost:5173, proxies /api
```

Interactive API docs: <http://localhost:8000/docs>. In the demo build the analyst
login (`analyst` / `analyst`) and the programmatic API key (`demo-key`) are
printed at startup. `APP_ENV=production` refuses to boot on a placeholder secret
or a default password.

## The two halves: web service and worker

| | Runs where | Executes the sample? | What it produces |
|---|---|---|---|
| **Web service** (`backend/`) | anywhere, incl. managed hosting | **No** — parsing + YARA only | static verdict + report |
| **Worker** (`worker/`) | a disposable Linux box you control | Yes, under isolation/emulation | behaviour merged back over HTTP |

Static analysis is safe to run anywhere. Dynamic analysis needs a disposable,
network-isolated machine with kernel-level control, which a managed PaaS does not
and should not provide. The worker fulfils that contract off-host and posts its
findings back in the same vocabulary the static analyzers use, so a dynamic
finding scores and displays identically to a static one.

**Every report states which tiers actually ran.** A verdict computed without
dynamic analysis is a verdict with a *stated* blind spot — never one dressed up
as a behavioural analysis that never happened.

## How the score works

`final = 0.6 × rule + 0.4 × model` (the split is tunable at runtime under
**Tuning**), banded **0–29 low · 30–59 medium · 60–79 high · 80–100 critical**.

- **Rule component** — severity-weighted with per-band saturation, so twenty low
  findings never outweigh one critical.
- **Model component** — an expert-weighted logistic regression over eight
  features (YARA hits, entropy, capability signals, IOC density, extension
  mismatch, obfuscation layers, auto-exec, embedded executable). Coefficients are
  set from domain knowledge, **labelled as expert-weighted rather than
  corpus-trained everywhere they appear**, and every feature's contribution is
  shown. `fit()` is provided for the day real labels exist.

Full detail and the hackathon-rubric mapping:
[`docs/scoring-and-rubric.md`](docs/scoring-and-rubric.md).

## Security model

The input is hostile by definition, so the controls are the product:

- The web service **never executes a sample** — enforced by a test that forbids
  `subprocess`/`eval`/`exec` from ever reaching the engine.
- Content-addressed, no-exec quarantine; streaming size cap; attacker-controlled
  filename carried as metadata, never as a path.
- SSRF-guarded URL fetcher; path-traversal-guarded SPA serving.
- No brute-forcing of encrypted archives.
- Every mutating route is authenticated (HMAC session token or API key).

Full threat model: [`SECURITY.md`](SECURITY.md).

## Integration matrix

The engine catalog spans a native engine, an emulator, four open-source
sandboxes, and threat intelligence. `/api/capabilities` reports which are enabled
on a given deployment, and the **Integrations** page renders the matrix.

| Engine | Kind | Tier | Enable with |
|---|---|---|---|
| Native engine | in-house | dynamic | worker + `DYNAMIC_WORKER_TOKEN` |
| Qiling | emulator | dynamic | worker |
| Firejail | open-source sandbox | dynamic | worker (Linux) |
| Cuckoo | open-source sandbox | dynamic | `CUCKOO_URL` |
| CAPEv2 | open-source sandbox | dynamic | `CAPEV2_URL` |
| Strelka | open-source sandbox | static | `STRELKA_URL` |
| Joe Sandbox | open-source sandbox | dynamic | `JOE_API_KEY` |
| VirusTotal | threat intel | static | `VT_API_KEY` |

Details and current status: [`docs/sandbox-matrix.md`](docs/sandbox-matrix.md).

## REST API

`POST /api/analyze` (file) and `POST /api/analyze/url`, then
`GET /api/result/{id}`. Plus job list, password resume, re-analyze, feedback,
`export.json` / `export.stix` / `export.pdf`, `GET /api/capabilities`,
`PUT /api/admin/weights`, the `/api/dynamic/*` worker seam, and Prometheus
`/metrics`. Full reference with curl examples: [`docs/api.md`](docs/api.md).

```bash
curl -X POST http://localhost:8000/api/analyze -H "X-API-Key: demo-key" -F "file=@suspicious.ps1"
curl http://localhost:8000/api/result/<public_id> -H "X-API-Key: demo-key"
```

## Project layout

```
backend/          FastAPI service (never executes a sample)
  app/engine/     the analysis engine: contracts, analyzers, YARA, scoring,
                  archives, fetcher, pipeline, report, integrations
  app/api/        HTTP routes: analyze/result, auth, admin, dynamic seam, meta
  tests/          pytest suite incl. the never-execute invariant
worker/           off-host native engine + sandbox runners (own Docker image)
frontend/         React + TS + Tailwind dashboard on the instrument design system
infra/            Prometheus + Grafana
docs/             architecture, scoring/rubric, sandbox matrix, API
```

Architecture and the module map: [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Testing

```bash
cd backend && APP_ENV=demo python -m pytest -q
```

The suite covers the analysis pipeline, scoring, archive/password handling, the
SSRF guard, report exports, the full API, and the load-bearing invariant that no
code path in the engine can execute a sample.

## Further reading

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — system design and module map
- [`SECURITY.md`](SECURITY.md) — threat model and controls
- [`docs/scoring-and-rubric.md`](docs/scoring-and-rubric.md) — the score, and the rubric mapping
- [`docs/sandbox-matrix.md`](docs/sandbox-matrix.md) — the integration catalog
- [`docs/api.md`](docs/api.md) — full API reference
- [`worker/README.md`](worker/README.md) — running the off-host worker safely

## Licence

MIT — see [`LICENSE`](LICENSE).
