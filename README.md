# Cyclowareness Sandbox

**Static-first file & URL threat analysis.** Upload a file or paste a URL; the
service quarantines the sample (**never executes it**), analyses it with PE /
Office / script / PDF / ELF parsers and a YARA engine, extracts IOCs, scores the
risk with a transparent rule + model hybrid, and exports the result as JSON,
STIX 2.1 or PDF. Dynamic detonation — the native engine and open-source sandbox
integrations — runs **off-host** through a worker seam, so hostile code never
runs on the web server.

Built to the national sandbox hackathon brief ("Advanced Threat Protection"):
file/URL ingest, encrypted-archive password handling, static + dynamic analysis,
rule + AI scoring, JSON/PDF/STIX export, a REST API, a feedback loop, and an
operator dashboard.

> Status: **backend complete and verified** (analysis pipeline, REST API, auth,
> dynamic-tier seam, metrics). Frontend, the native-engine worker, the
> open-source sandbox adapters, Docker/CI, and the test suite land in the
> increments that follow — see [`docs/`](docs/) and the commit history.

---

## Quick start (backend)

```bash
cd backend
python -m venv .venv && . .venv/Scripts/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
set APP_ENV=demo                                    # PowerShell: $env:APP_ENV="demo"
uvicorn app.main:app --port 8000
```

Open <http://localhost:8000/docs> for the interactive API. In the demo build the
analyst login is printed at startup (`analyst` / `analyst`) and the programmatic
API key is `demo-key`.

```bash
# submit a file
curl -X POST http://localhost:8000/api/analyze \
     -H "X-API-Key: demo-key" -F "file=@suspicious.ps1"
# read the verdict
curl http://localhost:8000/api/result/<public_id> -H "X-API-Key: demo-key"
```

## What runs where

| Tier | Where | Executes the sample? |
|------|-------|----------------------|
| **Static** (parsers + YARA + scoring) | in this process | **No** — parsing only |
| **Dynamic** (native engine, Cuckoo/CAPEv2/Firejail/Qiling) | off-host worker | Yes, on isolated hardware the operator controls |

The verdict always states which tiers actually ran. A score computed without
dynamic analysis is a score with a **stated** blind spot — not one dressed up as
a behavioural verdict that never happened.

## Design rules

- **A sample is never executed by the web service.** Static analysis parses; it
  does not run. Detonation happens only in the off-host worker.
- **Every point of the score is explainable.** The rule component is
  severity-weighted with saturation; the model is an expert-weighted logistic
  regression over eight features, and each feature's contribution is shown. It
  is labelled as expert-weighted, not corpus-trained, everywhere it appears.
- **"We did not look" ≠ "we looked and it was clean."** An analyzer that could
  not run says so, with a reason.

See [`docs/architecture.md`](docs/architecture.md) and
[`docs/scoring-and-rubric.md`](docs/scoring-and-rubric.md) for the full design
and the mapping to the hackathon scoring criteria.

## Licence

MIT — see [`LICENSE`](LICENSE).
