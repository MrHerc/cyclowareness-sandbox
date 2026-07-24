# Scoring, and the hackathon rubric mapping

Two parts. Part A is how the risk score works and why every point of it is
explainable. Part B maps the hackathon's 100-point criteria and bonuses to the
exact place in this project where each is satisfied.

---

## Part A — How the risk score works

All scoring lives in [`backend/app/engine/scoring.py`](../backend/app/engine/scoring.py).
It reads **signals and nothing else**. Analyzers observe; they never score. That
single rule is what makes the number defensible: no analyzer can quietly inflate
a verdict, and the final score always traces back to a list of sentences a human
can read.

The final score is a blend of two components:

```
final = 0.6 · rule_score + 0.4 · model_score        (weights runtime-tunable)
```

### Component 1 — Rule score (severity-weighted, saturating)

Each signal carries a severity. The **first** signal in a band is worth its full
weight; further signals in the same band add progressively less. Twenty
low-severity observations must not add up to one critical one — a hundred
suspicious strings is a *style*, one process-injection import chain is an
*intent*.

| Severity | First-signal weight |
|---|---|
| critical | 55.0 |
| high | 26.0 |
| medium | 11.0 |
| low | 4.0 |
| info | 0.0 |

Within a band, *n* signals contribute a geometric series with decay `0.45`:

```
contribution(weight, n) = weight · (1 − 0.45ⁿ) / (1 − 0.45)
```

So the second signal in a band is worth 0.45× the first, the third 0.45²×, and so
on. Bands are summed and the total is clamped to 100. The per-band arithmetic
(which signals, what each band contributed) is returned in the breakdown, so the
rule score is auditable by hand.

### Component 2 — Model score (expert-weighted logistic, 8 features)

A logistic regression over eight bounded features. The coefficients are **set
from domain knowledge, not fitted to a labelled corpus** — and labelled as such
everywhere they are displayed. This is a deliberate, honest choice: there is no
labelled malware corpus in this project, and a model presented as *trained* when
it is not is exactly the kind of claim this codebase refuses to make elsewhere.

The exact weights ([`WEIGHTS` in `scoring.py`](../backend/app/engine/scoring.py)):

| Feature | Weight | Meaning |
|---|---|---|
| `capability_signals` | **2.9** | Import chains / API calls that *do* something (inject, download-and-exec, credential access, persistence). |
| `yara_hits` | **2.6** | Number of YARA rule matches (saturating: 5 hits ≠ 5× one). |
| `obfuscation_layers` | **2.4** | Decoded script layers — deliberate hiding. |
| `extension_mismatch` | **2.2** | Content contradicts the claimed extension. |
| `autoexec` | **2.1** | An Office macro that runs on open. |
| `embedded_executable` | **1.8** | A PE/ELF carried inside another file. |
| `max_entropy` | **1.5** | Highest section entropy (packing/encryption — but installers pack too). |
| `ioc_density` | **0.9** | Volume of extracted indicators. |

Bias: **−3.1**, chosen so an all-zero feature vector scores ~5, not 50 — a file
we found nothing in reads as "nothing found", not a coin flip.

The ordering encodes one judgement stated plainly: **intent beats appearance.**
A macro that runs on open, or content that contradicts its own filename, is a
decision someone made; high entropy is a property a legitimate installer also
has. Each feature's contribution to the logit is reported, so "why is this 79 and
not 40" is always answerable.

`scoring.fit()` trains the *same* model on real labels the moment a corpus
exists, replacing `WEIGHTS` with nothing downstream changing — the expert weights
are a starting point, not a ceiling.

### Blending, and runtime tuning

`final = 0.6·rule + 0.4·model` is the default the brief asks for. The split is
**runtime-tunable** via [`PUT /api/admin/weights`](api.md) (the brief asks for
weights exposed for tuning); only the ratio matters, so any two non-negative
numbers are normalised to sum to 1. Overrides are in-memory and a restart returns
to 0.6/0.4 — for a tuning knob, the safe direction to fail.

### Risk bands

Fixed by the sandbox banding specification
([`RISK_BANDS` in `contracts.py`](../backend/app/engine/contracts.py)):

| Score | Band |
|---|---|
| 0–29 | low |
| 30–59 | medium |
| 60–79 | high |
| 80–100 | critical |

### Why every point is explainable

`assess()` returns a `breakdown` containing: the formula with the live weights;
the rule score with its per-band arithmetic and the signal ids in each band; the
model score with every feature value, its weight, and its exact contribution to
the logit; the model's provenance string (expert-weighted, not corpus-trained);
the top three reasons in the analyzers' own words; and the **tier record** —
which tiers actually ran. A score computed without dynamic analysis is a score
with a *stated* blind spot. That breakdown is what the UI headline and the PDF
executive summary both read from, so there is exactly one answer to "why".

---

## Part B — Rubric mapping (100 points + bonuses)

Where each scored criterion is satisfied in **this** repository. Items that need
an operator's Linux box to fully demonstrate (the dynamic tier) are marked
honestly — the code is real and the seam is live; only the isolated hardware is
the operator's to provide.

| Criterion | Pts | Where it lives | Notes |
|---|---:|---|---|
| **Prototype** (working end-to-end) | 13 | [`backend/app/api/sandbox.py`](../backend/app/api/sandbox.py), [`pipeline.py`](../backend/app/engine/pipeline.py), [`frontend/`](../frontend/) | Submit → quarantine → identify → analyse → score → report → export, end to end. Runnable with one command in demo mode. |
| **Native engine** | 13 | [`backend/app/engine/native.py`](../backend/app/engine/native.py), [`worker/engines/base.py`](../worker/engines/base.py) | The team's own behaviour engine. Interface + seam are in-repo; **detonation runs on the operator's isolated worker** (never on the web service, by design). |
| **Open-source sandbox integration** | 13 | [`backend/app/engine/integrations/`](../backend/app/engine/integrations/), [`docs/sandbox-matrix.md`](sandbox-matrix.md) | Descriptor catalog of 8 engines (native, qiling, firejail, cuckoo, capev2, strelka, joesandbox, virustotal); worker client seam under [`worker/`](../worker/). Each row is real and env-gated. |
| **Security** | 13 | [`SECURITY.md`](../SECURITY.md), [`storage.py`](../backend/app/engine/storage.py), [`fetcher.py`](../backend/app/engine/fetcher.py), [`archives.py`](../backend/app/engine/archives.py), [`auth.py`](../backend/app/auth.py) | No-exec content-addressed quarantine, SSRF guard, zip-bomb bounds, no archive brute-force, auth on every mutating route, production-config refusal. |
| **UI** | 12 | [`frontend/`](../frontend/) | Same-origin SPA (submit, live job polling, verdict + explainable breakdown, exports). |
| **Export** | 12 | [`backend/app/engine/report.py`](../backend/app/engine/report.py) | JSON, STIX 2.1, and PDF exports of any completed job. |
| **Code structure & docs** | 14 | [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`SECURITY.md`](../SECURITY.md), [`docs/`](.), module docstrings throughout | Registry-based module split, one analysis contract, thorough docstrings, this docs set. |
| **Extra features** | 10 | feedback loop ([`sandbox.py`](../backend/app/api/sandbox.py) `feedback`), reanalyze, archive child-job recursion, capabilities endpoint, admin weight tuning | See per-endpoint list in [`docs/api.md`](api.md). |

### Bonuses

| Bonus | Pts | Where it lives | Status |
|---|---:|---|---|
| **Behaviour graph** | +3 | `timeline` in [`DynamicReportIn`](../backend/app/schemas.py) + `job.dynamic.timeline`; worker emits ordered `{t_ms, kind, detail}` events via [`Report.add_event`](../worker/engines/base.py) | Wire format live; populated when a worker detonates. |
| **REST `/analyze` + `/result`** | +2 | [`POST /api/analyze`](api.md), [`GET /api/result/{id}`](api.md) | Live, API-key authenticated. |
| **6+ sandboxes** | +5 | [`integrations/__init__.py`](../backend/app/engine/integrations/__init__.py) — 8 engines cataloged | 8 ≥ 6; each env-gated, honestly reported by `/api/capabilities`. |
| **Minimal-AI authorship** | +10 | Scoring is an **own** rule + expert-weighted model; the optional LLM only writes prose narrative and **never** touches the numeric verdict ([`config.py`](../backend/app/config.py) `ai_provider`) | The score comes from the engine's own model whether or not an API key is set. |

### Honest caveats

- The **dynamic tier** (native engine, firejail, Cuckoo, CAPEv2, Qiling, Joe)
  requires an operator's network-isolated Linux worker to *demonstrate* live
  detonation. In this repository the contract, the HTTP seam, the worker
  interface, and the re-scoring path are all real and exercisable; what is not
  provided — and deliberately cannot be on a managed host — is the isolated
  hardware. `/api/capabilities` reports exactly which engines are live on any
  given deployment, so the claim is never overstated.
- The model is **expert-weighted, not corpus-trained**, and says so everywhere.
  `fit()` is present to train it the moment real labels exist.
