# Remediation plan — the 2026-08-03 seven-lens sweep

64 findings, produced by seven independent audit passes over the backend, the
engine, the worker, the API, the frontend, the test suite and the documentation.
Each was written by one agent and checked by two more whose instructions were to
refute it.

**18 are closed** (commits `cdc1998` and `239b4b8`). **46 remain**, laid out
below as three days of work.

---

## How to use this file

Every open item has the same shape:

```
### A3 · medium · <one line>
**Where** file:line
**What is wrong** the fact, measured
**Fix** what to change
**Cost** rough size
**Your call?** yes/no — whether this needs a decision from you rather than from me
```

Tick the box when it lands. If you disagree with a fix, write your view under
the item — several of these are judgement calls where your opinion decides, not
mine, and they are marked **Your call? yes**.

Three rules carried over from the sweep, because they are why the list is this
long and this specific:

1. **Nothing ships unmeasured.** Every change that can move a score is measured
   against the corpora before and after, and the numbers go in the commit.
2. **A fix that costs detections is not a fix.** Two proposals in this sweep
   were rejected for exactly that; both are recorded below with their numbers.
3. **When the truth cannot be recovered, say so.** Labelling a weak claim beats
   deleting it and beats leaving it unmarked.

---

## Already closed

Kept here so the list reads as a whole and nothing is done twice.

- [x] `GET /api/audit/export` truncated the chain of custody to 1000 of 14,044
      events with no total — added `total` / `offset` / `has_more` and headers.
- [x] `verdict._worst` dropped the attributability axis — 90 signed reports
      published `high` where the score banded every signal `low`. Now 0.
- [x] `export.pdf` was the only export not scrubbing the detonation host's name —
      397 jobs, 12/12 rendered PDFs.
- [x] Audit `tenant_id` could be rewritten with one `UPDATE` and `verify_chain`
      still said ok.
- [x] `DYNAMIC_WORKER_TOKEN` was never validated at boot.
- [x] The API was on the public internet in plaintext — TLS on 8443, API bound
      to loopback.
- [x] Timeline `t_ms` was a list index labelled milliseconds.
- [x] Guest processes shipped as the sample's behaviour — now attributed by
      parentage.
- [x] CAPE severity 4 (its highest) bucketed with severity 1.
- [x] ATT&CK techniques now declare `basis`; 1,634 are marked as inferred from
      prose.
- [x] Four tests that could not fail (rate-limit headers, nested archive,
      deep DER nesting, signed-malicious category).
- [x] `test_docs_match_code` matched only a route's stem, so `export.signed` and
      `export.incident` were undocumented and unguarded.
- [x] `docs/api.md` admin examples used cookie auth the API does not have.
- [x] `SECURITY.md` declared rate limiting and multi-tenancy out of scope; both
      ship.

---

# Day 1 — things that state something untrue

The highest-value group. None of these crash; all of them make the product say
something it cannot back, which is the one defect class this product cannot
afford.

### D1.1 · critical · The detonation corpus cannot detect a scoring change
**Where** `backend/tests/test_detonation_corpus.py:115`
**What is wrong** The 93-sample corpus is asserted against `MIN_MALWARE_DETECTED
= 69`, a floor so far below the actual result that no plausible regression
trips it. Eight scoring comments cite "84 of 88" — a figure this harness does
not produce. So every "measured against the corpus" claim in this repo rests on
a test that would stay green through a large regression.
**Fix** Pin the actual current number with a tolerance band (e.g. `assert 82 <=
detected <= 88`) so both a regression AND an unexplained improvement fail. Then
re-derive the "84 of 88" figure and correct the eight comments, or delete the
figure from them.
**Cost** half a day — the re-derivation is the work
**Your call?** no
- [ ] done

### D1.2 · critical · "Why this score" prints a formula that cannot produce the score
**Where** `frontend/src/pages/JobDetail.tsx:519`, `frontend/src/lib/types.ts:213`
**What is wrong** 18 of the 400 most recent jobs carry `contents_floor` — a
container raised to the score of the worst file inside it — and the UI renders
`rule × 0.6 + ai × 0.4` beside a gauge that does not equal it. The field that
reconciles them is in the payload and has no name in the TypeScript type, so it
was never rendered.
**Fix** Add `contents_floor` to `ScoreBreakdown`, and render one line under the
formula: the computed score, the descendant that raised it, and why.
**Cost** 1-2 hours
**Your call?** no
- [ ] done

### D1.3 · high · The trust-anchor tool tells the operator to delete a valid anchor
**Where** `tools/verify_anchor_provenance.py:36`
**What is wrong** Run exactly as documented, it exits 1 and instructs removal of
an anchor the product records as vendor-confirmed. Either the tool or the
record is wrong, and an operator following the instruction weakens the trust
store.
**Fix** Reproduce, decide which side is wrong, fix that side. Do not "make the
tool pass".
**Cost** 2-3 hours
**Your call?** no
- [ ] done

### D1.4 · high · The native Linux strace parser matches nothing it asks for
**Where** `worker/engines/native_linux.py:305`
**What is wrong** The parser cannot match a single line of the trace format it
requests, then reports "No malicious behaviour observed" — a clean bill of
health from a parse that produced nothing.
**Fix** Two honest options, and this is the decision: (a) fix the parser against
a real captured trace, or (b) make the engine report `ran=False` with the reason
until it is fixed, so it stops issuing verdicts. **My recommendation is (b)
first, (a) later** — ELF detonation goes through CAPE now, so this path is not
load-bearing, and a wrong "clean" is worse than an absent answer.
**Cost** (b) 1 hour · (a) 1 day
**Your call?** **yes** — (a) or (b)
- [ ] done

### D1.5 · medium · The Engines page contradicts the deployment
**Where** `frontend/src/pages/Integrations.tsx:62`
**What is wrong** It tells the operator CAPEv2 is unconfigured, blocked, and
needs sovereign mode relaxed — on a deployment where CAPEv2 has detonated 844
samples.
**Fix** Read the same capability descriptor the backend serves rather than
inferring state in the component.
**Cost** 2 hours
**Your call?** no
- [ ] done

### D1.6 · medium · `docs/sandbox-matrix.md` claims Strelka scanning that no code performs
**Where** `docs/sandbox-matrix.md:41` and the `/api/capabilities` descriptor
**Fix** Remove the claim from both, or implement it. Removing is correct unless
you want the feature.
**Cost** 30 minutes
**Your call?** **yes** — remove, or build it?
- [ ] done

### D1.7 · medium · The model's per-feature bars encode the wrong quantity
**Where** `frontend/src/pages/JobDetail.tsx:646`
**What is wrong** Bar length is the feature VALUE, not its contribution, so the
longest bar sits under the smallest number.
**Fix** Length from `contribution`, sign-aware.
**Cost** 1 hour
**Your call?** no
- [ ] done

### D1.8 · low · 38 of 1,633 jobs' model score cannot be reproduced by hand
**Where** `backend/app/engine/scoring.py:757`
**What is wrong** `MODEL_PROVENANCE` promises the published feature values
reproduce the model half. For 38 jobs they do not.
**Fix** Find the divergence (rounding, a feature dropped from the published
list, or a clamp applied after publication) and either publish what is missing
or correct the promise.
**Cost** half a day
**Your call?** no
- [ ] done

**Day 1 gate:** full suite green, corpus numbers recorded in the commit, and the
three UI items verified on the live deployment.

---

# Day 2 — the API contract, the chain of custody, and the quarantine

### D2.1 · medium · The quarantine is not mounted the way three files say it is
**Where** `docker-compose.yml:37`
**What is wrong** 1,362 live samples sit on a volume mounted `rw,relatime` —
not `noexec,nosuid,nodev` — while three files in the repo state that it is. The
kernel is not refusing execution, and the documents say it would.
**Fix** Mount with the flags, verify with `findmnt`, and re-run the suite. If
the flags break the container's writes, change the documents instead — but one
of the two must move.
**Cost** 1-2 hours (plus a container restart on the live host)
**Your call?** no
- [ ] done

### D2.2 · medium · The dynamic ingest writes no source address to the chain
**Where** `backend/app/api/dynamic.py:683`
**What is wrong** The largest mutation the product makes to a verdict — a worker
posting behaviour — records no source address. 5,483 live audit rows have none.
**Fix** Pass `client_ip(request)` into the audit call, as every other mutating
endpoint does.
**Cost** 1 hour
**Your call?** no
- [ ] done

### D2.3 · medium · 61% of chain-of-custody addresses are the Docker bridge
**Where** `DEPLOY.md:64`
**What is wrong** Requests arrive through the docker0 gateway, so the audit
trail records `172.17.0.1` instead of the caller. Now that TLS terminates in
front, this is fixable properly.
**Fix** Trust `X-Forwarded-For` from the proxy only (a configured trusted-proxy
list, never a blanket trust), and record the real client. Add a test that an
untrusted source cannot spoof it.
**Cost** half a day
**Your call?** no
- [ ] done

### D2.4 · medium · `POST /api/dynamic/report/{id}` accepts a report for a job in any status
**Where** `backend/app/api/dynamic.py:585`
**What is wrong** It also clears `job.error` unconditionally, on an invariant
nothing enforces.
**Fix** Accept only for jobs the queue actually offered; clear `error` only when
the report succeeded.
**Cost** 2 hours
**Your call?** no
- [ ] done

### D2.5 · medium · `GET /api/jobs` echoes an offset it ignored
**Where** `backend/app/api/sandbox.py:407`
**What is wrong** With a cursor present, `offset` is ignored — and then returned
as the page's position, so a client that reads it pages wrongly.
**Fix** Reject the combination with a 400, or return the true position. Rejecting
is clearer.
**Cost** 1 hour
**Your call?** no
- [ ] done

### D2.6 · medium · `docs/api.md` misdescribes the sovereignty endpoint's auth
**Where** `docs/api.md:256`
**Fix** Correct to the auth the endpoint actually requires.
**Cost** 15 minutes
**Your call?** no
- [ ] done

### D2.7 · low · A NUL byte from a sample makes the whole table un-castable to jsonb
**Where** `backend/app/engine/pipeline.py:77`
**What is wrong** A NUL reaching a JSON column breaks every `::jsonb` query
across `sandbox_jobs` — including the ones this audit runs.
**Fix** Strip NULs in `_sanitise` on the way in. Backfill the affected rows.
**Cost** 2 hours
**Your call?** no
- [ ] done

### D2.8 · low · The infrastructure scrub is a blind substring replacement
**Where** `backend/app/engine/report.py:148`
**What is wrong** A worker name that occurs inside ordinary report text is
replaced there too, corrupting the signed evidence.
**Fix** Replace whole tokens, not substrings; never inside a hash or a path.
**Cost** 2 hours
**Your call?** no
- [ ] done

### D2.9 · low · `types.ts` requires a field `/api/capabilities` never sends
**Where** `frontend/src/lib/types.ts:323`
**Fix** Make `recent` optional, or send it.
**Cost** 15 minutes
**Your call?** no
- [ ] done

**Day 2 gate:** suite green, and the audit chain verified end to end on the live
host (`entries_checked`, `ok`, `anchored`).

---

# Day 3 — the test suite, accessibility, and the documents

### D3.1 · high · Seven of eight ISO regression tests never run in the shipped image
**Where** `backend/tests/test_an_iso_is_media_not_a_dropper.py:44`
**What is wrong** They skip on a missing dependency the product image does not
carry, so the ISO regression is unguarded in the only environment that matters.
**Fix** Either add the dependency to the image or rewrite the fixtures to build
the ISO in-process. **Rewriting is better** — a test that needs a tool the
product does not ship is testing a different machine.
**Cost** half a day
**Your call?** no
- [ ] done

### D3.2 · medium · The new contrast test can go green while measuring the wrong theme
**Where** `backend/tests/test_the_palette_is_legible.py:53`
**What is wrong** Mine. Renaming the light-theme selector leaves it 44/44 green
while measuring the dark palette twice.
**Fix** Assert the light block was found and differs from the dark one before
using it.
**Cost** 30 minutes
**Your call?** no
- [ ] done

### D3.3 · medium · The invisible-character sweep sees 7 of the 13 file types it declares
**Where** `backend/tests/test_a_library_is_not_a_dropper.py:209`
**Fix** Widen the root to the repo, not `backend/`.
**Cost** 30 minutes
**Your call?** no
- [ ] done

### D3.4 · low · Three more tests that cannot fail
**Where** `test_worker_loop.py:161`, `test_the_queue_is_not_a_page.py:349`,
`test_the_chain_is_anchored_to_a_key.py:331`, plus a dead `_classify` helper in
`test_a_library_is_not_a_dropper.py:137`
**Fix** Same treatment as the four already done: assert the premise, then the
behaviour.
**Cost** 2 hours
**Your call?** no
- [ ] done

### D3.5 · medium · Accessibility: focus, and a skip link
**Where** `frontend/src/components/Layout.tsx:131`
**What is wrong** SPA navigation drops focus to `document.body`, and there is no
way past the eight rail controls for a keyboard user.
**Fix** Move focus to the page heading on route change; add a skip link.
**Cost** 2 hours
**Your call?** no
- [ ] done

### D3.6 · low · Errors are silent to assistive technology
**Where** `frontend/src/components/ui.tsx:575` (six call sites)
**Fix** `role="alert"` on `Callout` when it carries a failure.
**Cost** 1 hour
**Your call?** no
- [ ] done

### D3.7 · low · The behaviour graph hides every event from assistive technology
**Where** `frontend/src/components/BehaviorGraph.tsx:44`
**Fix** Keep `role="img"` but supply a real description, or expose the events as
a visually-hidden list.
**Cost** 1 hour
**Your call?** no
- [ ] done

### D3.8 · low · `Tabs` claims a radiogroup it does not implement
**Where** `frontend/src/components/ui.tsx:691`
**Fix** Add arrow-key navigation and a roving tabindex, or drop the roles.
**Cost** 1 hour
**Your call?** no
- [ ] done

### D3.9 · medium · A failed job has no re-analyse control
**Where** `frontend/src/pages/JobDetail.tsx:173`
**What is wrong** The failure callout tells the analyst to use a control that is
not rendered for a failed job.
**Fix** Render it, or change the sentence.
**Cost** 1 hour
**Your call?** no
- [ ] done

### D3.10 · low · Two dashboard numbers count different populations
**Where** `frontend/src/pages/Dashboard.tsx:141`, `:188`
**What is wrong** "By file type" counts a different set than the donut beside
it, and its "N more not shown" implies the wrong total. The "Needs attention"
definition lives only in a `title` tooltip on a non-interactive div.
**Fix** One population for both charts; move the definition into visible text.
**Cost** 2 hours
**Your call?** no
- [ ] done

### D3.11 · medium · Documentation that describes a different product
**Where** `worker/README.md:81`, `DEPLOY.md:57`, `infra/detonation-host/README.md:52`,
`backend/app/engine/trust_anchors.py:206`, `render.yaml:23`, `README.md:69,80,202`
**What is wrong** Stale detonatable-family tables; a script that no longer keeps
`max_sample_size` in step with `MAX_SAMPLE_MB`; a runbook that stops at step 07
while four scripts exist; `CYCLO_TRUST_ANCHORS` documented nowhere;
`ANTHROPIC_API_KEY` presented as enabling a feature `config.py` says is
impossible; a test command that suppresses its own summary; a manual-development
block that is not runnable on a POSIX shell; `/api/docs` described as reachable
from a browser when no browser path can authenticate to it.
**Fix** One pass, one commit, each corrected against the code.
**Cost** half a day
**Your call?** no
- [ ] done

### D3.12 · low · Two comments that misstate their own arithmetic
**Where** `backend/app/engine/scoring.py:71`, `backend/app/api/sandbox.py:60`
**What is wrong** A comment attributes 43 of a band's 46.9 points to a group
whose collapse actually moves it 1.6; a staleness constant is justified by a
"two minute" detonation ceiling that is really 600 seconds.
**Fix** Re-derive both, correct the comments.
**Cost** 1 hour
**Your call?** no
- [ ] done

**Day 3 gate:** suite green with no new skips, frontend builds, and a keyboard
pass over the four main screens.

---

## Deliberately not on the list

Recorded so nobody re-opens them without the numbers.

**Re-mapping ATT&CK off prose.** The rule table matches signal ids AND prose
titles, and 1,634 assertions rest on prose alone. Two repairs were measured:

| candidate | techniques lost on MALICIOUS samples |
|---|---|
| match signal ids only | 897–1,105 |
| ignore hedged titles | 603 |
| the bar this codebase set | 28 |

The coverage genuinely rests on prose — `office.vba_present` maps to T1204.002
through the word "macro" in its sentence, and that mapping is right. So the
claim stays and its footing is published instead. **Doing this properly means
building a curated id→technique table**, which is a project, not a fix. Worth
scheduling separately if ATT&CK fidelity becomes a selling point.

**Calibrating the ELF dynamic tier.** It is deliberately uncalibrated: every
`capev2.*` signal on an ELF sample is excluded from the score, the capabilities,
the threat name and the ATT&CK map, and the report says so. Removing the guard
needs a benign Linux corpus first, and there is a test that fails if anyone
tries without one.

---

## Your notes

Anything you want changed, reprioritised, or dropped — write it here.

<!--
  e.g. "D1.4: take option (a), the Linux engine matters for the demo"
       "D2.1: skip, the volume flags break our backup script"
-->
