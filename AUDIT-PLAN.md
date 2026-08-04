# Remediation plan — two days to a sandbox that survives a pentest

64 findings from the 2026-08-03 seven-lens sweep. **18 closed** (`cdc1998`,
`239b4b8`). **46 open**, laid out below as two days.

The split is not arbitrary and it is not by severity. It is by **what a
penetration tester reaches first**:

* **Day 1 — the attack surface.** Anything an attacker touches: what the
  service accepts, what it executes, what it trusts, what it records about who
  did it. If a pentest finds a hole, it is in here.
* **Day 2 — the claims and the guard.** Everything the product asserts about a
  sample, and the test suite that is supposed to stop those assertions drifting.
  A pentester does not exploit these; an auditor and a customer do.

A separate authorised pentest is running against the live deployment in
parallel — six offensive lenses (authz, file handling, injection and SSRF,
secrets and signatures, resource limits, the browser surface), each finding
re-run by a second agent whose job is to kill it. Anything it confirms is
inserted into Day 1 ahead of what is already there.

---

## Decisions taken

| Item | Decision | Why |
|---|---|---|
| **D1.4** Linux strace engine | **(b)** — report `ran=False` with the reason until the parser is fixed | A wrong "clean" is worse than an absent answer. ELF detonation goes through CAPE, so nothing depends on this path today. |
| **D1.6** Strelka claim | **Remove the claim** | Strelka is a cluster (backend, coordinator, Redis, frontend). It does not fit two days, and a half-integration would not make the sentence true — it would make it complicated AND untrue. |
| **D2.1** quarantine mount | **Fix the mount, not the documents** | `noexec,nosuid,nodev` over 1,362 live malware samples is a real control. Changing the documents would delete it from the design instead of adding it to the machine. |

---

## Not attempted in two days, and said so

These are real and they are cut, deliberately, because two days is two days:

* **Accessibility** (D3.5–D3.8, D3.10): focus lost on route change, no skip
  link, `Callout` without `role="alert"`, `Tabs` claiming a radiogroup it does
  not implement, the behaviour graph opaque to a screen reader. None is a
  security or truthfulness defect. They should be a third day.
* **Re-mapping ATT&CK off prose.** Measured twice: matching ids only costs
  897–1,105 techniques on malicious samples, ignoring hedged titles costs 603,
  against a bar of 28. The coverage genuinely rests on prose, so the claim now
  publishes its footing instead. Doing it properly means a curated
  id→technique table — a project, not a task.
* **Calibrating the ELF dynamic tier.** Needs a benign Linux corpus that does
  not exist. A test fails if anyone removes the guard without one.

---

# DAY 1 — the attack surface

Ordered by what an attacker reaches first.

## 1A · What the service executes

### 1A.1 · The quarantine is not mounted the way the design says
**Where** `docker-compose.yml:37`, and the live volume
**Measured** 1,362 live samples on a volume mounted `rw,relatime`. Three files
in the repo state `noexec,nosuid,nodev`. The kernel is not refusing execution,
and the documents say it is.
**Fix** Mount with the flags. Verify with `findmnt` on the live host. If the
flags break the container's writes, that is a finding of its own — report it,
do not quietly revert to the documents.
**Cost** 1–2 hours including a container restart
- [ ] done

### 1A.2 · The Linux strace engine issues a clean bill of health from a parse that produced nothing
**Where** `worker/engines/native_linux.py:305`
**Measured** The parser matches no line of the trace format it asks strace to
produce, then reports "No malicious behaviour observed".
**Fix (decided: option b)** Return `ran=False` with a reason naming the parser
gap, so the tier reports "did not run" instead of "found nothing". Add a test
that fails if it ever returns `ran=True` without having matched a line.
**Cost** 1 hour
- [ ] done

### 1A.3 · A NUL byte from a sample makes the whole table un-castable
**Where** `backend/app/engine/pipeline.py:77`
**Measured** A NUL reaching a JSON column breaks every `::jsonb` query across
`sandbox_jobs` — including the ones this audit runs. Sample-controlled.
**Fix** Strip NULs in `_sanitise` on the way in; backfill affected rows.
**Cost** 2 hours
- [ ] done

## 1B · What the service trusts

### 1B.1 · The dynamic ingest accepts a report for a job in any status
**Where** `backend/app/api/dynamic.py:585`
**Measured** It also clears `job.error` unconditionally, on an invariant nothing
enforces. This is the endpoint that writes behaviour into a signed verdict.
**Fix** Accept only for a job the queue actually offered; clear `error` only on
a report that succeeded.
**Cost** 2 hours
- [ ] done

### 1B.2 · The infrastructure scrub is a blind substring replacement
**Where** `backend/app/engine/report.py:148`
**Measured** A worker name occurring inside ordinary report text is replaced
there too, corrupting the signed evidence.
**Fix** Whole-token replacement; never inside a hash or a path.
**Cost** 2 hours
- [ ] done

### 1B.3 · The trust-anchor tool tells the operator to weaken the trust store
**Where** `tools/verify_anchor_provenance.py:36`
**Measured** Run exactly as documented it exits 1 and instructs removal of an
anchor the product records as vendor-confirmed.
**Fix** Reproduce, decide which side is wrong, fix that side. Do not make the
tool pass.
**Cost** 2–3 hours
- [ ] done

## 1C · What the service records about who did it

### 1C.1 · The largest mutation to a verdict records no source address
**Where** `backend/app/api/dynamic.py:683`
**Measured** 5,483 audit rows from dynamic ingest have no source IP.
**Fix** Pass `client_ip(request)`, as every other mutating endpoint does.
**Cost** 1 hour
- [ ] done

### 1C.2 · 61% of chain-of-custody addresses are the Docker bridge
**Where** `DEPLOY.md:64`, and the request path
**Measured** Requests arrive via docker0, so the audit trail records
`172.17.0.1` instead of the caller. Now that TLS terminates in front, this is
fixable — and doing it wrong opens a spoofing hole, so it is a Day 1 item.
**Fix** Trust `X-Forwarded-For` **only** from a configured trusted-proxy list,
never blanket. Add a test that an untrusted source cannot spoof it.
**Cost** half a day
- [ ] done

### 1C.3 · `GET /api/jobs` echoes an offset it ignored
**Where** `backend/app/api/sandbox.py:407`
**Fix** Reject cursor+offset with a 400. Clearer than silently picking one.
**Cost** 1 hour
- [ ] done

## 1D · Whatever the live pentest confirms

Inserted here as it lands, ahead of everything above it if it is worse.

- [ ] triaged

**Day 1 gate**
* full suite green, no new skips
* `findmnt` shows the quarantine flags on the live host
* the audit chain verifies end to end (`entries_checked`, `ok`, `anchored`)
* a spoofed `X-Forwarded-For` from an untrusted source does not reach the audit
  trail — tested, not assumed

---

# DAY 2 — the claims, and the guard that is supposed to hold them

## 2A · The guard is broken, so fix it first

Everything in 2B is "the product says something it cannot back". There is no
point fixing those while the tests that are supposed to catch them cannot fail.

### 2A.1 · The detonation corpus cannot detect a scoring change
**Where** `backend/tests/test_detonation_corpus.py:115`
**Measured** 93 samples asserted against `MIN_MALWARE_DETECTED = 69`, a floor
far below the actual result — no plausible regression trips it. Eight scoring
comments cite "84 of 88", a figure this harness does not produce. Every
"measured against the corpus" claim in the repo rests on this.
**Fix** Pin the real number with a tolerance band so a regression AND an
unexplained improvement both fail. Re-derive "84 of 88" or delete it from the
eight comments.
**Cost** half a day — the re-derivation is the work
- [ ] done

### 2A.2 · Seven of eight ISO regression tests never run in the shipped image
**Where** `backend/tests/test_an_iso_is_media_not_a_dropper.py:44`
**Fix** Build the ISO in-process rather than adding a tool the product does not
ship. A test that needs a binary the image lacks is testing a different machine.
**Cost** half a day
- [ ] done

### 2A.3 · Four more tests that cannot fail
**Where** `test_the_palette_is_legible.py:53` (mine — renaming the light-theme
selector leaves it green while measuring the dark palette twice),
`test_a_library_is_not_a_dropper.py:209` (sees 7 of the 13 file types it
declares) and `:137` (a dead helper), `test_worker_loop.py:161`,
`test_the_queue_is_not_a_page.py:349`, `test_the_chain_is_anchored_to_a_key.py:331`
**Fix** Assert the premise, then the behaviour. Same treatment as the four
already done.
**Cost** 3 hours
- [ ] done

## 2B · Things the product states that it cannot back

### 2B.1 · "Why this score" prints a formula that cannot produce the score
**Where** `frontend/src/pages/JobDetail.tsx:519`, `frontend/src/lib/types.ts:213`
**Measured** 18 of the 400 most recent jobs carry `contents_floor` — a container
raised to its worst member's score — and the UI renders `rule × 0.6 + ai × 0.4`
beside a gauge that does not equal it.
**Fix** Add `contents_floor` to the type; render one line naming the descendant
that raised it.
**Cost** 1–2 hours
- [ ] done

### 2B.2 · 38 of 1,633 jobs' model score cannot be reproduced by hand
**Where** `backend/app/engine/scoring.py:757`
**Fix** Find the divergence and either publish what is missing or correct
`MODEL_PROVENANCE`'s promise.
**Cost** half a day
- [ ] done

### 2B.3 · The Engines page contradicts the deployment
**Where** `frontend/src/pages/Integrations.tsx:62`
**Measured** It says CAPEv2 is unconfigured, blocked and needs sovereign mode
relaxed — on a deployment where CAPEv2 has detonated 844 samples.
**Fix** Read the capability descriptor the backend serves; stop inferring state
in the component.
**Cost** 2 hours
- [ ] done

### 2B.4 · The model's per-feature bars encode the wrong quantity
**Where** `frontend/src/pages/JobDetail.tsx:646`
**Measured** Bar length is the feature value, not the contribution, so the
longest bar sits under the smallest number.
**Fix** Length from `contribution`, sign-aware.
**Cost** 1 hour
- [ ] done

### 2B.5 · A failed job has no re-analyse control
**Where** `frontend/src/pages/JobDetail.tsx:173`
**Fix** Render it, or change the sentence that tells the analyst to use it.
**Cost** 1 hour
- [ ] done

### 2B.6 · `docs/sandbox-matrix.md` claims Strelka scanning no code performs
**Where** `docs/sandbox-matrix.md:41`, the `/api/capabilities` descriptor
**Fix (decided)** Remove the claim from both.
**Cost** 30 minutes
- [ ] done

### 2B.7 · `docs/api.md` misdescribes the sovereignty endpoint's auth
**Where** `docs/api.md:256`
**Cost** 15 minutes
- [ ] done

### 2B.8 · Documentation describing a different product
**Where** `worker/README.md:81`, `DEPLOY.md:57`,
`infra/detonation-host/README.md:52`, `backend/app/engine/trust_anchors.py:206`,
`render.yaml:23`, `README.md:69,80,202`
**What** Stale detonatable-family tables; a script that no longer keeps
`max_sample_size` in step with `MAX_SAMPLE_MB`; a runbook stopping at step 07
while four scripts exist; `CYCLO_TRUST_ANCHORS` documented nowhere;
`ANTHROPIC_API_KEY` presented as enabling a feature `config.py` calls
impossible; a test command that suppresses its own summary; a
manual-development block not runnable on a POSIX shell; `/api/docs` described
as browser-reachable when no browser path can authenticate to it.
**Fix** One pass, one commit, each corrected against the code.
**Cost** half a day
- [ ] done

### 2B.9 · Two comments that misstate their own arithmetic
**Where** `backend/app/engine/scoring.py:71`, `backend/app/api/sandbox.py:60`
**What** 43 of a band's 46.9 points attributed to a group whose collapse moves
it 1.6; a staleness constant justified by a "two minute" detonation ceiling
that is really 600 seconds.
**Cost** 1 hour
- [ ] done

### 2B.10 · `types.ts` requires a field `/api/capabilities` never sends
**Where** `frontend/src/lib/types.ts:323`
**Cost** 15 minutes
- [ ] done

**Day 2 gate**
* full suite green, no new skips, and the corpus test now fails if the score
  moves — proven by deliberately breaking it once and watching it go red
* frontend builds clean
* one job re-analysed end to end and its score reproduced by hand from the
  published breakdown

---

## Your notes

Anything to reprioritise, drop, or do differently — here.

<!--
  e.g. "1C.2: we sit behind Cloudflare too, take that into account"
       "2B.8: skip README, I will rewrite it myself"
-->
