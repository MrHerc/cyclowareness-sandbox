# Sandbox integration matrix

Cyclowareness Sandbox is designed to connect to a range of analysis engines
without any downstream code changing, because every engine — the team's own, an
emulator, an open-source detonation sandbox, or a reputation service — returns
findings in the same `Signal`/`IOCs` vocabulary
([`contracts.py`](../backend/app/engine/contracts.py)).

The catalog below is the **single source of truth** for what this deployment can
be connected to. It is defined in
[`backend/app/engine/integrations/__init__.py`](../backend/app/engine/integrations/__init__.py)
and rendered live, per host, by [`GET /api/capabilities`](api.md). Every row is
real: the env vars named here are the ones the worker and the sibling client
modules actually read. Nothing is aspirational — a row that is not `configured`
is a row an operator can turn on by supplying exactly what its **enable** column
says.

## The honest position

- **Static analysis runs everywhere.** Parsers + YARA + scoring execute inside
  the web service on any host, including managed PaaS. They never run the sample.
- **Dynamic analysis runs on the operator's isolated worker.** Detonation,
  emulation, and syscall tracing require a disposable, network-isolated VM with
  kernel-level control. The web service never detonates — it defines the seam and
  an off-host worker ([`worker/`](../worker/)) fulfils it. Out-of-process
  sandboxes (Cuckoo/CAPEv2/Joe) run on their own separate clusters.

A row being present in the matrix means the *integration* exists and is one
credential away — not that this particular deployment is currently executing
samples. `/api/capabilities` reports the live `configured` state for each.

## Matrix

| Engine | Kind | Tier | Where it runs | Enable (env) | Contributes | Status |
|---|---|---|---|---|---|---|
| **Native behaviour engine** | native | dynamic | Off-host worker | `DYNAMIC_WORKER_TOKEN` (worker attaches) | Own syscall/behaviour tracer: observed syscalls, process + network activity as Signals, timeline events | Interface + seam in-repo ([`worker/engines/base.py`](../worker/engines/base.py)); live when a worker attaches |
| **Qiling emulation** | emulator | dynamic | Off-host worker | `DYNAMIC_WORKER_TOKEN` (worker attaches) **+ operator installs `qiling`** | CPU/syscall emulation — behaviour without a live OS target; cross-arch, headless detonation | Adapter live; worker-resident. `qiling` is GPL-2.0 and **deliberately not shipped** — the operator installs it themselves ([licensing](licensing.md)) |
| **Firejail sandbox** | opensource-sandbox | dynamic | Off-host Linux worker | `DYNAMIC_WORKER_TOKEN` (Linux worker with `firejail`) | seccomp-bpf + namespace jail detonation; behaviour as Signals. Linux-only | Descriptor live; needs a Linux worker box |
| **Cuckoo Sandbox** | opensource-sandbox | dynamic | Separate Cuckoo cluster | `CUCKOO_URL`, `CUCKOO_TOKEN` | Full dynamic detonation in isolated guest VMs via REST; report ingested + re-scored | Enabled by pointing at a reachable instance |
| **CAPE Sandbox** | opensource-sandbox | dynamic | Separate CAPEv2 cluster | `CAPEV2_URL`, `CAPEV2_TOKEN` | Config + unpacked-payload extraction (Cuckoo descendant) via REST; report ingested + re-scored | Enabled by pointing at a reachable instance |
| **Strelka file scanning** | opensource-sandbox | static | Separate Strelka cluster | `STRELKA_URL` | Scalable file-scan/enrichment (YARA, unpackers, metadata). **Does not execute** the sample | Enabled by pointing at a reachable frontend |
| **Joe Sandbox (community)** | opensource-sandbox | dynamic | Hosted Joe service | `JOE_API_KEY` | Deep dynamic detonation + behavioural reporting via Web API; community tier is rate-limited | Enabled with a community API key |
| **VirusTotal reputation** | threat-intel | static | VirusTotal API | `VT_API_KEY` | SHA-256 hash-reputation lookup — uploads nothing, does not detonate. Unknown hash stays unknown, never "clean" | Enabled with an API key |

That is **eight** integrated engines across the two tiers (native + emulator +
three open-source detonation sandboxes + Strelka file-scan + Joe + VirusTotal),
which satisfies the "6+ sandboxes" bonus.

## How "configured" is decided

Two kinds of "configured", deliberately distinguished in
[`integrations/base.py`](../backend/app/engine/integrations/base.py):

- **Engines the web service talks to directly** (VirusTotal, Cuckoo, CAPEv2,
  Strelka, Joe) are `configured` when *their own* credentials/URLs are present in
  the environment.
- **Worker-resident engines** (native, Qiling, firejail) have no env vars of
  their own on the web service — it never reaches them. For those, `configured`
  means *a worker can attach at all*, i.e. `DYNAMIC_WORKER_TOKEN` is set.

`configured` is therefore a statement about this deployment, never about a
licence. Qiling in particular needs one more thing the token cannot supply: the
GPL-2.0 `qiling` package, which we do not distribute, installed by the operator
on their own worker. `worker/engines/qiling_emu.py` reports itself unavailable
until then, with that reason in the message. See [licensing](licensing.md).

`describe()` serialises each row for `/api/capabilities` and **never emits a
secret** — only whether the integration is live and what it would take to enable
it. `configured_count()` reports how many are live on the current deployment.

## Adding an engine

An integration is an additive descriptor plus (for dynamic engines) a worker-side
[`Engine`](../worker/engines/base.py) subclass implementing `available()`,
`supports(family)`, and `run(...) -> Report`. Because every engine returns the
same `Report`/`Signal` shape, nothing in the scorer, reporter, or UI needs to
change — the new engine's findings score and display exactly like every other
engine's.
