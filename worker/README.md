# Cyclowareness Sandbox — off-host dynamic-analysis worker

This is the program that actually detonates samples. The web service never does
(see the repository README and `backend/app/engine/native.py`). The worker is a
**separate, self-contained** program: it shares no code with the backend app and
talks to it only over the `/api/dynamic/*` HTTP seam, authenticated with a shared
worker token. You run it on hardware you control — a disposable, network-isolated
Linux VM — and it claims jobs, runs them through a detonation engine, and posts
the behaviour back to be merged into the verdict and re-scored.

## The safety model (read this first)

The service's one non-negotiable rule is: **the web service never executes a
sample; only this off-host worker does, and only inside isolation or emulation.**
Three engines fulfil that rule differently:

- **Native (Firejail + seccomp + strace)** — real execution of the sample's own
  code, but *only* inside a Firejail jail with `--net=none` (or a sinkhole),
  `--seccomp`, `--noroot`, a throwaway private root, and CPU/file/proc rlimits.
  The sample is traced with `strace -f` and the syscall sequence becomes the
  evidence. **If `firejail` is not present, this engine refuses to run** — there
  is no unconfined fallback. Running malware outside its jail is worse than not
  running it, so the absence of Firejail disables native detonation entirely.
- **Qiling (emulation, operator-installed)** — the sample's instructions run in
  an *emulated* CPU and OS; syscalls/API calls are hooked, never executed against
  the real kernel. This is safe even on a workstation (nothing is truly
  detonated) and is the demonstrable native-behaviour path when no isolation VM
  is available. **We ship the adapter, not the library:** `qiling` is GPL-2.0 and
  is deliberately absent from `requirements.txt` and this image, because
  importing it in-process in a distributed image would make that image a
  derivative work of a GPL-2.0 library. Install it yourself if you want it — see
  [Enabling Qiling](#enabling-qiling-optional).
- **External sandboxes (Cuckoo / CAPEv2 / Joe)** — the sample is submitted to a
  detonation service the operator already runs/subscribes to; the worker only
  normalises the returned behavioural JSON. No execution happens on the worker.

Regardless of engine, every report states plainly whether the sample was
actually detonated (`ran=true/false`, the engine name, and the confinement used).
"We could not detonate" is reported honestly as `ran=false` with a reason — it is
never dressed up as "clean".

**Operational requirement:** run the worker (or its container) on a dedicated,
disposable VM that is network-isolated and snapshotted between runs. The Docker
container boundary is **not** a malware-containment boundary; Firejail inside plus
the isolated host outside are. Never run the worker on the same host as the web
service.

## How it maps to the brief

The brief scores two dynamic axes, and this worker is where both are earned:

- **Native Engine** — `engines/native_linux.py` is the team's own engine: it
  confines, executes, traces, and derives behaviour Signals (`spawns_shell`,
  `network_connect`, `file_write`, `anti_debug` via ptrace, `persistence` via
  cron/systemd/init, `wx_memory`) plus a timeline and network/file IOCs — with
  the Firejail safety invariant enforced. `engines/qiling_emu.py` is the safe
  emulation counterpart of the same idea.
- **Open-source sandbox integration** — `engines/opensource.py` submits to and
  normalises Cuckoo, CAPEv2, and Joe Sandbox into the identical Signal
  vocabulary, so a behavioural finding scores and displays the same no matter
  which sandbox produced it.

Every engine emits the same `Report` (defined in `engines/base.py`), which maps
one-to-one onto the backend's `DynamicReportIn`. The backend re-scores using
exactly the same Signal → score path as static analysis.

## Engine priority

For each job the agent picks the **first available engine that supports the
sample's family**, in this order:

    native > qiling > cuckoo > capev2 > joe

"Available" is checked at runtime (binary present / package importable / service
URL configured), so the same binary does the right thing on a Firejail lab box, a
Qiling-only laptop, or a host wired to an external Cuckoo — unavailable engines
are silently skipped, never forced.

| Engine | Family support | Available when |
|--------|----------------|----------------|
| native | `elf`, `script` | `firejail` **and** `strace` on PATH |
| qiling | `pe`, `elf` | `qiling` installed **by you** (not shipped) **and** a rootfs present |
| cuckoo | pe/elf/script/office/pdf | `CUCKOO_URL` set **and `SOVEREIGN_MODE=false`** |
| capev2 | pe/elf/script/office/pdf | `CAPEV2_URL` set **and `SOVEREIGN_MODE=false`** |
| joe | pe/elf/script/office/pdf | `JOE_URL` **and** `JOE_API_KEY` set **and `SOVEREIGN_MODE=false`** |

The last three hand the whole sample file to a service on another host, so
sovereign mode — which is **on by default** — makes them unavailable whatever
credentials are set.

A destination **inside this deployment is not egress** and is not blocked: `http://127.0.0.1:8000`, `localhost`, or a private address on this machine's own network. The reference deployment runs CAPE at `127.0.0.1:8000`, and refusing that stopped nothing from leaving while disabling the whole dynamic tier. A HOSTNAME is never resolved — only a literal loopback/private/link-local address counts as internal, because a name that resolves privately today can resolve anywhere tomorrow. The worker prints the reason once at startup, naming the
variable, rather than skipping them silently. `native` and `qiling` detonate on
this host and send nothing anywhere, so they are untouched by it.

## Configuration

All configuration is environment variables (see `config.py`):

| Variable | Required | Default | Meaning |
|----------|----------|---------|---------|
| `DYNAMIC_WORKER_TOKEN` | **yes** | — | Shared secret sent as `X-Worker-Token`; must match the backend. Without it the worker exits. |
| `SANDBOX_API_URL` | no | `http://localhost:8000` | Backend base URL. |
| `WORKER_NAME` | no | `cyclowareness-worker` | Identity stamped on every report. |
| `POLL_INTERVAL_SECONDS` | no | `15` | Queue poll cadence. |
| `ENGINE_TIMEOUT_SECONDS` | no | `120` | Hard wall-clock cap per detonation. |
| `QUEUE_LIMIT` | no | `20` | Jobs claimed per poll. |
| `FIREJAIL_BIN` / `STRACE_BIN` | no | `firejail` / `strace` | Native-engine tool paths. |
| `NATIVE_SINKHOLE` | no | *(none)* | If set, native jails route to this sinkhole instead of `--net=none`. |
| `QILING_ROOTFS` | no | `/opt/qiling/rootfs` | Base dir of emulated-OS filesystems. |
| `CUCKOO_URL` / `CUCKOO_TOKEN` | no | — | Cuckoo REST base + optional bearer token. |
| `CAPEV2_URL` / `CAPEV2_TOKEN` | no | — | CAPEv2 REST base + optional token. |
| `JOE_URL` / `JOE_API_KEY` | no | — | Joe Sandbox API base + key. `JOE_APIKEY` is also accepted, but `JOE_API_KEY` is the documented spelling and the one the backend's matrix checks. |
| `SOVEREIGN_MODE` | no | **`true`** | "Nothing leaves this deployment." Same variable and default as the web service, because it is one promise, not two — and this is a **separate process**, so the backend's choke point cannot speak for it. On, the three upload engines above are unavailable. A value it does not recognise keeps the default: a typo on a switch that governs egress must not read as "off". |
| `MAX_CONCURRENT_JOBS` | no | `1` | Detonations in flight at once. Set it to the number of analysis machines the sandbox has and no higher — the guests are the scarce resource. The default is 1 because that is what a single-guest install can honour. |
| `HTTP_TIMEOUT_SECONDS` | no | `30` | Timeout for talking to the **backend** (not the engine timeout). |
| `CONTAINMENT_CHECK` | no | *(none)* | A command answering "is this host safe to detonate on, right now?" — exit 0 means contained, anything else refuses the batch. `infra/detonation-host/containment-status.sh` is the reference implementation. Empty disables the gate, which is correct for a deployment that does not detonate at all; the worker says so once at startup, because "no gate configured" and "gate passing" must never look the same in a log. |
| `CONTAINMENT_CHECK_TIMEOUT_SECONDS` | no | `15` | Short by design — the check reads a ruleset, it does not talk to a guest. A gate that hangs is a gate that gets removed. |

## Running

### Locally (development, single pass)

```bash
cd worker
pip install -r requirements.txt          # only `requests` is required
export DYNAMIC_WORKER_TOKEN=changeme      # must match the backend
export SANDBOX_API_URL=http://localhost:8000
python agent.py --once                    # one queue pass, then exit
python agent.py                           # continuous poll loop
```

With no optional engines installed and no external sandbox configured, the worker
logs each engine as `unavailable` (with the reason, where it has one) and simply
skips jobs it cannot handle — it does not fail. Provide Firejail on a Linux VM,
set an external sandbox URL, or install Qiling yourself, to light up real
behaviour.

### Enabling Qiling (optional)

Qiling is **not installed by this repository or its image**, and that is a
licence decision, not an oversight: Qiling is GPL-2.0, and a distributed image
that imports it in-process would be a derivative work of a GPL-2.0 library —
irreconcilable with the BUSL-1.1 licence on Cyclowareness Sandbox
([`../docs/licensing.md`](../docs/licensing.md)).

`engines/qiling_emu.py` is our own adapter against Qiling's public API. If you
want emulation on your own worker:

```bash
pip install qiling                     # you are accepting Qiling's GPL-2.0 terms
export QILING_ROOTFS=/opt/qiling/rootfs # emulated-OS filesystems you provide
```

The engine then reports itself available and the agent starts choosing it. That
choice, and its licence consequences for whatever you build around your worker,
are yours — we neither make it for you nor distribute the result.

### Docker (on a disposable, isolated VM)

```bash
docker build -t cyclowareness-worker .
docker run --rm \
  -e SANDBOX_API_URL=http://backend:8000 \
  -e DYNAMIC_WORKER_TOKEN=changeme \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  cyclowareness-worker
```

The image installs `firejail` and `strace`, so the native engine is live inside
it. `--cap-add=SYS_PTRACE` lets `strace` attach; Firejail manages its own seccomp
profile, which is why the container's default seccomp is loosened. On a hardened
Docker host Firejail may additionally need a user namespace or `--privileged` —
that friction is intentional: this image belongs on a dedicated analysis VM, not
a shared cluster.

## Files

- `agent.py` — poll → download → choose engine → run (timeout) → post → cleanup.
  `--once` for a single pass.
- `config.py` — environment configuration, dependency-free.
- `engines/base.py` — the `Engine` interface and the `Report` dataclass /
  `to_payload()` wire format.
- `engines/native_linux.py` — the native Firejail+seccomp+strace engine.
- `engines/qiling_emu.py` — the Qiling emulation adapter (guarded import; the
  GPL-2.0 `qiling` library is operator-installed, never shipped).
- `engines/opensource.py` — Cuckoo / CAPEv2 / Joe Sandbox clients.
- `Dockerfile`, `docker-entrypoint.sh` — the Linux image and its startup checks.

## Licence

> Copyright (c) 2026 Safarali Safarli
>
> Use of this software is governed by the Business Source License 1.1 included in
> the [`LICENSE`](../LICENSE) file at the repository root. As of the Change Date
> specified in that file (2030-07-27), in accordance with the Business Source
> License, use of this software will be governed by the Apache License,
> Version 2.0.

The image's third-party contents are disclosed in
[`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md) and
[`../sbom.json`](../sbom.json). `firejail` (GPL-2.0) and `strace`
(LGPL-2.1-or-later) are installed by apt and invoked as **separate processes** —
never linked or imported — which is why they carry no obligation onto this code.
