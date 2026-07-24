# Detonation host — setup runbook

This is the machine that **actually runs the malware**. It sits apart from the
web/API tier and hosts the dynamic-analysis backend (CAPEv2) with real
Windows/Linux analysis VMs. Behaviour data only ever comes from here — the web
tier never executes a sample.

> **Safety, non-negotiable.** This host runs live malware. It must be a
> disposable, **network-isolated** machine you fully control: not your daily
> computer, not on a LAN with production systems, ideally with a dedicated
> internet line or a controlled sinkhole. Treat it as compromised by design.

## What to get (procurement)

| Path | What | When to pick it |
|------|------|-----------------|
| **Bare-metal (recommended)** | Hetzner AX52 / AX102 or similar — Ryzen, 32–64 GB RAM, NVMe. ~€60–90/mo. | Best: real nested virt, full control, cheapest for the power. Ordering can take from minutes up to a day. |
| **Cloud VM w/ nested virt** | GCP (nested-virt image), Azure Dv5, AWS `*.metal`. | You want it **right now**. More expensive; you must enable nested virtualization on the instance. |
| **Spare physical PC** | Any 8-core / 32 GB box with an Intel VT-x / AMD-V CPU, running Ubuntu 22.04. | You already have hardware. Free. |

Minimum: **8 CPU threads, 32 GB RAM, 250 GB SSD, Ubuntu 22.04 LTS**, CPU with
virtualization (Intel VT-x / AMD-V). More RAM = more concurrent detonations.

You will also need a **Windows 10 VM image** — Microsoft provides free 90-day
evaluation VMs (legal for testing): search "Microsoft Edge / IE dev VMs" or the
Windows evaluation center.

## Phase 1 — Bootstrap the host (do this first)

SSH into the fresh box as root and run:

```bash
git clone https://github.com/MrHerc/cyclowareness-sandbox.git
cd cyclowareness-sandbox/infra/detonation-host
sudo bash 01-bootstrap.sh
```

It installs KVM/QEMU, Docker, packet-capture tools, a locked-down firewall and a
`sandbox` service user, then prints a **status block**. **Paste that block back to
Claude** — the `Nested virt flag` line decides the next step. Do not continue
until nested virt is confirmed (or confirmed unnecessary on bare metal).

## Phase 2 — CAPEv2 (the detonation engine)

CAPEv2 (an actively maintained Cuckoo fork) is our dynamic backend. It ships its
own installer; we do not re-script it. On the bootstrapped host, as the `sandbox`
user, follow the upstream install — Claude will walk you through it line by line
tailored to your host:

- Repo: `https://github.com/kevoreilly/CAPEv2`
- Installer: `installer/cape2.sh` (Ubuntu 22.04 target)
- We configure: the KVM machinery, the results database, and the API that
  Cyclowareness Sandbox will poll.

Claude gives you the exact commands once Phase 1's status block confirms the host.

## Phase 3 — Windows analysis VM

Import the Windows 10 eval image into KVM, install the CAPE guest agent, disable
Windows Defender/updates inside the guest (so they do not fight the sample), take
a clean **snapshot** (the state every analysis reverts to). Claude provides the
per-step commands.

## Phase 4 — Network isolation + connect

- Route the analysis VM's traffic through **INetSim** (fake internet) or a
  controlled sinkhole so malware "sees" a network but nothing reaches the real
  internet. Capture full pcap.
- Point CAPEv2's API at the host; set `DYNAMIC_WORKER_TOKEN` and the Cyclowareness
  Sandbox API URL so the worker claims jobs, detonates, and posts real behaviour
  back through `/api/dynamic/*`.

## After setup

Submit a sample in Cyclowareness Sandbox → the job is dispatched to this host →
CAPEv2 detonates it in the snapshotted VM → behaviour, network, dropped files and
config are captured and merged into the verdict / CVSS / MITRE. **Real data, no
simulation.**

---

**Right now:** get a host from the table above, run Phase 1, and send Claude the
status block. That single step unblocks the entire dynamic track.
