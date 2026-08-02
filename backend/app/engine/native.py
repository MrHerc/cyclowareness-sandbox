"""The dynamic tier: the contract an external worker fulfils.

This module contains no detonation code, and that is deliberate — not a gap.

Dynamic analysis (running the sample and watching what it does: syscalls,
network, dropped files, memory) is the national sandbox hackathon brief's "Native Engine" and its
open-source sandbox integrations (Cuckoo, CAPEv2, Firejail). All of them require
a disposable, network-isolated virtual machine with kernel-level control. A
managed web host does not provide that, and MUST NOT — executing hostile code on
shared infrastructure is exactly the thing this whole codebase is built to avoid.

So the web application never detonates anything. Instead it defines the seam:

    web app  ──emits──▶  a DynamicRequest for a job
                             │
                    (an operator's isolated lab worker claims it)
                             │
    web app  ◀──ingests──  a DynamicReport of Signals + IOCs

The worker runs on hardware the operator controls — a Firejail/seccomp jail for
Linux samples, a snapshotted Windows VM behind an internet sinkhole for PE — and
returns results in the SAME Signal/IOC vocabulary every static analyzer uses
(``sandbox.native.*`` / ``sandbox.cuckoo.*`` ids). Because the contract is the
contract, a dynamic finding scores, exports and displays identically to a static
one; nothing downstream knows or cares that it came from off-host.

Until a worker is attached, ``dynamic_available()`` is False, the pipeline
records the dynamic tier as not-run with this reason, and every report states
it. "We did not run the sample" is a claim the product makes honestly, rather
than implying a behavioural analysis that never happened.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from .contracts import IOCs, Signal


@dataclass
class DynamicRequest:
    """What the web app hands to a dynamic worker."""

    job_public_id: str
    sha256: str
    family: str
    #: How the worker fetches the quarantined bytes. A signed, single-use URL in
    #: a real deployment; never the raw quarantine path, which is web-host-local.
    fetch_token: str
    #: Wall-clock budget the worker must honour (the brief suggests 120-300s).
    timeout_seconds: int = 180


@dataclass
class DynamicReport:
    """What a worker returns. Same vocabulary as every static analyzer."""

    job_public_id: str
    worker: str
    engine: str  # "native" | "cuckoo" | "capev2" | "firejail" | ...
    ran: bool
    unavailable_reason: str | None = None
    signals: list[Signal] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    iocs: IOCs = field(default_factory=IOCs)
    duration_ms: int = 0


#: Families a dynamic worker can meaningfully detonate.
#:
#: THE PIPELINE'S TIER TEXT AND THE QUEUE FILTER MUST READ THE SAME SET. They
#: did not: `_tier_record` chose its wording from `dynamic_available()` alone,
#: which asks whether a worker is attached and nothing about whether this
#: particular job will ever be offered to it. Measured on the live deployment,
#: **719 of 1626 completed reports** carried
#:
#:     "Queued for detonation on the attached isolated worker; behaviour will be
#:      merged into this report when the worker posts it."
#:
#: for jobs the queue never offers — 440 because the family is not in this set
#: (unknown 238, archive 162, diskimage 27, jar 7, apk 6), the rest because they
#: are inert `script` files the attributability gate deliberately excludes.
#:
#: Nothing errored, because nothing compared the two lists. `"ran": False` was
#: correct the whole time; the future tense was the lie.
DETONABLE_FAMILIES = frozenset({"pe", "elf", "script", "office", "pdf", "rtf", "lnk"})


def dynamic_available() -> bool:
    """True only when an operator has attached a dynamic worker.

    Gated on an explicit environment variable rather than on a probe: a
    behavioural-analysis capability must be turned on deliberately by whoever
    owns the isolated hardware, never inferred and never defaulted on.
    """
    return os.environ.get("SANDBOX_DYNAMIC_WORKER", "").strip().lower() in ("1", "true", "yes")


def unavailable_reason() -> str:
    return (
        "Dynamic detonation runs on an isolated worker that executes the sample under "
        "kernel-level supervision. No such worker is attached to this deployment, so the "
        "sample was not run — only statically analysed."
    )
