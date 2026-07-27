"""The open-source sandbox integration catalog.

This module is the single source of truth for *what this deployment can be
connected to*. ``/api/capabilities`` renders it as a matrix so the product can
state — honestly, per host — which engines are live and which are dormant but
one credential away.

Every descriptor is real: the env vars named here are the same ones the worker
and the sibling client modules read. Nothing is aspirational; a row that is not
``configured`` is a row an operator can turn on by supplying exactly what its
``requires`` string says.

The web service itself never detonates a sample. The dynamic-tier engines below
all run *off-host* in the worker (native/emulator/jail) or *out-of-process* on a
separate sandbox cluster (Cuckoo/CAPE/Joe). The static-tier ones (Strelka,
VirusTotal) are file-scan / reputation services the web service may query
directly. This separation is the whole point of the descriptor: it records where
the work happens, not just whether it is on.

Each row also declares its ``destination``: the sovereignty choke-point key its
client calls, or empty when the engine is worker-resident and nothing leaves the
building. That declaration is what lets the matrix say "configured, and refused"
rather than showing a credentialed integration as live on a deployment whose own
policy will never let it run.
"""
from __future__ import annotations

from .base import Engine

#: The catalog. Order is presentation order for the matrix: the team's own
#: engines first, then the open-source detonation sandboxes, then the static
#: file-scan / reputation services.
ENGINES: list[Engine] = [
    Engine(
        key="native",
        name="Native behaviour engine",
        vendor="Cyclowareness",
        kind="native",
        tier="dynamic",
        env_keys=[],  # worker-resident: reachable when a worker can attach
        requires="An off-host worker attached with DYNAMIC_WORKER_TOKEN.",
        notes=(
            "The team's own syscall/behaviour tracer. Runs the sample inside "
            "the isolated worker and reports observed syscalls, process and "
            "network activity as Signals. Never executes on the web service."
        ),
        docs_url="",
    ),
    Engine(
        key="qiling",
        name="Qiling emulation",
        vendor="Qiling Framework (open source)",
        kind="emulator",
        tier="dynamic",
        env_keys=[],  # worker-resident
        requires="An off-host worker attached with DYNAMIC_WORKER_TOKEN.",
        notes=(
            "Scriptable CPU/syscall emulation. Runs a sample under emulation "
            "rather than on real hardware, so it can observe behaviour without "
            "a live OS target — useful for cross-architecture and headless "
            "detonation. Runs in the worker, never on the web service."
        ),
        docs_url="https://github.com/qilingframework/qiling",
    ),
    Engine(
        key="firejail",
        name="Firejail sandbox",
        vendor="Firejail (open source)",
        kind="opensource-sandbox",
        tier="dynamic",
        env_keys=[],  # worker-resident
        requires="A Linux worker with firejail, attached via DYNAMIC_WORKER_TOKEN.",
        notes=(
            "seccomp-bpf and Linux namespace jail. The worker detonates the "
            "sample inside a firejail confinement (restricted syscalls, private "
            "filesystem and network namespaces) and reports behaviour as "
            "Signals. Linux-only; runs off-host in the worker."
        ),
        docs_url="https://github.com/netblue30/firejail",
    ),
    Engine(
        key="cuckoo",
        name="Cuckoo Sandbox",
        vendor="Cuckoo (open source)",
        kind="opensource-sandbox",
        tier="dynamic",
        env_keys=["CUCKOO_URL", "CUCKOO_TOKEN"],
        destination="cuckoo",
        requires="A reachable Cuckoo instance: set CUCKOO_URL and CUCKOO_TOKEN.",
        notes=(
            "The classic open-source automated malware analysis system. Samples "
            "are submitted to a separate Cuckoo cluster over its REST API for "
            "full dynamic detonation in isolated guest VMs; the report is "
            "ingested and re-scored. Runs entirely out-of-process."
        ),
        docs_url="https://cuckoosandbox.org",
    ),
    Engine(
        key="capev2",
        name="CAPE Sandbox",
        vendor="CAPEv2 (open source)",
        kind="opensource-sandbox",
        tier="dynamic",
        env_keys=["CAPEV2_URL", "CAPEV2_TOKEN"],
        destination="capev2",
        requires="A reachable CAPEv2 instance: set CAPEV2_URL and CAPEV2_TOKEN.",
        notes=(
            "Config-and-payload-extracting sandbox, a Cuckoo descendant focused "
            "on malware configuration and unpacked-payload extraction. Samples "
            "are submitted to a separate CAPEv2 cluster over its REST API; the "
            "report is ingested and re-scored. Runs out-of-process."
        ),
        docs_url="https://github.com/kevoreilly/CAPEv2",
    ),
    Engine(
        key="strelka",
        name="Strelka file scanning",
        vendor="Target Strelka (open source)",
        kind="opensource-sandbox",
        tier="static",
        env_keys=["STRELKA_URL"],
        destination="strelka",
        requires="A reachable Strelka frontend: set STRELKA_URL.",
        notes=(
            "Real-time, scalable file-scanning and enrichment orchestrator "
            "(YARA rules, unpackers, metadata extractors). Static only — it "
            "does not execute the sample. Files are streamed to a separate "
            "Strelka cluster and the scan tree is ingested."
        ),
        docs_url="https://github.com/target/strelka",
    ),
    Engine(
        key="joesandbox",
        name="Joe Sandbox (community)",
        vendor="Joe Security",
        kind="opensource-sandbox",
        tier="dynamic",
        env_keys=["JOE_API_KEY"],
        destination="joesandbox",
        requires="A Joe Sandbox community API key: set JOE_API_KEY.",
        notes=(
            "Community edition of a deep dynamic analysis sandbox. Samples are "
            "submitted to the hosted Joe Sandbox service over its Web API for "
            "detonation and behavioural reporting. Rate-limited on the "
            "community tier; runs off-site."
        ),
        docs_url="https://www.joesandbox.com",
    ),
    Engine(
        key="virustotal",
        name="VirusTotal reputation",
        vendor="VirusTotal (Google)",
        kind="threat-intel",
        tier="static",
        env_keys=["VT_API_KEY"],
        destination="virustotal",
        requires="A VirusTotal API key: set VT_API_KEY.",
        notes=(
            "Hash-reputation lookup. Queries the multi-engine verdict for a "
            "sample's SHA-256 — it uploads nothing and does not detonate. An "
            "'unknown' hash is treated as unknown, never as clean."
        ),
        docs_url="https://docs.virustotal.com/reference/overview",
    ),
]


def capability_report() -> list[dict]:
    """The full integration matrix as serialisable rows, in presentation order."""
    return [e.describe() for e in ENGINES]


def configured_count() -> int:
    """How many integrations are actually live on this deployment."""
    return sum(1 for e in ENGINES if e.configured())
