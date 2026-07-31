"""Worker configuration, read entirely from the environment.

This module is deliberately dependency-free (standard library only) so that
``config.py`` imports cleanly even on a host where none of the optional engine
packages are installed. Nothing here talks to the network or touches a sample.

The worker is a separate program from the web service. It shares no code with
the backend app package; the only contract between them is the HTTP seam under
``/api/dynamic/*`` and the shared ``DYNAMIC_WORKER_TOKEN``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _str(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


#: What pydantic-settings accepts as false, which is what the backend parses
#: `SOVEREIGN_MODE` with. The two processes must read one environment variable
#: the same way or the promise splits in half between them.
_FALSE = {"0", "off", "f", "false", "n", "no"}


def _bool(name: str, default: bool) -> bool:
    """A flag, parsed the way the backend parses it.

    Anything unrecognised keeps the default. For a switch whose default is ON
    and whose subject is egress, a typo must not read as "off".
    """
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in _FALSE:
        return False
    if raw in {"1", "on", "t", "true", "y", "yes"}:
        return True
    return default


@dataclass(frozen=True)
class Config:
    """Everything the worker needs, resolved once at startup."""

    # --- backend seam -------------------------------------------------------
    #: Base URL of the Cyclowareness Sandbox web service. The worker only ever
    #: calls the three /api/dynamic/* endpoints on this host.
    api_url: str = "http://localhost:8000"
    #: Shared secret sent as ``X-Worker-Token`` on every request. REQUIRED —
    #: without it the backend closes the dynamic seam and the worker cannot run.
    worker_token: str = ""
    #: Free-text identity that appears in every report ("what detonated this").
    worker_name: str = "cyclowareness-worker"

    # --- loop behaviour -----------------------------------------------------
    poll_interval_seconds: int = 15
    #: Hard wall-clock cap on a single detonation. An engine that exceeds this
    #: is killed and reported as ``ran=False`` (timed out) — a sample that hangs
    #: the worker must never hang the queue.
    #:
    #: 600, NOT 120. The old default was shorter than a detonation and therefore
    #: guaranteed failure: measured on the reference host, CAPE task 4064 ran
    #: 315 seconds (12:10:44 -> 12:15:59) and the worker had already given up at
    #: 120 and filed `ran=False`. The sample detonated perfectly and the product
    #: recorded nothing.
    #:
    #: The arithmetic was never going to work. CAPE's own cuckoo.conf sets
    #: `default = 200` for the analysis and `vm_state = 300` for snapshot revert
    #: and boot — 200 + revert + boot + processing does not fit in 120 under any
    #: circumstances. 600 clears the observed 315 with headroom while still
    #: bounding a wedged guest.
    engine_timeout_seconds: int = 600
    #: How many jobs to claim per queue poll.
    queue_limit: int = 20
    #: How many detonations may be in flight at once.
    #:
    #: Set this to the number of analysis machines the sandbox has, and no
    #: higher — the guests are the scarce resource, and CAPE queues anything
    #: beyond them, which only makes each task's wall-clock look worse.
    #:
    #: The default is 1 because that is what a single-guest install can honour,
    #: and because the loop was strictly sequential before this existed: adding
    #: guests to the sandbox bought nothing at all, since the worker detonated
    #: one sample at a time regardless of how many machines were idle.
    #:
    #: It matters more now that the timeout is 600: at concurrency 1 a
    #: ten-minute ceiling is six jobs an hour. Set it to the number of guests —
    #: the reference cluster has three (cape1..cape3) — and no higher, because
    #: CAPE queues anything beyond them and that only makes each task's
    #: wall-clock look worse.
    max_concurrent_jobs: int = 1
    #: HTTP request timeout for talking to the backend (not the engine timeout).
    http_timeout_seconds: int = 30

    # --- containment gate ---------------------------------------------------
    #: A command that answers "is this host safe to detonate on, right now?".
    #: Exit 0 means contained; anything else means it is not, and the batch is
    #: refused. `infra/detonation-host/containment-status.sh` is the one written
    #: for the reference host; it reads the nftables containment table and costs
    #: a few milliseconds, so it can run before every batch.
    #:
    #: Empty disables the gate, which is correct for deployments that do not
    #: detonate at all (a Qiling-only laptop confines by construction). It is NOT
    #: silent: the worker says so once at startup, because "no gate configured"
    #: and "gate passing" must never look the same in a log.
    containment_check: str = ""
    #: A gate that hangs is a gate that gets removed. Short by design: the check
    #: reads a ruleset, it does not talk to a guest.
    containment_check_timeout_seconds: int = 15

    # --- native engine ------------------------------------------------------
    #: Absolute path to firejail. If it is missing the native engine refuses to
    #: run rather than executing a sample unconfined — the safety invariant.
    firejail_bin: str = "firejail"
    strace_bin: str = "strace"
    #: When set, native detonations are given a route to this sinkhole address
    #: instead of real network. Empty means "no network at all" (default).
    native_sinkhole: str = ""

    # --- sovereignty --------------------------------------------------------
    #: "Nothing leaves this deployment." Same variable and same default as the
    #: web service's `SOVEREIGN_MODE`, because it is one promise, not two.
    #:
    #: It has to be read here as well: the backend's choke point governs the
    #: backend's process, and this is a SEPARATE PROGRAM. `/api/capabilities`
    #: listed "CAPEv2 cluster — uploads the sample file for detonation" as
    #: Blocked while the worker, with `CAPEV2_URL` set, uploaded every
    #: detonatable sample to it. The screen was not lying about the backend; it
    #: was answering for a process it cannot see.
    #:
    #: On, the three upload engines are unavailable and say why at startup. The
    #: engines that detonate on this host — native and Qiling — are untouched:
    #: they send nothing anywhere, which is the whole point of shipping them.
    sovereign_mode: bool = True

    # --- optional open-source sandbox integrations --------------------------
    #: A REST base URL enables the matching client. Empty disables it.
    cuckoo_url: str = ""
    cuckoo_token: str = ""
    capev2_url: str = ""
    capev2_token: str = ""
    joe_url: str = ""
    joe_apikey: str = ""

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            api_url=_str("SANDBOX_API_URL", "http://localhost:8000").rstrip("/"),
            worker_token=_str("DYNAMIC_WORKER_TOKEN"),
            worker_name=_str("WORKER_NAME", "cyclowareness-worker"),
            poll_interval_seconds=_int("POLL_INTERVAL_SECONDS", 15),
            engine_timeout_seconds=_int("ENGINE_TIMEOUT_SECONDS", 120),
            queue_limit=_int("QUEUE_LIMIT", 20),
            max_concurrent_jobs=max(1, _int("MAX_CONCURRENT_JOBS", 1)),
            http_timeout_seconds=_int("HTTP_TIMEOUT_SECONDS", 30),
            containment_check=_str("CONTAINMENT_CHECK"),
            containment_check_timeout_seconds=_int("CONTAINMENT_CHECK_TIMEOUT_SECONDS", 15),
            firejail_bin=_str("FIREJAIL_BIN", "firejail"),
            strace_bin=_str("STRACE_BIN", "strace"),
            native_sinkhole=_str("NATIVE_SINKHOLE"),
            sovereign_mode=_bool("SOVEREIGN_MODE", True),
            cuckoo_url=_str("CUCKOO_URL").rstrip("/"),
            cuckoo_token=_str("CUCKOO_TOKEN"),
            capev2_url=_str("CAPEV2_URL").rstrip("/"),
            capev2_token=_str("CAPEV2_TOKEN"),
            joe_url=_str("JOE_URL").rstrip("/"),
            # JOE_API_KEY is the documented name and the one the backend's
            # integration descriptor checks to decide whether to show Joe as
            # configured. This side read only JOE_APIKEY, so an operator who
            # followed the documentation saw "configured" in the UI while the
            # worker quietly refused to run the engine. Both are accepted;
            # the documented spelling wins.
            joe_apikey=_str("JOE_API_KEY") or _str("JOE_APIKEY"),
        )

    def require_token(self) -> None:
        """Fail loudly at startup if the shared secret is missing."""
        if not self.worker_token:
            raise SystemExit(
                "DYNAMIC_WORKER_TOKEN is required. The worker authenticates to the "
                "backend with this shared secret; without it the dynamic seam is "
                "closed and no jobs can be claimed."
            )
