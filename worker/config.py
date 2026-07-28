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
    engine_timeout_seconds: int = 120
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
