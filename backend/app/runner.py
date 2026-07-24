"""Off-request analysis execution.

Analysis runs on a small thread pool, not inside the request handler, for a
reason beyond latency: a request that blocks for the length of a full analysis
is a request an attacker can hold open to exhaust the server. Submission returns
a job id immediately; the client polls.

Each task opens its own database session — sessions are not thread-safe, and the
request's session is already closed by the time the task runs.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from . import metrics
from .db import session_scope
from .engine import pipeline
from .engine.models import SandboxJob

logger = logging.getLogger("sandbox.runner")

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="analysis")


def _guard(fn: Callable, *args) -> None:
    try:
        fn(*args)
    except Exception:  # noqa: BLE001 — a background crash must not be silent
        logger.exception("background task crashed")


def submit(fn: Callable, *args) -> None:
    _executor.submit(_guard, fn, *args)


def analyse_job(job_id: int, password: str | None = None) -> None:
    """Run one job to completion on its own session."""
    db = session_scope()
    metrics.jobs_inflight.inc()
    try:
        job = db.get(SandboxJob, job_id)
        if job is None:
            return
        with metrics.timed(metrics.analysis_duration):
            pipeline.run(db, job, password=password)
        db.commit()
        if job.status == "completed":
            metrics.jobs_processed_total.labels(risk_level=job.risk_level).inc()
            hits = 0
            for payload in (job.analysis or {}).values():
                if isinstance(payload, dict) and payload.get("analyzer") == "yara":
                    hits += len(payload.get("signals", []))
            if hits:
                metrics.yara_hits_total.inc(hits)
        elif job.status == "failed":
            metrics.jobs_failed_total.inc()
    except Exception:  # noqa: BLE001
        logger.exception("analysis crashed for job %s", job_id)
    finally:
        metrics.jobs_inflight.dec()
        db.close()


def submit_analysis(job_id: int, password: str | None = None) -> None:
    submit(analyse_job, job_id, password)
