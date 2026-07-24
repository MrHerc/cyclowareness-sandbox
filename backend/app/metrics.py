"""Prometheus instrumentation.

The brief asks each module to expose metrics; this service is one process, so
they live in one registry and one ``/metrics`` endpoint. Names mirror the
brief's suggested per-module metrics (``uploader.requests_total`` becomes
``sandbox_uploads_total``, and so on) so a Grafana board built against the spec
maps cleanly.

``prometheus_client`` is an optional dependency: if it is not installed the
whole module degrades to no-ops, and the service still runs. Metrics are an
observability nicety, never a reason the analyser cannot analyse.
"""
from __future__ import annotations

from contextlib import contextmanager

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

    _ENABLED = True
except Exception:  # noqa: BLE001 — prometheus_client not installed
    _ENABLED = False
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"


class _NoopMetric:
    def labels(self, *_a, **_k):  # noqa: ANN002, ANN003
        return self

    def inc(self, *_a, **_k):  # noqa: ANN002, ANN003
        return None

    def dec(self, *_a, **_k):  # noqa: ANN002, ANN003
        return None

    def observe(self, *_a, **_k):  # noqa: ANN002, ANN003
        return None

    def set(self, *_a, **_k):  # noqa: ANN002, ANN003
        return None


def _counter(name: str, doc: str, labels: tuple[str, ...] = ()):
    if not _ENABLED:
        return _NoopMetric()
    return Counter(name, doc, labels) if labels else Counter(name, doc)


def _histogram(name: str, doc: str, labels: tuple[str, ...] = ()):
    if not _ENABLED:
        return _NoopMetric()
    return Histogram(name, doc, labels) if labels else Histogram(name, doc)


def _gauge(name: str, doc: str):
    if not _ENABLED:
        return _NoopMetric()
    return Gauge(name, doc)


# --- submission --------------------------------------------------------------
uploads_total = _counter("sandbox_uploads_total", "Samples submitted", ("source",))
upload_rejects_total = _counter(
    "sandbox_upload_rejects_total", "Submissions rejected before analysis", ("reason",)
)
fetch_duration = _histogram("sandbox_url_fetch_seconds", "URL download wall time")
fetch_failures_total = _counter("sandbox_url_fetch_failures_total", "URL downloads that failed", ("reason",))

# --- analysis ----------------------------------------------------------------
jobs_processed_total = _counter("sandbox_jobs_processed_total", "Analyses completed", ("risk_level",))
jobs_failed_total = _counter("sandbox_jobs_failed_total", "Analyses that raised")
analysis_duration = _histogram("sandbox_analysis_seconds", "Full pipeline wall time")
yara_hits_total = _counter("sandbox_yara_hits_total", "YARA rule matches across all samples")
jobs_inflight = _gauge("sandbox_jobs_inflight", "Analyses currently running")

# --- dynamic tier ------------------------------------------------------------
dynamic_reports_total = _counter(
    "sandbox_dynamic_reports_total", "Dynamic reports ingested from workers", ("engine",)
)

# --- reporting ---------------------------------------------------------------
reports_generated_total = _counter(
    "sandbox_reports_generated_total", "Exports produced", ("format",)
)


@contextmanager
def timed(histogram):  # noqa: ANN001
    import time

    start = time.perf_counter()
    try:
        yield
    finally:
        histogram.observe(time.perf_counter() - start)


def render() -> tuple[bytes, str]:
    """Return ``(body, content_type)`` for the /metrics endpoint."""
    if not _ENABLED:
        return (b"# prometheus_client not installed\n", CONTENT_TYPE_LATEST)
    return (generate_latest(), CONTENT_TYPE_LATEST)


def enabled() -> bool:
    return _ENABLED
