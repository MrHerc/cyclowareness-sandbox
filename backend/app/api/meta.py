"""Health, capabilities and metrics — what this deployment can honestly do.

The UI reads ``/api/capabilities`` at startup so it can state, precisely, what
is and is not available on this host: how many YARA rules loaded, which static
analyzers imported, whether a dynamic worker is attached, which open-source
sandbox integrations are configured. A product that implies a capability it does
not have is worse than one that names the gap.

It also reports the sovereignty posture and the running count of refused
outbound calls. That count is the difference between a marketing claim and a
verifiable one: an auditor asked to accept "your files never leave the building"
can be shown the switch, the exhaustive list of destinations it governs, and the
number of times it fired.
"""
from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import text

from .. import metrics, retention, sovereignty
from ..config import get_settings
from ..db import session_scope
from ..engine import native
from ..engine import scoring

logger = logging.getLogger("sandbox.meta")

router = APIRouter(tags=["meta"])

SUPPORTED_EXTENSIONS = [
    ".exe", ".dll", ".sys", ".ps1", ".js", ".vbs", ".bat", ".cmd",
    ".py", ".sh", ".hta", ".elf", ".bin", ".so", ".jar", ".apk",
    ".zip", ".rar", ".7z", ".iso", ".img", ".pdf",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
]


@router.api_route("/api/health", methods=["GET", "HEAD"])
def health(response: Response):
    """Is this process actually able to serve?

    It used to return a dict of constants, which cannot fail — so the Docker
    HEALTHCHECK and render.yaml's `healthCheckPath` both reported healthy for a
    process that could not reach its database and answered 500 to every real
    request. A health check that cannot fail is a health check that is not
    checking anything.

    One trivial round-trip is enough to tell "the process is up" from "the
    process is up and can serve". Nothing about the data is disclosed, so this
    stays unauthenticated — an orchestrator has to be able to call it.

    HEAD as well as GET: many uptime probes and load balancers send HEAD, and
    FastAPI does not add it to a GET route, so they were getting 405.
    """
    settings = get_settings()
    database = "ok"
    try:
        with session_scope() as session:
            session.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("health: database unreachable: %s", exc)
        database = "unreachable"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ok" if database == "ok" else "degraded",
        "service": "cyclowareness-sandbox",
        "env": settings.app_env,
        "ai_provider": settings.ai_provider,
        "database": database,
    }


@router.get("/api/capabilities")
def capabilities():
    settings = get_settings()
    from ..engine import analyzers

    yara_status: dict = {"loaded": 0}
    try:
        from ..engine import yara_engine

        raw = yara_engine.rules_loaded()
        yara_status = {
            "loaded": raw.get("rules_active", raw.get("loaded", 0)),
            "files": raw.get("files_loaded"),
            "failed": raw.get("failed_files") or None,
            "available": raw.get("available", True),
        }
    except Exception as exc:  # noqa: BLE001
        yara_status = {"loaded": 0, "error": type(exc).__name__}

    # The open-source sandbox integration matrix, if that module is present.
    try:
        from ..engine.integrations import capability_report

        integrations = capability_report()
    except Exception:  # noqa: BLE001 — integrations layer optional
        integrations = []

    return {
        "service": "cyclowareness-sandbox",
        "demo_mode": settings.is_demo,
        "ai_provider": settings.ai_provider,
        "scoring": {
            "model": "expert-weighted logistic (8 features)",
            "weights": scoring.get_weights(),
        },
        "static_analyzers": list(analyzers.all_names()),
        "unavailable_analyzers": analyzers.unavailable_analyzers(),
        "yara": yara_status,
        "dynamic_worker": native.dynamic_available(),
        # The sovereignty posture, with the refusal count. The count is the part
        # that matters: "no data leaves" is a claim, "we refused 14 outbound
        # calls and here they are" is evidence, and this is the endpoint an
        # operator points an auditor at.
        "sovereignty": sovereignty.status(),
        # How long this deployment keeps a customer's malware and its evidence.
        # It belongs next to the sovereignty posture because both answer the same
        # procurement question: what happens to our data once you have it.
        "retention": retention.policy(),
        "integrations": integrations,
        "supported_extensions": SUPPORTED_EXTENSIONS,
        "metrics_enabled": metrics.enabled(),
    }


@router.get("/metrics")
def prometheus_metrics(request: Request):
    """Prometheus exposition. Unauthenticated ONLY if the operator says so.

    These counters are business data: how many samples this deployment took
    today, how many were malicious, how many uploads were rejected, how long
    analysis takes. Published openly they tell a competitor a customer's volume
    and a customer's threat profile, from an endpoint nobody has to log in to —
    and a scraper needs no credential, so nobody ever notices it being read.

    So it is closed by default and opened deliberately, either by binding the
    port privately or by giving the scraper a token. `METRICS_TOKEN` is checked
    with `compare_digest`; `METRICS_PUBLIC=true` says out loud that this
    deployment intends anyone to read them.

    Deliberately NOT protected by the analyst session: a Prometheus scraper
    cannot log in, and a metrics endpoint that needs a browser is a metrics
    endpoint that never gets scraped.
    """
    settings = get_settings()
    token = settings.metrics_token.strip()
    # The demo build is a thing someone runs on a laptop to look at, and one of
    # the things worth looking at is the metrics endpoint. Only `production`
    # holds a real customer's numbers.
    if not (settings.metrics_public or settings.is_demo):
        if not token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Metrics are not exposed on this deployment",
            )
        presented = request.headers.get("authorization", "")
        presented = presented[7:] if presented.lower().startswith("bearer ") else presented
        if not secrets.compare_digest(presented, token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Metrics require the configured token",
            )
    body, content_type = metrics.render()
    return Response(content=body, media_type=content_type)
