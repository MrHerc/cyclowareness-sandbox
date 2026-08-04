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

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import text

from .. import metrics, retention, sovereignty
from ..auth import _secure_equals, require_admin, require_analyst
from ..config import get_settings
from .dynamic_state import dynamic_state
from ..db import session_scope
from ..engine import native
from ..engine import scoring
from ..engine import storage

logger = logging.getLogger("sandbox.meta")

router = APIRouter(tags=["meta"])

SUPPORTED_EXTENSIONS = [
    ".exe", ".dll", ".sys", ".ps1", ".js", ".vbs", ".bat", ".cmd",
    ".py", ".sh", ".hta", ".elf", ".bin", ".so", ".jar", ".apk",
    ".zip", ".rar", ".7z", ".iso", ".img", ".pdf",
    # The two formats attackers moved to when macros were blocked. Both were
    # accepted and analysed as `unknown` — recognised, then ignored.
    ".rtf", ".lnk",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
]


@router.get("/api/health", operation_id="health_get")
@router.head("/api/health", operation_id="health_head")
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

    Two decorators rather than one ``api_route(methods=["GET", "HEAD"])``. That
    form is a single route carrying two methods, and FastAPI derives one
    operation id for it, so the schema shipped ``health_api_health_get`` twice --
    a duplicate operationId is a collision in any generated client. The ids are
    written out rather than derived, because the derived pair differed only by a
    suffix that the duplicate proved is not always applied.
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
    _dynamic_available, _dynamic_reason = dynamic_state(settings)
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
        # WHETHER THE KERNEL WOULD REFUSE TO RUN WHAT IS STORED HERE.
        #
        # Three files in this repo stated the quarantine is mounted
        # `noexec,nosuid,nodev`. The live deployment had 1,362 samples on a
        # plain `rw,relatime` directory and a script written there executed. A
        # control that exists only in documentation is not a control, so it is
        # measured and published: `true`, `false`, or `null` where the platform
        # cannot say.
        "quarantine_noexec": storage.quarantine_is_noexec(),
        # BOTH switches, not the flag alone — see `dynamic_state`. Reading only
        # `SANDBOX_DYNAMIC_WORKER` advertised a behavioural tier on a deployment
        # whose own ingest endpoints answered 503 to every request.
        "dynamic_worker": _dynamic_available,
        "dynamic_unavailable_reason": _dynamic_reason,
        # The sovereignty posture, with the refusal COUNT. The count is the part
        # that matters here: "no data leaves" is a claim, "we refused 14 outbound
        # calls" is evidence, and this is the endpoint an operator points an
        # auditor at — deliberately unauthenticated, so a buyer can read the
        # posture before they have an account.
        #
        # Which is exactly why the refusal LIST is not on it. Each entry carries
        # the thing that was refused: for `url_fetch` the submitted URL verbatim,
        # for `virustotal` the sample's SHA-256. So the proof that nothing left
        # the building was a public, live feed of what every tenant on this
        # deployment had been analysing. The list is served from
        # /api/sovereignty/refusals, to an authenticated caller.
        "sovereignty": sovereignty.status(),
        # How long this deployment keeps a customer's malware and its evidence.
        # It belongs next to the sovereignty posture because both answer the same
        # procurement question: what happens to our data once you have it.
        "retention": retention.policy(),
        "integrations": integrations,
        "supported_extensions": SUPPORTED_EXTENSIONS,
        # The real ceiling, because the UI was printing a hardcoded "Up to 32 MB"
        # next to the file picker. An operator who raises MAX_SAMPLE_MB gets an
        # interface that still refuses on the analyst's behalf, and one who
        # LOWERS it gets a promise the server then breaks with a 413.
        "max_sample_mb": settings.max_sample_mb,
        "metrics_enabled": metrics.enabled(),
    }


@router.get("/api/sovereignty/refusals")
def sovereignty_refusals(_identity=Depends(require_admin)):
    """The refusals in full, with what each one was — for the operator.

    Split off `/api/capabilities` because the two answer different questions to
    different readers. "How many did you refuse" is a posture a prospect may
    read; "which URLs and which sample hashes" is analysis data belonging to the
    deployment.

    `require_admin`, not `require_analyst`. An API key satisfies the latter, and
    the refusal records carry no tenant -- so one tenant's submit-only key was
    reading the URLs and sample hashes of every other tenant on the deployment.
    The docstring above already names the right reader: the operator. That is
    what `require_admin` means here, exactly as it does for `/api/admin/*`.
    """
    return sovereignty.refusals(include_detail=True)


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
        if not _secure_equals(presented, token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Metrics require the configured token",
            )
    body, content_type = metrics.render()
    return Response(content=body, media_type=content_type)
