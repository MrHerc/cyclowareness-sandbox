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

from fastapi import APIRouter, Response

from .. import metrics, sovereignty
from ..config import get_settings
from ..engine import native
from ..engine import scoring

router = APIRouter(tags=["meta"])

SUPPORTED_EXTENSIONS = [
    ".exe", ".dll", ".sys", ".ps1", ".js", ".vbs", ".bat", ".cmd",
    ".py", ".sh", ".hta", ".elf", ".bin", ".so", ".jar", ".apk",
    ".zip", ".rar", ".7z", ".iso", ".img", ".pdf",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
]


@router.get("/api/health")
def health():
    settings = get_settings()
    return {
        "status": "ok",
        "service": "cyclowareness-sandbox",
        "env": settings.app_env,
        "ai_provider": settings.ai_provider,
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
        "integrations": integrations,
        "supported_extensions": SUPPORTED_EXTENSIONS,
        "metrics_enabled": metrics.enabled(),
    }


@router.get("/metrics")
def prometheus_metrics():
    body, content_type = metrics.render()
    return Response(content=body, media_type=content_type)
