"""Cyclowareness Sandbox — static-first file & URL threat analysis.

One FastAPI process. In development the API runs on :8000 and Vite serves the UI
on :5173 (proxying /api). In the Docker image the compiled SPA is copied in and
served by this same process, so the whole product is ONE service on ONE origin:
no CORS, and nothing to misconfigure between two deployments.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__, retention
from .api import admin, audit, auth, dynamic, meta, sandbox
from .config import get_settings
from .db import init_db

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
)
logger = logging.getLogger("sandbox.main")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if settings.is_demo:
        logger.info(
            "DEMO build. Log in at the UI with  username=%s  password=%s  "
            "(override with ANALYST_USERNAME / ANALYST_PASSWORD). API key: %s",
            settings.analyst_username,
            settings.analyst_password,
            settings.api_key_list[0] if settings.api_key_list else "(none)",
        )
    # Retention runs in-process rather than from a cron entry: this ships as an
    # appliance into environments that are often air-gapped, and an operator who
    # has to wire up a scheduler is an operator whose disk eventually fills.
    if retention.start_scheduler():
        logger.info("retention: %s", retention.policy()["statement"])
    else:
        logger.info("retention is not configured — samples and reports are kept indefinitely")
    try:
        yield
    finally:
        retention.stop_scheduler()


app = FastAPI(
    title="Cyclowareness Sandbox",
    description=(
        "Static-first malware and URL analysis. Uploads and URL-fetched files are "
        "quarantined (never executed), statically analysed (PE/Office/script/PDF/ELF "
        "parsers + YARA), scored by a transparent rule + model hybrid, and exported "
        "as JSON, STIX 2.1 or PDF. Dynamic detonation runs off-host through the "
        "native-engine worker seam."
    ),
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(meta.router)
app.include_router(auth.router)
app.include_router(sandbox.router)
app.include_router(admin.router)
app.include_router(dynamic.router)
app.include_router(audit.router)


# --- serve the built frontend ------------------------------------------------
# Present only when a compiled SPA has been built in (the Docker image does this).
# In local dev the directory does not exist and Vite serves the frontend, so this
# whole block is a no-op there.
_FRONTEND_DIST = __import__("pathlib").Path(__file__).resolve().parent.parent / "frontend_dist"

if _FRONTEND_DIST.is_dir():
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    app.mount("/assets", StaticFiles(directory=_FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        """Return a real file when one exists, else index.html for client routing.

        /api/* never reaches here — those routes are registered above and match
        first. Path traversal is contained: the resolved path must stay inside
        the dist directory.
        """
        candidate = (_FRONTEND_DIST / full_path).resolve()
        if _FRONTEND_DIST in candidate.parents and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_FRONTEND_DIST / "index.html")
