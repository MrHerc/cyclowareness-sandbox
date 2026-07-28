"""Cyclowareness Sandbox — static-first file & URL threat analysis.

One FastAPI process. In development the API runs on :8000 and Vite serves the UI
on :5173 (proxying /api). In the Docker image the compiled SPA is copied in and
served by this same process, so the whole product is ONE service on ONE origin:
no CORS, and nothing to misconfigure between two deployments.
"""
from __future__ import annotations

import logging
import math
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__, retention
from .api import admin, audit, auth, dynamic, meta, sandbox
from .config import get_settings
from .db import init_db
from .ratelimit import rate_limit_middleware

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
)
logger = logging.getLogger("sandbox.main")
settings = get_settings()


def _check_quarantine_is_writable() -> None:
    """Refuse to start if samples cannot be stored, and say why.

    The image runs as uid 10001, so a quarantine directory bind-mounted from a
    host that owns it as root is unwritable. Nothing failed at boot — the service
    reported healthy, served the UI, and answered every upload with a bare
    `500 Internal Server Error`, with the real cause (`PermissionError:
    '/quarantine/.partial-…'`) visible only in the container log. An operator
    following DEPLOY.md hits this on their first submission and has nothing to go
    on.

    A deployment fault should be fatal at startup and legible, not a mystery on
    every request.
    """
    import os
    import tempfile

    from .engine.storage import quarantine_root

    try:
        root = quarantine_root()
        with tempfile.NamedTemporaryFile(dir=root, prefix=".writecheck-"):
            pass
    except OSError as exc:
        raise RuntimeError(
            f"Quarantine directory is not usable: {exc}\n"
            f"  path : {os.environ.get('SANDBOX_QUARANTINE', '(default temp dir)')}\n"
            f"  uid  : {os.getuid() if hasattr(os, 'getuid') else 'n/a'}\n"
            "Every submission would fail with a 500. If this is a bind mount, give "
            "the container's user ownership of it, e.g.\n"
            "  chown -R 10001:10001 /path/on/host"
        ) from exc


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _check_quarantine_is_writable()
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

# --- a validation error must not itself be unserialisable --------------------
#
# FastAPI's default handler returns `jsonable_encoder(exc.errors())`, and every
# entry carries the `input` that failed — so rejecting `{"rule_weight": NaN}`
# put NaN in the 422 body, `json.dumps` refused it (Starlette hard-codes
# `allow_nan=False`), and the 422 became a **500 in text/plain**: the only
# non-JSON error this API produces, and the one no client branch handles.
#
# It is not specific to that field. Any endpoint taking a float had it, because
# `NaN` and `Infinity` are what `json.dumps` emits by default and what
# `json.loads` accepts, so they reach validation as real floats from any caller
# using a stock JSON library.
@app.exception_handler(RequestValidationError)
async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": _json_safe(jsonable_encoder(exc.errors()))})


def _json_safe(value: Any) -> Any:
    """Replace values JSON cannot carry with their literal names."""
    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# There was none of this at all. `POST /api/analyze` runs the whole static engine
# and writes to quarantine, and `POST /api/auth/login` could be walked through a
# password list at line speed. Registered after CORS so a rejected request still
# carries the headers a browser needs to read the 429.
app.middleware("http")(rate_limit_middleware)

app.include_router(meta.router)
app.include_router(auth.router)
app.include_router(sandbox.router)
app.include_router(admin.router)
app.include_router(dynamic.router)
app.include_router(audit.router)


# --- an unknown /api path is a client error, not a page ----------------------
#
# Registered here: AFTER every real router, so a route that exists still wins,
# and BEFORE the SPA fallback below, which would otherwise answer for it.
#
# In the Docker image — the only build customers run — the SPA fallback matched
# every path that no route claimed, so `GET /api/does-not-exist`, `/api/analyse`
# (a plausible typo for `/api/analyze`) and `/api/jobs/` with a trailing slash
# all returned **200 text/html**: 925 bytes of `index.html`. Measured on eight
# paths against production. `spa()`'s docstring asserted "/api/* never reaches
# here", which is true only of paths that already match a route — exactly the
# ones this is not about.
#
# The cost was not cosmetic. Every client's 404 handling became unreachable
# code: `api.ts` decides an error occurred from the status alone, so a 200 went
# straight to `res.json()` on HTML and threw a bare SyntaxError instead of an
# ApiError, and the UI reported a parse failure rather than "no such endpoint".
#
# Declared for every method, not just GET. The SPA fallback is GET-only, so an
# unknown path with any other verb produced a 405 whose Allow header advertised
# GET on an endpoint that does not exist.
_ANY_METHOD = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


@app.api_route("/api", methods=_ANY_METHOD, include_in_schema=False)
@app.api_route("/api/{rest:path}", methods=_ANY_METHOD, include_in_schema=False)
def api_not_found(rest: str = "") -> None:
    from fastapi import HTTPException

    # The same shape every other error on this API uses, so one client branch
    # handles all of them.
    raise HTTPException(status_code=404, detail="Unknown API endpoint")


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

        /api/* never reaches here — every real route is registered above and
        matches first, and `api_not_found` claims everything else under that
        prefix. That second half used to be missing, which is how an unknown API
        path came to answer 200 text/html. Path traversal is contained: the
        resolved path must stay inside the dist directory.
        """
        candidate = (_FRONTEND_DIST / full_path).resolve()
        if _FRONTEND_DIST in candidate.parents and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_FRONTEND_DIST / "index.html")
