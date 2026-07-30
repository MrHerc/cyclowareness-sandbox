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

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Match, Route

from . import __version__, retention
from .api import admin, audit, auth, dynamic, meta, sandbox
from .auth import require_analyst
from .config import get_settings
from .db import init_db
from .ratelimit import rate_limit_middleware

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
)
logger = logging.getLogger("sandbox.main")
settings = get_settings()


def _recover_interrupted_jobs() -> None:
    """Re-queue every job this process's predecessor was in the middle of.

    `running` and `queued` are owned by an in-process thread pool. A restart —
    a deploy, an OOM kill, `docker compose up -d` — takes the pool with it and
    leaves those rows exactly as they were, and nothing anywhere reset them. The
    job then sat in-flight forever: the queue page showed it working, the API
    answered 409 to every re-analysis, and the analyst's evidence was simply
    gone with no error to read.

    Re-queued rather than failed, because the quarantined bytes are still there
    and re-running is cheap and correct. The submission is left to the analyst's
    next action rather than fired here: a restart that recovers 200 jobs must not
    also start 200 analyses before the service is serving requests.
    """
    from sqlalchemy import update

    from .db import session_scope
    from .engine.models import JobStatus, SandboxJob

    db = session_scope()
    try:
        count = db.execute(
            update(SandboxJob)
            .where(SandboxJob.status.in_([JobStatus.RUNNING, JobStatus.QUEUED]))
            .values(status=JobStatus.QUEUED, stage="interrupted by a restart")
        ).rowcount
        db.commit()
        if count:
            logger.warning(
                "%d job(s) were in flight when this process last stopped and have been "
                "re-queued. Re-analyse them from the interface to run them again.",
                count,
            )
    except Exception:  # noqa: BLE001 — never block startup on the sweep
        logger.exception("could not re-queue interrupted jobs")
    finally:
        db.close()


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
    _recover_interrupted_jobs()
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
    # THE API SURFACE IS NOT PUBLIC.
    #
    # FastAPI mounts `/docs`, `/redoc` and `/openapi.json` unauthenticated by
    # default, so an anonymous caller could read the complete route list of a
    # deployment that holds live malware: every parameter, every schema, the
    # admin endpoints, the worker seam. Nothing there is a secret on its own, and
    # all of it is reconnaissance handed over for free.
    #
    # The schema is still served — to an authenticated analyst, through
    # `/api/openapi.json` below. Turned off entirely would have been the easy
    # answer and the wrong one: an operator integrating against this needs the
    # spec, and making them read the source instead is how undocumented clients
    # get written.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
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
    try:
        detail: Any = _json_safe(jsonable_encoder(exc.errors()))
    except (RecursionError, ValueError, TypeError):
        # Describing the rejection must not be able to fail harder than the
        # rejection. `jsonable_encoder` recurses over the input it echoes, so a
        # deeply nested body — around a thousand levels, roughly 2 KB — blew the
        # stack while EXPLAINING that the body was invalid, and the 422 became
        # the 500 this handler exists to prevent. Say less instead.
        detail = "Request body could not be parsed for this endpoint"
    return JSONResponse(status_code=422, content={"detail": detail})


def _json_safe(value: Any) -> Any:
    """Replace values JSON cannot carry with their literal names."""
    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


# ORDER IS LOAD-BEARING, AND IT WAS BACKWARDS.
#
# There was no rate limiting at all: `POST /api/analyze` runs the whole static
# engine and writes to quarantine, and `POST /api/auth/login` could be walked
# through a password list at line speed.
#
# The limiter answers 429 from a middleware, so that response never reaches the
# route — and it only carries CORS headers if the CORS middleware is OUTSIDE it.
# Starlette builds the stack so the LAST `add_middleware` call is the outermost,
# which is the opposite of what the old comment here assumed ("registered after
# CORS so a rejected request still carries the headers"). It was registered
# after, so it wrapped CORS instead, and a browser on the Vite dev origin got an
# opaque network failure where the message said "retry in 34 seconds".
#
# Limiter first, CORS second, so CORS ends up on the outside of everything.
app.middleware("http")(rate_limit_middleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/openapi.json", include_in_schema=False)
def authenticated_openapi(_identity=Depends(require_analyst)):
    """The OpenAPI schema, to an analyst who has authenticated.

    The default unauthenticated `/openapi.json` is turned off above. This is the
    replacement rather than a removal: an operator integrating against the
    product needs the spec, and the alternative to publishing it is undocumented
    clients written against guesses.
    """
    return app.openapi()


@app.get("/api/docs", include_in_schema=False)
def authenticated_docs(_identity=Depends(require_analyst)):
    """Swagger UI, pointed at the authenticated schema above.

    The page itself carries no secret; the fetch it makes does, and that fetch
    goes through `require_analyst` like everything else. A browser that reaches
    here without a session gets the same 401 the schema would give it.
    """
    from fastapi.openapi.docs import get_swagger_ui_html

    return get_swagger_ui_html(
        openapi_url="/api/openapi.json", title="Cyclowareness Sandbox — API"
    )


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
# Registered as a plain Starlette Route with `methods=None`, which matches EVERY
# verb. A list cannot: the first version enumerated seven, and TRACE, PROPFIND,
# LOCK and anything else a scanner invents fell past them into a framework 405
# advertising `Allow: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT` — seven
# methods this endpoint does not have, on a path that does not exist.
#
#: The routes that existed before this fallback did. Snapshotted because the
#: fallback itself matches everything, so it cannot be asked whether a path is
#: real without excluding itself — and the SPA mount registered after it would
#: answer for every path too.
_REAL_ROUTES = list(app.router.routes)


def _sub_routes(route: Any) -> list[Any]:
    """The routes inside a router wrapper, if this is one.

    `include_router` does not flatten into `app.router.routes` on this FastAPI
    (0.140): it appends a `_IncludedRouter` that holds the original router. Such
    a wrapper answers `matches()` correctly but has no `methods` of its own, so
    the methods for the Allow header have to be gathered from its children.
    Written against the *shape* rather than the class, so a version that goes
    back to flattening — or forward to another wrapper — still works.
    """
    inner = getattr(route, "routes", None)
    if inner is None:
        inner = getattr(getattr(route, "original_router", None), "routes", None)
    return list(inner) if inner else []


def _methods_at(routes: list[Any], scope: dict[str, Any]) -> set[str]:
    """Every method some real route accepts at this scope's path."""
    found: set[str] = set()
    for route in routes:
        children = _sub_routes(route)
        if children:
            found |= _methods_at(children, scope)
            continue
        match, _child = route.matches(scope)
        if match in (Match.PARTIAL, Match.FULL):
            found |= set(getattr(route, "methods", None) or ())
    return found


async def api_not_found(request: Request) -> Response:
    scope = request.scope

    # "No such endpoint" and "not with that verb" are different answers, and
    # claiming the first when the second is true is its own small lie. FastAPI
    # does not add HEAD to a GET route, so `HEAD /api/jobs` reaches here — and
    # answering 404 would say an endpoint the very next request will
    # successfully use does not exist. `/api/health` is render.yaml's
    # healthCheckPath and HEAD is what many uptime probes send. Measured on the
    # previous image, before this fallback existed, Starlette answered 405; this
    # reproduces that for the paths that are real, Allow header and all.
    if any(route.matches(scope)[0] is Match.PARTIAL for route in _REAL_ROUTES):
        allowed = _methods_at(_REAL_ROUTES, scope)
        # Omitted rather than guessed if the walk finds nothing: an Allow header
        # naming the wrong verbs is worse than no header at all.
        headers = {"Allow": ", ".join(sorted(allowed))} if allowed else {}
        return JSONResponse({"detail": "Method not allowed"}, status_code=405, headers=headers)

    # Starlette redirects a trailing slash to the route that exists, and a 307
    # preserves the method and the body — so `POST /api/analyze/url/` used to
    # complete the submission. Claiming every path under /api made that fallback
    # unreachable and turned it into a hard 404 that drops the body. Reissued.
    path: str = scope.get("path", "")
    if path.endswith("/") and len(path) > 1:
        probe = dict(scope, path=path.rstrip("/"))
        if any(route.matches(probe)[0] is not Match.NONE for route in _REAL_ROUTES):
            query = scope.get("query_string", b"").decode("latin-1")
            return RedirectResponse(
                probe["path"] + (f"?{query}" if query else ""), status_code=307
            )

    # The same shape every other error on this API uses, so one client branch
    # handles all of them.
    return JSONResponse({"detail": "Unknown API endpoint"}, status_code=404)


class _AnyMethod:
    """An ASGI endpoint, deliberately not a function.

    `Route(..., methods=None)` means "every verb" only when the endpoint is an
    ASGI app. Given a plain function, Starlette quietly substitutes
    `methods = ["GET"]` — so the first version of this registered a GET-only
    fallback, and `POST /api/does-not-exist` partial-matched it into a framework
    405 instead of reaching the handler at all. An instance is not a function,
    so `methods=None` survives and the route matches TRACE, PROPFIND and
    anything else a scanner invents.
    """

    async def __call__(self, scope, receive, send) -> None:
        response = await api_not_found(Request(scope, receive))
        await response(scope, receive, send)


for _fallback_path in ("/api", "/api/{rest:path}"):
    app.router.routes.append(
        Route(_fallback_path, _AnyMethod(), methods=None, include_in_schema=False)
    )


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

        Path traversal is contained: the resolved path must stay inside the dist
        directory.
        """
        # `api_not_found` above claims everything under a literal, single-slash,
        # lower-case `/api`. A router match is exact, so `//api/jobs` and
        # `/API/jobs` are not that path — they arrived here and were answered
        # with 200 text/html, which is the entire bug that fallback was written
        # to close, still reachable by anyone whose URL builder emits a double
        # slash. Anything that READS as an API path is refused here too.
        if _looks_like_api(full_path):
            raise HTTPException(status_code=404, detail="Unknown API endpoint")
        candidate = (_FRONTEND_DIST / full_path).resolve()
        if _FRONTEND_DIST in candidate.parents and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_FRONTEND_DIST / "index.html")


def _looks_like_api(full_path: str) -> bool:
    """Would a human call this an API path, whatever the router thinks?"""
    normalised = full_path.lstrip("/").lower()
    return normalised == "api" or normalised.startswith("api/")
