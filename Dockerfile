# Cyclowareness Sandbox — single production image.
#
# The whole product ships as ONE image: the compiled SPA is built by a Node
# stage and copied into the Python image, where the FastAPI process serves it
# same-origin alongside the API. No CORS, one port, nothing to misconfigure.
#
# This image is the WEB SERVICE. It never executes a sample — it only quarantines
# and statically analyses. Detonation happens exclusively in the off-host worker
# (see ./worker), so this container needs no isolation runtime of its own.
#
# Build:
#   docker build -t cyclowareness-sandbox .
# Run (demo):
#   docker run --rm -p 8000:8000 cyclowareness-sandbox
# Run with a quarantine volume mounted noexec (untrusted bytes never execute):
#   docker run --rm -p 8000:8000 \
#     -e SANDBOX_QUARANTINE=/var/lib/sandbox/quarantine \
#     --mount type=volume,source=sandbox-quarantine,target=/var/lib/sandbox/quarantine,volume-opt=o=noexec \
#     cyclowareness-sandbox
#   (or bind a host path mounted noexec,nosuid,nodev)

# --- stage 1: build the frontend ---------------------------------------------
FROM node:20-slim AS frontend
WORKDIR /frontend

# Install deps first so the layer caches when only source changes. Assumes the
# frontend agent produced a package-lock.json; `npm ci` needs it.
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci

COPY frontend/ ./
RUN npm run build
# Output: /frontend/dist


# --- stage 2: python runtime -------------------------------------------------
FROM python:3.12-slim AS runtime

# System deps for the analysis engine:
#   - libmagic1: content-based file typing fallback (puremagic is pure-Python and
#     covers the common cases, but libmagic broadens coverage).
#   - unrar-free / unar: RAR *extraction* for rarfile (listing works without it).
#     Debian ships `unar`; the non-free `unrar` handles RAR5 more completely but
#     is not in the default repos — uncomment the alternative below if you add it.
# yara-python ships a self-contained wheel, so no libyara package is needed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libmagic1 \
        unar \
    && rm -rf /var/lib/apt/lists/*
#   Alternative for fuller RAR5 support (requires the non-free component enabled):
#   && apt-get install -y --no-install-recommends unrar

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_ENV=demo

WORKDIR /app

# Install Python deps first for layer caching.
#
# From the LOCK, not the declaration. requirements.txt states floors with the
# reasoning behind each one; requirements.lock.txt is the exact closure those
# floors resolved to, and it is what sbom.json and THIRD_PARTY_NOTICES.md
# describe. Installing from floors made the image un-reproducible and the SBOM
# false the moment anything upstream released - `fastapi` recorded as 0.140.0
# against 0.140.6 installed, which is exactly the drift a procurement scanner
# looks for.
COPY backend/requirements.txt backend/requirements.lock.txt ./
RUN pip install --no-cache-dir -r requirements.lock.txt \
    # pcodedmp is GPL-3.0-or-later and arrives as a hard dependency of oletools,
    # so a plain install puts GPL bytes in a proprietary image. We never import
    # it: olevba only reaches it from extract_pcode(), which the Office analyzer
    # does not call. Removing it therefore changes no behaviour and spares every
    # customer's procurement scanner a finding it would otherwise have to
    # adjudicate. See docs/licensing.md and THIRD_PARTY_NOTICES.md.
 && pip uninstall -y pcodedmp

# Application code.
COPY backend/ ./

# The compiled SPA, served same-origin by app.main (looks for ../frontend_dist).
COPY --from=frontend /frontend/dist ./frontend_dist

# Run as a non-root user; the quarantine dir is owned by it and mounted noexec.
#
# `/data` is created here for the same reason. docker-compose mounts a named
# volume there for the SQLite database, and Docker gives a fresh volume the
# ownership of the image's directory at that path — so a path the image never
# creates arrives root-owned and unwritable by uid 10001. That made
# `docker compose up --build`, the first command in both README.md and
# DEPLOY.md, fail on a clean machine.
RUN useradd --create-home --uid 10001 sandbox \
    && mkdir -p /var/lib/sandbox/quarantine /data \
    && chown -R sandbox:sandbox /app /var/lib/sandbox /data
USER sandbox

EXPOSE 8000

# Container-level healthcheck hits the API's honest readiness endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
