# Cyclowareness Sandbox — off-host dynamic-analysis worker.
#
# SAFETY: This image runs samples' own code (the native engine). It MUST run on
# hardware the operator controls, network-isolated, ideally a disposable VM that
# is snapshotted and rolled back between runs. The container boundary is NOT a
# malware containment boundary — Firejail + seccomp inside, plus the isolated
# host outside, are. Never run this image on the same host as the web service.
#
# Build:  docker build -t cyclowareness-worker .
# Run:    docker run --rm \
#           -e SANDBOX_API_URL=http://backend:8000 \
#           -e DYNAMIC_WORKER_TOKEN=... \
#           --cap-add=SYS_PTRACE \        # strace needs ptrace
#           --security-opt seccomp=unconfined \  # firejail manages its own seccomp
#           cyclowareness-worker
#
# Firejail needs a user namespace; on a locked-down Docker host you may also need
# --privileged or a custom seccomp profile. That is deliberate friction: this
# container is meant for a dedicated analysis VM, not a general cluster.

FROM python:3.12-slim

# Native-engine tooling. These are BINARIES the native engine shells out to;
# without firejail the native engine refuses to run (it never executes a sample
# unconfined), so it is installed here to make real detonation possible.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        firejail \
        strace \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /worker

# Install Python deps first for layer caching. Only `requests` is required.
# Nothing GPL is baked in: the Qiling emulation adapter ships as source but the
# GPL-2.0 `qiling` package is deliberately not installed here (see
# requirements.txt and ../docs/licensing.md), so this image stays clean for a
# BUSL-1.1 product — and small.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x docker-entrypoint.sh

# Run as a non-root user. Firejail itself drops privileges further per sample
# (--noroot); this just avoids the agent process owning root in the container.
RUN useradd --create-home --uid 10001 worker \
    && chown -R worker:worker /worker
USER worker

ENV PYTHONUNBUFFERED=1 \
    SANDBOX_API_URL=http://localhost:8000 \
    WORKER_NAME=cyclowareness-worker \
    POLL_INTERVAL_SECONDS=15 \
    ENGINE_TIMEOUT_SECONDS=600

ENTRYPOINT ["./docker-entrypoint.sh"]
