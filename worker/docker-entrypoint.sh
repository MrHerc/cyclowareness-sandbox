#!/usr/bin/env sh
# Entrypoint for the Cyclowareness Sandbox worker container.
#
# Fails fast on the one required setting, reports which detonation tools are
# actually present in the image, then hands off to the agent. Everything after
# this line runs inside a container that MUST itself be on hardware the operator
# controls and network-isolated — the container boundary is not the security
# boundary for live malware; the disposable host is.
set -eu

if [ -z "${DYNAMIC_WORKER_TOKEN:-}" ]; then
  echo "FATAL: DYNAMIC_WORKER_TOKEN is not set. The worker authenticates to the" >&2
  echo "       backend with this shared secret; refusing to start without it." >&2
  exit 1
fi

echo "Cyclowareness Sandbox worker starting"
echo "  backend    : ${SANDBOX_API_URL:-http://localhost:8000}"
echo "  worker name: ${WORKER_NAME:-cyclowareness-worker}"

# Report the native-engine tooling so the operator can see at a glance whether
# real detonation is possible in this image or only emulation/external.
if command -v firejail >/dev/null 2>&1; then
  echo "  firejail   : $(command -v firejail) (native confinement available)"
else
  echo "  firejail   : MISSING (native engine will refuse to run — safety invariant)"
fi
if command -v strace >/dev/null 2>&1; then
  echo "  strace     : $(command -v strace)"
else
  echo "  strace     : MISSING (native engine disabled)"
fi

exec python -u agent.py "$@"
