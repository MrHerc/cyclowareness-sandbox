#!/usr/bin/env bash
# Build the second CD the guest boots with: the unattended answer file, the
# first-logon provisioning script, a Python runtime and the CAPE agent.
#
# This existed only as commands typed on the host. 04-create-guest.sh refuses to
# run without cape-provision.iso, and nothing in the repository produced it - so
# the "reproducible from the repository" claim was false for anyone starting from
# a clean machine.
#
# Windows Setup finds autounattend.xml by scanning removable media for it at the
# root, which is why it rides on this ISO rather than being injected into the
# install image.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/var/lib/libvirt/iso/cape-provision.iso}
CAPE_DIR=${CAPE_DIR:-/opt/CAPEv2}
PYTHON_URL=${PYTHON_URL:-https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe}
CACHE=${CACHE:-/var/lib/libvirt/aux/payload}

for tool in xorriso curl; do
  command -v "$tool" >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq xorriso curl
done
mkdir -p "$CACHE" "$(dirname "$OUT")"

echo "== agent =="
# Taken from the CAPE checkout rather than vendored: the agent and the host that
# drives it must be the same version, and CAPE bumps it.
AGENT="$CAPE_DIR/agent/agent.py"
[[ -f $AGENT ]] || { echo "no agent at $AGENT - install CAPE first" >&2; exit 1; }
cp "$AGENT" "$CACHE/agent.py"
printf '   agent.py %s bytes (AGENT_VERSION %s)\n' \
  "$(stat -c %s "$CACHE/agent.py")" \
  "$(grep -oE 'AGENT_VERSION *= *"[^"]+"' "$CACHE/agent.py" | head -1 | grep -oE '"[^"]+"' | tr -d '"')"

echo "== python runtime =="
# The agent needs a Python in the guest, and the guest has no internet by
# design - so it ships on the CD. Cached because it is 25 MB and this script is
# re-run whenever the answer file changes.
if [[ ! -s $CACHE/python-amd64.exe ]]; then
  curl -4 -sSL --max-time 600 -o "$CACHE/python-amd64.exe" "$PYTHON_URL"
fi
printf '   python-amd64.exe %s bytes\n' "$(stat -c %s "$CACHE/python-amd64.exe")"

echo "== mastering =="
STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT
cp "$HERE/guest/autounattend.xml" "$STAGE/autounattend.xml"
cp "$HERE/guest/setup.cmd" "$STAGE/setup.cmd"
cp "$HERE/guest/harden.py" "$STAGE/harden.py"
mkdir -p "$STAGE/payload"
cp "$CACHE/agent.py" "$CACHE/python-amd64.exe" "$STAGE/payload/"

rm -f "$OUT"
# -iso-level 4 so the answer file keeps its real name in the ISO 9660 tree too.
# Plain 8.3 truncates it to AUTOUNAT.XML, and the medium then depends entirely on
# Joliet for Windows Setup to find `autounattend.xml`. That did work, but the
# failure if it ever stopped working is silent and baffling: Setup simply ignores
# the answer file and stops on the language prompt, with nothing logged.
xorriso -as mkisofs -iso-level 4 -J -joliet-long -R -V CAPEPROV -o "$OUT" "$STAGE" 2>&1 | tail -1

echo "== verifying =="
# Windows Setup only looks at the ROOT of the medium; a file one directory down
# is silently ignored. Checked in both trees, because they can disagree.
for want in /autounattend.xml /setup.cmd /payload/agent.py /payload/python-amd64.exe; do
  xorriso -indev "$OUT" -find "$want" 2>/dev/null | grep -q . \
    || { echo "   MISSING from the Rock Ridge tree: $want" >&2; exit 1; }
done
if command -v isoinfo >/dev/null; then
  isoinfo -i "$OUT" -l 2>/dev/null \
    | sed -n '/Directory listing of \/$/,/^$/p' \
    | grep -qi 'autounattend.xml' \
    || { echo "   autounattend.xml is truncated in the ISO 9660 tree" >&2; exit 1; }
fi
printf '   %s  %s bytes\n' "$(basename "$OUT")" "$(stat -c %s "$OUT")"
echo "Provisioning ISO ready."
