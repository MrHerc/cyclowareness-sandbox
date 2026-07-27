#!/usr/bin/env bash
# Take the golden snapshot CAPE reverts to before every analysis.
#
# It must be a RUNNING snapshot. CAPE calls revertToSnapshot(flags=0) and then
# immediately waits for the domain to be RUNNING - it never starts the domain
# itself, and its own error message says "Your snapshot MUST BE in running
# state!". A powered-off snapshot reverts fine and then every task times out.
#
# This is also why the guest boots legacy BIOS. Measured on this host with
# libvirt 8.0.0:
#
#   UEFI (OVMF pflash), running  -> error: internal snapshots of a VM with
#                                   pflash based firmware are not supported
#   UEFI, powered off            -> works, but CAPE will not accept it
#   BIOS, running                -> created and reverted; the only usable shape
#
# Upgrading libvirt does not rescue UEFI: its changelog restores only *inactive*
# internal snapshots there and says active ones were meant to be disallowed.
set -euo pipefail

DOMAIN=${DOMAIN:-cape1}
NAME=${SNAPSHOT:-clean}
GUEST_IP=${GUEST_IP:-192.168.122.105}
AGENT="http://${GUEST_IP}:8000"

up() { curl -s --max-time 6 "$AGENT/" >/dev/null 2>&1; }

echo "== preflight =="
[[ "$(virsh domstate "$DOMAIN")" == "running" ]] || { echo "$DOMAIN is not running" >&2; exit 1; }
up || { echo "agent not answering - do not snapshot a guest CAPE cannot drive" >&2; exit 1; }
if virsh dumpxml "$DOMAIN" | grep -q pflash; then
  echo "$DOMAIN uses UEFI/pflash; a running internal snapshot is impossible" >&2
  exit 1
fi

echo "== ejecting install media (a mounted Windows ISO is a sandbox artefact) =="
for dev in $(virsh domblklist "$DOMAIN" --details | awk '$2=="cdrom"{print $3}'); do
  virsh change-media "$DOMAIN" "$dev" --eject --live --config 2>/dev/null | sed 's/^/   /' || true
done

echo "== replacing $NAME =="
virsh snapshot-delete "$DOMAIN" "$NAME" 2>/dev/null || true
virsh snapshot-create-as "$DOMAIN" "$NAME" \
  --description "Cyclowareness golden image: CAPE agent running as admin, Defender/firewall/updates off, telemetry silenced"
virsh snapshot-info "$DOMAIN" "$NAME" | grep -E 'Name|State' | sed 's/^/   /'

echo
echo "== proving the revert actually discards guest state =="
MARK=$(date +%s)
printf 'golden-snapshot-probe-%s\n' "$MARK" > /tmp/probe.txt
curl -s --max-time 20 -F 'filepath=C:\revert_probe.txt' -F "file=@/tmp/probe.txt" "$AGENT/store" >/dev/null
BEFORE=$(curl -s --max-time 20 -X POST -F 'filepath=C:\revert_probe.txt' "$AGENT/retrieve")
[[ "$BEFORE" == *"$MARK"* ]] || { echo "could not plant the probe" >&2; exit 1; }

virsh snapshot-revert "$DOMAIN" "$NAME"
[[ "$(virsh domstate "$DOMAIN")" == "running" ]] || { echo "domain is not running after revert" >&2; exit 1; }
for _ in $(seq 1 15); do up && break; sleep 3; done

AFTER=$(curl -s --max-time 20 -X POST -F 'filepath=C:\revert_probe.txt' "$AGENT/retrieve")
if [[ "$AFTER" == *"$MARK"* ]]; then
  echo "REVERT DID NOT DISCARD STATE - the snapshot is not usable" >&2
  exit 1
fi
echo "   probe present before, gone after: revert discards state"
echo
echo "Golden snapshot ready. Point conf/kvm.conf at it (snapshot = $NAME)."
