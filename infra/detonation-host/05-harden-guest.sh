#!/usr/bin/env bash
# Silence the guest's own network chatter, through the CAPE agent.
#
# Why this is a separate step and not part of the unattended install: several of
# these settings only stick once Windows has finished its first-boot work, and
# doing it over the agent means the same script can be re-applied to an existing
# guest without rebuilding the image.
#
# Why it matters: an idle Windows 10 guest reaches ~22 external endpoints before
# a sample does anything, and those get lifted as IOCs. Subtracting them
# afterwards does not work - the same services answer from a different CDN or
# anycast member every run - so the traffic has to stop being generated.
# Measured effect of this script: 22 endpoints -> 12.
set -euo pipefail

GUEST_IP=${GUEST_IP:-192.168.122.105}
AGENT="http://${GUEST_IP}:8000"
HERE=$(cd "$(dirname "$0")" && pwd)

up() { curl -s --max-time 6 "$AGENT/" >/dev/null 2>&1; }

echo "== waiting for the guest agent on $GUEST_IP =="
for _ in $(seq 1 30); do up && break; sleep 4; done
up || { echo "agent unreachable - is the guest running?" >&2; exit 1; }

echo "== uploading and running the hardening script =="
curl -s --max-time 30 -F 'filepath=C:\harden.py' -F "file=@${HERE}/guest/harden.py" \
  "$AGENT/store" | sed 's/^/   /'
curl -s --max-time 300 -X POST -F 'filepath=C:\harden.py' -F 'cwd=C:\' "$AGENT/execpy" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("  ",d.get("message"));print("  ",(d.get("stdout") or "").strip())'

echo "== rebooting so the disabled services stay disabled =="
virsh reboot cape1
for _ in $(seq 1 30); do sleep 6; up && break; done
up || { echo "guest did not come back" >&2; exit 1; }

echo "== confirming the noisiest services are dead =="
for svc in DiagTrack wlidsvc DoSvc WerSvc; do
  state=$(curl -s --max-time 25 -X POST --data-urlencode "command=sc query $svc" "$AGENT/execute" \
    | python3 -c 'import sys,json,re;o=json.load(sys.stdin).get("stdout") or "";m=re.search(r"STATE\s*:\s*\d+\s+(\w+)",o);print(m.group(1) if m else "?")')
  printf "   %-12s %s\n" "$svc" "$state"
done

cat <<'NOTE'

The residual endpoints are Akamai/Microsoft CDN and cannot be removed without
making the guest obviously artificial. They are suppressed in the product
instead - see worker/engines/baseline_networks.txt, and REGENERATE that file
after running this script, because it describes this exact image.
NOTE
