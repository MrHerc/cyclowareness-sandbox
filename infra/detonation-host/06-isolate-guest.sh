#!/usr/bin/env bash
# Install the guest containment rules and verify them from inside the guest.
#
# THIS IS THE SAFETY GATE. Do not detonate real malware on a host that has not
# passed the verification at the end of this script: a sample that reaches the
# internet from a rented server earns an abuse complaint against the person
# renting it, and one that reaches the host's SSH is a sandbox escape.
#
# Two ordering mistakes cost real time here, both found by measuring from inside
# the guest rather than reading the ruleset:
#
#   * an APPENDED `-i virbr0 -j DROP` never fires, because ufw's "allow 22/tcp
#     from anywhere" sits in a chain INPUT jumps to first. Port 22 on the host
#     answered from the guest.
#   * `ESTABLISHED,RELATED` must be accepted BEFORE that DROP, or CAPE's own
#     host-initiated connections to the agent lose their replies and the whole
#     sandbox goes dark.
#
# The rules are re-applied on a timer because CAPE's rooter runs
# `iptables-save | filter | iptables-restore` over the entire ruleset when it
# stops, and a reboot loses them too.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
GUEST_IP=${GUEST_IP:-192.168.122.105}
AGENT="http://${GUEST_IP}:8000"

echo "== installing =="
install -m 700 "$HERE/guest-isolation.sh" /usr/local/sbin/cyclo-guest-isolation.sh
install -m 644 "$HERE/systemd/cyclo-guest-isolation.service" /etc/systemd/system/
install -m 644 "$HERE/systemd/cyclo-guest-isolation.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cyclo-guest-isolation.service
systemctl enable --now cyclo-guest-isolation.timer
/usr/local/sbin/cyclo-guest-isolation.sh
echo "   timer: $(systemctl is-active cyclo-guest-isolation.timer)"

echo
echo "== verifying FROM INSIDE THE GUEST (the only test that counts) =="
ex() {
  curl -s --max-time 40 -X POST --data-urlencode "command=$1" "$AGENT/execute" 2>/dev/null \
    | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: print(""); raise SystemExit
print((((d.get("stdout") or "")+(d.get("stderr") or "")).strip() or "")[:200].replace(chr(10)," "))'
}
curl -s --max-time 8 "$AGENT/" >/dev/null || { echo "agent unreachable - start the guest first" >&2; exit 1; }

fail=0
for port in 22 80 8000 5432 27017 6379; do
  v=$(ex "powershell -NoProfile -Command Test-NetConnection -ComputerName 192.168.122.1 -Port $port -InformationLevel Quiet" | grep -oE 'True|False' | head -1)
  printf "   host:%-6s reachable=%s\n" "$port" "${v:-?}"
  [[ "$v" == "True" ]] && { echo "   ^^ MUST be False"; fail=1; }
done
rs=$(ex "powershell -NoProfile -Command Test-NetConnection -ComputerName 192.168.122.1 -Port 2042 -InformationLevel Quiet" | grep -oE 'True|False' | head -1)
printf "   host:2042   reachable=%s  (result server, MUST be True)\n" "${rs:-?}"
[[ "$rs" != "True" ]] && fail=1

for probe in "http://1.1.1.1" "https://www.microsoft.com"; do
  code=$(ex "curl.exe -s -m 8 -o NUL -w %{http_code} $probe")
  printf "   egress %-26s -> %s\n" "$probe" "${code:-?}"
  [[ "$code" =~ ^[1-5][0-9][0-9]$ ]] && { echo "   ^^ MUST be 000"; fail=1; }
done

echo
if (( fail )); then
  echo "CONTAINMENT FAILED - do not detonate anything on this host." >&2
  exit 1
fi
echo "Containment verified. Safe to detonate."
