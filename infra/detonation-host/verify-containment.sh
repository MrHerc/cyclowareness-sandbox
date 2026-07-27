#!/usr/bin/env bash
# Is this host safe to detonate on, RIGHT NOW? Answers only that, changes nothing.
#
# Run it before any real-malware run, and after anything that touches the
# firewall — CAPE's rooter rewrites the whole ruleset when it stops.
#
# It is deliberately separate from 06-isolate-guest.sh. That script applies the
# rules and then verifies, which means it verifies a state it just created: with
# a hole punched in INPUT, the combined script still printed "Safe to detonate",
# because it closed the hole before looking. A gate that cannot fail is worse
# than no gate, since it manufactures confidence. Verified by experiment - with
# this half run alone against the same hole, it correctly fails.
#
# Every probe runs INSIDE the guest. Reading the host's own iptables output
# proves nothing about what a sample can reach: rule order, ufw's chain jumps and
# conntrack all decide the real answer, and only the guest can observe it.
set -uo pipefail

GUEST_IP=${GUEST_IP:-192.168.122.105}
HOST_IP=${HOST_IP:-192.168.122.1}
RS_PORT=${RS_PORT:-2042}
AGENT="http://${GUEST_IP}:8000"
#: Ports that must be unreachable from the guest. 22 is the one that matters —
#: a sample reaching it is a sandbox escape — and the rest are services CAPE's
#: own DNAT of common ports can otherwise expose.
FORBIDDEN_PORTS=${FORBIDDEN_PORTS:-"22 80 443 8000 8090 5432 6379 27017"}
EGRESS_PROBES=${EGRESS_PROBES:-"http://1.1.1.1 https://www.microsoft.com http://93.184.216.34"}

fail=0
note() { printf '   %-42s %s\n' "$1" "$2"; }
bad() { echo "   ^^ $1"; fail=1; }

ex() {
  curl -s --max-time 45 -X POST --data-urlencode "command=$1" "$AGENT/execute" 2>/dev/null \
    | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: raise SystemExit
print((((d.get("stdout") or "")+(d.get("stderr") or "")).strip())[:300].replace(chr(10)," "))'
}

echo "== the guest must be running, or this proves nothing =="
if ! curl -s --max-time 8 "$AGENT/" >/dev/null 2>&1; then
  echo "   agent at $AGENT is not answering." >&2
  echo "   Revert the golden snapshot and try again — an unreachable guest is" >&2
  echo "   NOT a passing result." >&2
  exit 2
fi
note "agent" "answering"

echo
echo "== guest -> host: only the result server =="
for port in $FORBIDDEN_PORTS; do
  raw=$(ex "powershell -NoProfile -Command Test-NetConnection -ComputerName $HOST_IP -Port $port -InformationLevel Quiet")
  verdict=$(printf '%s' "$raw" | grep -oE 'True|False' | head -1)
  # An unparseable answer is a failure, not a pass. Treating "no reply" as
  # "not reachable" is how a dead probe silently certifies a broken host.
  if [[ -z $verdict ]]; then
    note "host:$port" "UNKNOWN (${raw:-no output})"
    bad "could not determine reachability — refusing to certify"
  elif [[ $verdict == True ]]; then
    note "host:$port" "REACHABLE"
    bad "must be unreachable from the guest"
  else
    note "host:$port" "blocked"
  fi
done

raw=$(ex "powershell -NoProfile -Command Test-NetConnection -ComputerName $HOST_IP -Port $RS_PORT -InformationLevel Quiet")
verdict=$(printf '%s' "$raw" | grep -oE 'True|False' | head -1)
if [[ $verdict == True ]]; then
  note "host:$RS_PORT (result server)" "reachable"
else
  note "host:$RS_PORT (result server)" "${verdict:-UNKNOWN}"
  bad "the result server MUST be reachable or every analysis returns empty"
fi

echo
echo "== guest -> internet: nothing =="
for probe in $EGRESS_PROBES; do
  code=$(ex "curl.exe -s -m 10 -o NUL -w %{http_code} $probe")
  code=$(printf '%s' "$code" | grep -oE '^[0-9]{3}' | head -1)
  if [[ -z $code ]]; then
    note "egress $probe" "UNKNOWN"
    bad "could not determine egress — refusing to certify"
  elif [[ $code == "000" ]]; then
    note "egress $probe" "blocked"
  else
    note "egress $probe" "HTTP $code"
    bad "the guest reached the internet"
  fi
done

echo
echo "== DNS must not resolve outward either =="
raw=$(ex "powershell -NoProfile -Command (Resolve-DnsName -Name example.com -ErrorAction SilentlyContinue).Count")
n=$(printf '%s' "$raw" | grep -oE '^[0-9]+' | head -1)
if [[ ${n:-0} -gt 0 ]]; then
  note "dns example.com" "$n answers"
  bad "outbound DNS resolves — a sample can exfiltrate over it"
else
  note "dns example.com" "no answers"
fi

echo
if (( fail )); then
  echo "CONTAINMENT FAILED — do not detonate anything on this host." >&2
  exit 1
fi
echo "Containment verified. Safe to detonate."
