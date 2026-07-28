#!/usr/bin/env bash
# Is this host safe to detonate on, RIGHT NOW? Answers only that, changes nothing.
#
# Run it before any real-malware run, and after anything that touches the
# firewall - CAPE's rooter rewrites the whole ruleset when it stops.
#
# Deliberately separate from 06-isolate-guest.sh. That script applies the rules
# and then verifies, so it verified a state it had just created: with a hole
# punched in INPUT it still printed "Safe to detonate", because it closed the
# hole before looking. A gate that cannot fail manufactures confidence.
#
# Every probe runs INSIDE the guest, from one uploaded script in one round trip.
# Reading the host's iptables output proves nothing about what a sample can
# reach - rule order, ufw's chain jumps and conntrack decide the real answer, and
# only the guest can observe it. Asking the agent question by question took over
# six minutes because each blocked port waited out a full TCP timeout; the probe
# caps every connect explicitly and finishes in seconds.
#
# With a sinkhole running the question is sharper than "can it reach the
# network". A simulated internet is SUPPOSED to answer, so this checks that what
# answers is the simulator: names must resolve to the sinkhole, HTTP must be
# served by it, and a connection to a raw internet address - which no amount of
# DNS trickery can redirect - must still fail.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
GUEST_IP=${GUEST_IP:-192.168.122.105}
HOST_IP=${HOST_IP:-192.168.122.1}
AGENT="http://${GUEST_IP}:8000"
EXPECT_SINKHOLE=${EXPECT_SINKHOLE:-1}
PROBE="$HERE/guest/containment-probe.ps1"

fail=0
note() { printf '   %-40s %s\n' "$1" "$2"; }
bad() { echo "   ^^ $1"; fail=1; }

echo "== the guest must be running, or this proves nothing =="
if ! curl -s --max-time 8 "$AGENT/" >/dev/null 2>&1; then
  echo "   agent at $AGENT is not answering." >&2
  echo "   Revert the golden snapshot and try again - an unreachable guest is" >&2
  echo "   NOT a passing result." >&2
  exit 2
fi
note "agent" "answering"
[[ -f $PROBE ]] || { echo "   missing probe: $PROBE" >&2; exit 2; }

curl -s --max-time 30 -F 'filepath=C:\containment-probe.ps1' -F "file=@$PROBE" \
  "$AGENT/store" >/dev/null || { echo "   could not upload the probe" >&2; exit 2; }

# Forward slashes: the agent splits commands with shlex, which eats backslashes.
OUT=$(curl -s --max-time 180 -X POST \
  --data-urlencode 'command=powershell -NoProfile -ExecutionPolicy Bypass -File C:/containment-probe.ps1' \
  "$AGENT/execute" \
  | python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: raise SystemExit
sys.stdout.write((d.get("stdout") or "") + (d.get("stderr") or ""))' | tr -d '\r')
# PowerShell emits CRLF. Without stripping it every value compared as "True",
# nothing matched, and the gate failed on a host that was actually fine - the
# worst kind of false alarm, because the next person relaxes the check.

[[ -n ${OUT:-} ]] || { echo "   the probe produced no output - refusing to certify" >&2; exit 1; }

# --- the probe must have FINISHED, and every answer must be present ----------
#
# This is the gate on the gate. Every verdict below is a `while read` loop that
# only inspects lines whose first field matches, so a probe that stopped early
# skipped the loop body entirely, left `fail` at 0, and printed "Safe to
# detonate" having tested nothing. Reproduced: synthetic output containing the
# single line `RESULTSERVER True` and nothing else certified the host.
#
# So: count the answers before believing any of them. A truncated probe is a
# failed probe, not a passing one.
completed=$(awk '/^PROBE-COMPLETE/{print $2}' <<< "$OUT")
if [[ -z ${completed:-} ]]; then
  echo "   the probe did not run to completion (no PROBE-COMPLETE line)." >&2
  echo "   Refusing to certify a host on partial evidence." >&2
  exit 1
fi
answers=$(grep -cE '^(PORT|RESULTSERVER|DOCKER|EGRESS|EGRESSUDP|DNS|HTTP) ' <<< "$OUT")
if (( answers != completed )); then
  echo "   the probe reported $completed answers but $answers arrived." >&2
  echo "   Output was truncated; refusing to certify." >&2
  exit 1
fi
note "probe answers" "$answers/$completed complete"

echo
echo "== guest -> host: the result server and the sinkhole, nothing else =="
while read -r kind arg value; do
  [[ $kind == PORT ]] || continue
  case "$value" in
    True)  note "host:$arg" "REACHABLE"; bad "must be unreachable from the guest" ;;
    False) note "host:$arg" "blocked" ;;
    *)     note "host:$arg" "UNKNOWN"; bad "could not determine reachability" ;;
  esac
done <<< "$OUT"

rs=$(awk '/^RESULTSERVER/{print $2}' <<< "$OUT")
if [[ $rs == True ]]; then
  note "host:2042 (result server)" "reachable"
else
  note "host:2042 (result server)" "${rs:-UNKNOWN}"
  bad "the result server MUST be reachable or every analysis returns empty"
fi

echo
echo "== guest -> the container network: nothing =="
# The old host rules named an interface pair, so virbr0 -> docker0 matched
# nothing and the Cyclowareness API container was reachable from a detonating
# sample. Neither the rules nor this probe covered it.
while read -r kind arg value; do
  [[ $kind == DOCKER ]] || continue
  case "$value" in
    False) note "docker $arg" "blocked" ;;
    True)  note "docker $arg" "REACHABLE"; bad "the guest reached the container network" ;;
    *)     note "docker $arg" "UNKNOWN"; bad "could not determine reachability" ;;
  esac
done <<< "$OUT"

echo
echo "== guest -> internet: nothing, by raw address =="
while read -r kind arg value; do
  [[ $kind == EGRESS ]] || continue
  case "$value" in
    False) note "egress $arg" "blocked" ;;
    True)  note "egress $arg" "CONNECTED"; bad "THE GUEST REACHED THE INTERNET" ;;
    *)     note "egress $arg" "UNKNOWN"; bad "could not determine egress" ;;
  esac
done <<< "$OUT"

# UDP, which the old probe never tested at all. TCP/80 being blocked says
# nothing about the channel malware actually uses to tunnel out.
udp=$(awk '/^EGRESSUDP/{print $3}' <<< "$OUT")
case "$udp" in
  False) note "egress udp 8.8.8.8:53" "blocked" ;;
  True)  note "egress udp 8.8.8.8:53" "ANSWERED"; bad "UDP egress reaches the real internet" ;;
  *)     note "egress udp 8.8.8.8:53" "UNKNOWN"; bad "could not determine UDP egress" ;;
esac

echo
dns=$(awk '/^DNS/{print $2}' <<< "$OUT")
http=$(grep '^HTTP ' <<< "$OUT" | head -1)
if [[ $EXPECT_SINKHOLE == 1 ]]; then
  echo "== the simulated internet answers, and it is the simulator =="
  if [[ $dns == "$HOST_IP" ]]; then
    note "dns example.com" "-> $dns (sinkhole)"
  else
    note "dns example.com" "-> ${dns:-none}"
    bad "names must resolve to the sinkhole, not to a real address or nothing"
  fi
  if grep -qiE 'inetsim|not really|default html' <<< "$http"; then
    note "http example.com" "served by the sinkhole"
  else
    note "http example.com" "${http:0:70}"
    bad "the simulator did not serve it"
  fi
else
  echo "== no sinkhole expected; names must not resolve =="
  if [[ -z $dns || $dns == none ]]; then
    note "dns example.com" "no answer"
  else
    note "dns example.com" "-> $dns"
    bad "outbound DNS resolves - a sample can exfiltrate over it"
  fi
fi

echo
if (( fail )); then
  echo "CONTAINMENT FAILED - do not detonate anything on this host." >&2
  exit 1
fi
echo "Containment verified. Safe to detonate."
