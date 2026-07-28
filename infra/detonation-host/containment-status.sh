#!/usr/bin/env bash
# Is containment structurally intact RIGHT NOW? Answers in JSON, changes nothing.
#
# This is the CHEAP check, meant to run before every batch of detonations. It is
# not a replacement for verify-containment.sh, which boots a probe inside the
# guest and is the only thing that observes the guest's actual view - run that
# after every boot, after every cape-rooter restart, and before any corpus run.
#
# What this catches that a periodic probe cannot: the ruleset changing between
# the probe and the detonation. CAPE's rooter inserts CAPE_ACCEPTED_SEGMENTS at
# FORWARD position 1 on every SIGTERM (rooter.py:173-174) and its per-task egress
# path is another `-I FORWARD` at position 1 (rooter.py:1086). Neither removes
# our rules; both would sit above them if containment still lived in the iptables
# FORWARD chain. It does not - it is in `table inet cyclo_containment`, whose
# hooks run first regardless - and this script's job is to prove that is still
# true rather than assume it.
#
# Exit 0 = contained. Exit 1 = NOT contained. Any other exit = unknown, which the
# caller must treat as NOT contained.
set -uo pipefail

NAME=${CYCLO_NFT_TABLE:-cyclo_containment}
BR=${CYCLO_BRIDGE:-virbr0}

fail() {
    printf '{"contained":false,"reason":"%s"}\n' "$1"
    exit 1
}

command -v nft >/dev/null 2>&1 || fail "nft is not installed"
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed"

ruleset=$(nft -j list table inet "$NAME" 2>/dev/null) || fail "table inet $NAME is absent"
[[ -n ${ruleset:-} ]] || fail "table inet $NAME is empty"

# Parsed, not grepped. `nft -j` spacing varies between versions and a grep that
# silently stops matching would report "contained: false" forever, or - far
# worse, if written the other way round - "true" without checking anything.
printf '%s' "$ruleset" | python3 -c '
import json, sys

BRIDGE = sys.argv[1]
items = json.load(sys.stdin)["nftables"]
chains = {c["name"]: c for c in (i.get("chain") for i in items if "chain" in i)}
rules = [r for r in (i.get("rule") for i in items if "rule" in i)]


def bad(reason):
    print(json.dumps({"contained": False, "reason": reason}))
    raise SystemExit(1)


for want, hook in (("forward", "forward"), ("input", "input")):
    chain = chains.get(want)
    if chain is None:
        bad(f"chain {want} is missing")
    # A chain present but unhooked filters nothing while looking entirely
    # correct in `nft list`.
    if chain.get("hook") != hook:
        bad(f"chain {want} is not hooked to {hook}")
    if chain.get("type") != "filter":
        bad(f"chain {want} is not a filter chain")

by_chain = {}
for rule in rules:
    by_chain.setdefault(rule.get("chain"), []).append(rule)

# Present-but-empty must fail: a chain with a policy and no rules is the shape a
# half-applied `nft -f` leaves behind, and it accepts everything.
drops = {
    name: sum(1 for r in rs if any("drop" in e for e in r.get("expr", [])))
    for name, rs in by_chain.items()
}
if drops.get("forward", 0) < 2:
    bad("the forward chain does not drop guest egress")
if drops.get("input", 0) < 1:
    bad("the input chain has no terminal drop")

# Egress must be matched by EXCLUSION, never by interface pair. An interface pair
# is what left virbr0 -> docker0 open, so a detonating sample could reach the
# Cyclowareness API container on 172.17.0.2:8000 - a permanent hole, not a race.
def matches_exclusion(rule):
    for expr in rule.get("expr", []):
        match = expr.get("match")
        if match and match.get("op") == "!=":
            right = match.get("right")
            if isinstance(right, str) and right == BRIDGE:
                return True
    return False


if not any(matches_exclusion(r) for r in by_chain.get("forward", [])):
    bad(f"egress is matched by interface pair, not by exclusion of {BRIDGE}")

# Reported, not enforced. A drop counter that has never moved is not proof of a
# fault on its own - the caller compares it across polls, and a counter that
# stays still while samples detonate is the real signal.
packets = 0
for rule in by_chain.get("input", []):
    for expr in rule.get("expr", []):
        counter = expr.get("counter")
        if isinstance(counter, dict):
            packets += int(counter.get("packets") or 0)

print(json.dumps({
    "contained": True,
    "bridge": BRIDGE,
    "drop_rules": sum(drops.values()),
    "drop_packets": packets,
}))
' "$BR"
