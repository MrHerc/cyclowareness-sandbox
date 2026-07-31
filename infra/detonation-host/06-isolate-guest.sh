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
# Containment lives in `containment.nft` - a separate nftables table with its own
# hooks, loaded once and never re-asserted. It replaced a 60-second timer over
# hand-written iptables rules, which had a 65.3-second worst-case window, opened
# a 150-230ms hole on every tick by deleting each DROP before re-inserting it,
# and left virbr0 -> docker0 open permanently because its rules named an
# interface pair. See the header of containment.nft for the measurements.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
GUEST_IP=${GUEST_IP:-192.168.122.105}
AGENT="http://${GUEST_IP}:8000"

echo "== installing containment =="
install -d -m 755 /etc/nftables.d
install -m 644 "$HERE/containment.nft" /etc/nftables.d/cyclo-containment.nft

# Syntax-check BEFORE loading. `nft -f` applies a file atomically, but a file
# that does not parse leaves whatever was there - and on a first install that is
# nothing at all, i.e. no containment, reported as a shell error nobody reads.
nft -c -f /etc/nftables.d/cyclo-containment.nft
nft -f /etc/nftables.d/cyclo-containment.nft

# Replay it at boot, via our OWN unit, ordered before libvirtd - so containment
# exists before anything can bring a guest up. That closes the boot window a
# timer could never close.
#
# NOT by enabling nftables.service and NOT by adding an include to
# /etc/nftables.conf. Ubuntu's stock /etc/nftables.conf opens with
# `flush ruleset`, so enabling that unit would wipe the whole ruleset at boot -
# ufw, Docker and libvirt with it - and leave three empty chains whose policy is
# accept. It ships disabled precisely for that reason, and turning it on to
# persist a containment rule would open the box far wider than the rule closes.
install -m 644 "$HERE/systemd/cyclo-containment.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable cyclo-containment.service >/dev/null
echo "   boot unit: $(systemctl is-enabled cyclo-containment.service)"

# The iptables layer STAYS, and that was measured rather than assumed. Retiring
# it and re-running the gate with the nft table alone: egress stayed blocked, and
# the result server on 192.168.122.1:2042 went unreachable along with the
# sinkhole's HTTP - every analysis would have come back empty. An `accept` in an
# nft base chain only lets a packet reach the iptables chains, where INPUT's
# policy is DROP. The nft table can forbid; it cannot permit.
#
# So the two layers do different jobs, and neither is spare: nft holds the drops
# where nothing can flush or reorder them, iptables holds the accepts the sandbox
# needs in order to work at all.
if ! systemctl is-enabled --quiet cyclo-guest-isolation.timer 2>/dev/null; then
  cat <<'NOTE'
   WARNING: cyclo-guest-isolation.timer is disabled.
   The nft table still blocks egress, but nothing is granting the guest the
   result server or the sinkhole, so every analysis will come back empty:
       systemctl enable --now cyclo-guest-isolation.timer
NOTE
fi

echo "   nft table: $(nft list table inet cyclo_containment >/dev/null 2>&1 && echo loaded || echo MISSING)"
echo "   survives an iptables restore: $(
  iptables-save > /tmp/.cyclo-rt.$$ && iptables-restore < /tmp/.cyclo-rt.$$ \
    && rm -f /tmp/.cyclo-rt.$$ \
    && nft list table inet cyclo_containment >/dev/null 2>&1 && echo yes || echo NO)"

echo
echo "== verifying =="
# Delegated to verify-containment.sh, which changes nothing and can be run on
# its own. Keeping the checks in here made them useless: this script re-applies
# the rules first, so it was verifying a state it had just created. Proved by
# experiment - with a hole punched in INPUT, the combined script still printed
# "Safe to detonate" because it closed the hole before looking, while the
# verifier run alone correctly failed. Run verify-containment.sh before every
# real-malware run, not just after installing.
exec "$HERE/verify-containment.sh"
