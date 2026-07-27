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
echo "== verifying =="
# Delegated to verify-containment.sh, which changes nothing and can be run on
# its own. Keeping the checks in here made them useless: this script re-applies
# the rules first, so it was verifying a state it had just created. Proved by
# experiment - with a hole punched in INPUT, the combined script still printed
# "Safe to detonate" because it closed the hole before looking, while the
# verifier run alone correctly failed. Run verify-containment.sh before every
# real-malware run, not just after installing.
exec "$HERE/verify-containment.sh"
