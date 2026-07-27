#!/bin/bash
# Keep the detonation guest off the internet and off the host, idempotently.
#
# Re-assertable, not one-shot: CAPE's rooter runs `iptables-save | filter |
# iptables-restore` across the WHOLE ruleset on stop and sets ip_forward=1 on
# start, so hand-applied rules do not survive a rooter cycle; a reboot loses them
# too. A systemd timer re-applies this every minute, bounding the window.
#
# Scope is FORWARD plus INPUT-on-virbr0 only. SSH arrives on INPUT via enp41s0
# and is matched by nothing here - which is what makes this safe to run
# unattended on a box whose only door is port 22.
set -u
WAN=enp41s0
BR=virbr0
RS_PORT=2042

# --- routed traffic: the guest goes nowhere, in either direction -------------
iptables -D FORWARD -i $BR -o $WAN -j DROP 2>/dev/null
iptables -D FORWARD -i $WAN -o $BR -j DROP 2>/dev/null
iptables -I FORWARD 1 -i $BR -o $WAN -j DROP
iptables -I FORWARD 2 -i $WAN -o $BR -j DROP

# --- guest -> host ------------------------------------------------------------
# Order matters twice over:
#
# 1. The DROP is INSERTED near the top, not appended. ufw's "allow 22/tcp from
#    anywhere" lives in a chain INPUT jumps to, so an appended DROP is only
#    reached after ufw has already accepted - measured from inside the guest,
#    port 22 on the host answered True. A sample that can reach the host's SSH
#    is a sandbox escape waiting to happen.
#
# 2. ESTABLISHED,RELATED must be accepted BEFORE that DROP. CAPE drives the
#    guest agent over connections the HOST opens; without this the replies are
#    dropped on the way back and the whole sandbox goes dark. It does not let the
#    guest open anything - only answers to what we asked for.
# 3. DNS is deliberately NOT accepted. libvirt's dnsmasq on this bridge forwards
#    upstream, so allowing udp/53 handed a detonating sample a working recursive
#    resolver - and DNS tunnelling is an exfiltration channel that blocking TCP
#    egress does nothing about. The host's ruleset looked correct; only probing
#    from inside the guest showed `Resolve-DnsName example.com` returning four
#    real answers.
#
#    Nothing analytically useful is lost. The query still leaves the guest and
#    still lands in the per-task pcap, so the domain a sample wanted is captured
#    as an IOC either way - only the answer is withheld. Serving controlled
#    answers is a sinkhole feature to build deliberately, not a default.
for spec in "-m conntrack --ctstate ESTABLISHED,RELATED" \
            "-p tcp --dport $RS_PORT" "-p udp --dport 53" "-p udp --dport 67"; do
  iptables -D INPUT -i $BR $spec -j ACCEPT 2>/dev/null
done
iptables -D INPUT -i $BR -j DROP 2>/dev/null

iptables -I INPUT 1 -i $BR -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -I INPUT 2 -i $BR -p tcp --dport $RS_PORT -j ACCEPT
iptables -I INPUT 3 -i $BR -p udp --dport 67 -j ACCEPT
iptables -I INPUT 4 -i $BR -j DROP
