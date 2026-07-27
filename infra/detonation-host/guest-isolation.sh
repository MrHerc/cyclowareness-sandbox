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
HOST_IP=192.168.122.1
RS_PORT=2042
# Ports the simulated internet answers on. The guest may reach these AND ONLY
# these on the host, and only at $HOST_IP - never a wildcard, because CAPE's web
# UI sits on 0.0.0.0:8000 and rpcbind on 0.0.0.0:111.
SINKHOLE_TCP="53 21 25 80 110 443 465 990 995 6667"
SINKHOLE_UDP="53 69 123"

# Delete in a loop: `iptables -D` removes ONE matching rule per call, so a single
# delete left older duplicates behind and the chain grew on every timer tick.
drop_all() { while iptables -D "$@" 2>/dev/null; do :; done; }

# --- routed traffic: the guest goes nowhere, in either direction -------------
drop_all FORWARD -i $BR -o $WAN -j DROP
drop_all FORWARD -i $WAN -o $BR -j DROP
iptables -I FORWARD 1 -i $BR -o $WAN -j DROP
iptables -I FORWARD 2 -i $WAN -o $BR -j DROP

# --- guest -> host ------------------------------------------------------------
# Order matters three ways:
#
# 1. The DROP is INSERTED near the top, not appended. ufw's "allow 22/tcp from
#    anywhere" lives in a chain INPUT jumps to, so an appended DROP is only
#    reached after ufw has already accepted - measured from inside the guest,
#    port 22 on the host answered True. A sample that can reach the host's SSH
#    is a sandbox escape waiting to happen.
#
# 2. ESTABLISHED,RELATED must be accepted BEFORE that DROP. CAPE drives the
#    guest agent over connections the HOST opens; without this the replies are
#    dropped on the way back and the whole sandbox goes dark.
#
# 3. The sinkhole accepts are pinned to -d $HOST_IP. Without that, opening 80
#    and 443 for the simulator would also open anything else the host ever binds
#    to a wildcard on those ports.
drop_all INPUT -i $BR -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
drop_all INPUT -i $BR -p tcp --dport $RS_PORT -j ACCEPT
drop_all INPUT -i $BR -p udp --dport 67 -j ACCEPT
for p in $SINKHOLE_TCP; do drop_all INPUT -i $BR -d $HOST_IP -p tcp --dport "$p" -j ACCEPT; done
for p in $SINKHOLE_UDP; do drop_all INPUT -i $BR -d $HOST_IP -p udp --dport "$p" -j ACCEPT; done
drop_all INPUT -i $BR -j DROP

n=1
iptables -I INPUT $n -i $BR -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; n=$((n+1))
iptables -I INPUT $n -i $BR -p tcp --dport $RS_PORT -j ACCEPT; n=$((n+1))
iptables -I INPUT $n -i $BR -p udp --dport 67 -j ACCEPT; n=$((n+1))
for p in $SINKHOLE_TCP; do iptables -I INPUT $n -i $BR -d $HOST_IP -p tcp --dport "$p" -j ACCEPT; n=$((n+1)); done
for p in $SINKHOLE_UDP; do iptables -I INPUT $n -i $BR -d $HOST_IP -p udp --dport "$p" -j ACCEPT; n=$((n+1)); done
iptables -I INPUT $n -i $BR -j DROP
