#!/usr/bin/env bash
# Tell CAPE about the Linux guest. The reversible half of 09-create-linux-guest.sh.
#
# EVERY CHANGE IS A NEW FILE, NEVER AN EDIT. CAPE reads
# `conf/<name>.conf.d/*.conf` after the base file, sorted, later keys winning
# (lib/cuckoo/common/config.py, `_get_files_to_read`). So enabling Linux
# analysis is three drop-ins, and rolling it back is `rm` plus a restart —
# nothing in the shipped configuration is touched, and a mistake cannot corrupt
# the Windows guests' machine definitions.
#
# THREE SWITCHES, NOT ONE. Enabling `[linux]` in web.conf only opens the
# submission gate. Without a machine whose `platform = linux`, CAPE accepts the
# task and then fails it as unserviceable — which is the ARM64 pathology this
# deployment already lived through: one burned task every ten seconds, for ever.
# And without `[strace]` in processing.conf there is no `behavior` block at all,
# because `modules/processing/strace.py` is the only producer of one for a Linux
# task. All three, or none.
#
# `systemctl restart cape` interrupts analyses in flight. Check the queue first.
set -euo pipefail

CAPE_DIR=${CAPE_DIR:-/opt/CAPEv2}
NAME=${NAME:-cape4}
IP=${IP:-192.168.122.108}
HOST_IP=${HOST_IP:-192.168.122.1}
SNAPSHOT=${SNAPSHOT:-clean}
CONF="$CAPE_DIR/conf"

[ -d "$CONF" ] || { echo "no CAPE config at $CONF" >&2; exit 1; }
virsh dominfo "$NAME" >/dev/null 2>&1 || {
    echo "$NAME is not defined — run 09-create-linux-guest.sh first" >&2; exit 1; }
virsh snapshot-list "$NAME" --name 2>/dev/null | grep -qx "$SNAPSHOT" || {
    echo "$NAME has no '$SNAPSHOT' snapshot — CAPE reverts to it before every task" >&2
    exit 1; }

echo "=== what is in flight right now (a restart interrupts these) ==="
# `systemctl restart cape` kills running analyses, and a machine that dies
# mid-task gets marked CuckooDeadMachine and dropped from the pool until the
# next restart. So look before restarting.
RUNNING=$(sudo -u cape psql -tAc \
    "select count(*) from tasks where status in ('running','processing')" cape 2>/dev/null || echo "?")
echo "  tasks running/processing: $RUNNING"
if [ "$RUNNING" != "0" ] && [ "$RUNNING" != "?" ]; then
    echo "  -> $RUNNING analysis(es) in flight; re-run when the queue is idle." >&2
    [ "${FORCE:-0}" = "1" ] || exit 1
fi

echo "=== 1. the machine ==="
mkdir -p "$CONF/kvm.conf.d"
cat > "$CONF/kvm.conf.d/50-$NAME.conf" <<EOF
# Added by 10-enable-linux-analysis.sh. Delete this file and restart cape to
# undo; the shipped kvm.conf is untouched.
#
# \`machines\` is restated in full because a drop-in overrides a key rather than
# appending to it. If a Windows guest is ever added or removed, this line has to
# follow — that is the cost of the drop-in, and it is cheaper than editing the
# base file.
[kvm]
machines = cape1,cape2,cape3,$NAME

[$NAME]
label = $NAME
platform = linux
ip = $IP
snapshot = $SNAPSHOT
# Same result server as the Windows guests: it is the host's address on the
# guest bridge, and containment.nft admits exactly this port from virbr0.
resultserver_ip = $HOST_IP
resultserver_port = 2042
arch = x64
EOF

echo "=== 2. the submission gate ==="
mkdir -p "$CONF/web.conf.d"
cat > "$CONF/web.conf.d/50-linux.conf" <<'EOF'
# Added by 10-enable-linux-analysis.sh. Delete to undo.
#
# Upstream calls Linux analysis "for advanced users only, can be buggy, work in
# progress for fun". That is why the RESULT of it is deliberately not scored on
# our side: `scoring.DYNAMIC_UNCALIBRATED_FAMILIES` keeps every `capev2.*`
# signal from an ELF job out of the number and out of the capability model,
# because CAPE's Linux signature set has never been measured against benign
# Linux software. The trace is recorded, timelined and shown; it does not
# accuse.
[linux]
enabled = yes
EOF

echo "=== 3. the only producer of a behaviour block for a Linux task ==="
mkdir -p "$CONF/processing.conf.d"
cat > "$CONF/processing.conf.d/50-strace.conf" <<'EOF'
# Added by 10-enable-linux-analysis.sh. Delete to undo.
#
# `modules/processing/strace.py` (class StraceAnalysis, key = "behavior") reads
# logs/strace.log and is the ONLY thing that produces a behaviour block for a
# Linux analysis. Enabling [linux] without this yields a completed task with no
# behaviour at all — evidence getting thinner with nothing failing.
[strace]
enabled = yes
EOF

echo "=== 4. what CAPE resolves now (its own parser, before restarting) ==="
cd "$CAPE_DIR"
sudo -u cape /etc/poetry/bin/poetry run python -c "
from lib.cuckoo.common.config import Config
kvm = Config('kvm')
print('  machines:', kvm.get('kvm').get('machines'))
for m in str(kvm.get('kvm').get('machines')).split(','):
    m = m.strip()
    s = kvm.get(m)
    print('   %-8s platform=%-8s ip=%-16s snapshot=%s' % (
        m, s.get('platform'), s.get('ip'), s.get('snapshot')))
print('  web[linux].enabled       :', Config('web').get('linux').get('enabled'))
print('  processing[strace].enabled:', Config('processing').get('strace').get('enabled'))
print('  processing[virustotal]    :', Config('processing').get('virustotal').get('enabled'))
"

echo
echo "=== 5. restart ==="
systemctl restart cape
sleep 20
systemctl is-active cape

echo "=== 6. did it load every machine, INCLUDING the Windows ones ==="
journalctl -u cape --since "-2 min" --no-pager | grep -iE "loaded .* machine|machinery|error" | tail -8

echo
echo "To roll back:"
echo "  rm $CONF/kvm.conf.d/50-$NAME.conf \\"
echo "     $CONF/web.conf.d/50-linux.conf \\"
echo "     $CONF/processing.conf.d/50-strace.conf && systemctl restart cape"
