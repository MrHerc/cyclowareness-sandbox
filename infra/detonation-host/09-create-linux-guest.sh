#!/usr/bin/env bash
# Build the Linux detonation guest, so ELF samples can be run rather than only read.
#
# Sibling of 04-create-guest.sh (Windows). Everything here that looks like a
# quirk is a constraint this host actually imposes:
#
# BIOS, NOT UEFI. libvirt refuses internal snapshots on pflash firmware, and
# CAPE reverts with `revertToSnapshot(flags=0)` and then immediately waits for
# the domain to be RUNNING (lib/cuckoo/common/abstracts.py). A running internal
# snapshot is therefore the only working shape, and that is a firmware
# constraint rather than a Windows one -- it binds a Linux guest identically.
#
# EVERY PACKAGE IS BAKED IN HERE, ON THE HOST. The guest has no egress:
# containment.nft drops `virbr0 -> anything not virbr0` in the forward hook, on
# purpose, because that is what stops a detonating sample reaching the analysis
# API and the evidence database. So an `apt-get` in cloud-init `runcmd` hangs
# and the guest comes up WITHOUT strace -- which means an empty behaviour log
# and nothing erroring. That is this project's oldest failure mode. Do not move
# package installation into the guest.
#
# strace MUST BE IN /usr/bin. `analyzer/linux/lib/core/packages.py` launches
#   sudo strace -o /dev/stderr -s 800 -ttf <target>
# with `env={"XAUTHORITY": ..., "DISPLAY": ":0"}`, which REPLACES the
# environment. There is no PATH, so the shell falls back to the confstr default
# of /bin:/usr/bin and a strace in /usr/local/bin is simply not found.
#
# THE AGENT RUNS AS ROOT. That same launcher calls `sudo strace`, and
# `analyzer.py` runs `date -s <clock>` with check=True -- a failure there aborts
# the analysis rather than degrading it.
#
# pyinotify AND PIL ARE NOT OPTIONAL DECORATION. `auxiliary.conf` enables
# filecollector and screenshots_linux; both import-guard and both degrade to a
# log.warning. filecollector is how DROPPED FILES reach the report, so losing it
# thins the evidence silently.
#
# NEVER `virsh undefine --remove-all-storage` on this domain: it carries a
# CD-ROM, and that flag once deleted a freshly built 5 GB Windows ISO.
#
# This script defines and snapshots a guest. It does NOT tell CAPE about it --
# see 10-enable-linux-analysis.sh, which is the reversible half.
set -euo pipefail

NAME=${NAME:-cape4}
MAC=${MAC:-52:54:00:9a:11:08}
IP=${IP:-192.168.122.108}
HOST_IP=${HOST_IP:-192.168.122.1}
IMAGES=${IMAGES:-/var/lib/libvirt/images}
ISODIR=${ISODIR:-/var/lib/libvirt/iso}
CACHE=${CACHE:-/var/lib/libvirt/aux/payload}
CAPE_DIR=${CAPE_DIR:-/opt/CAPEv2}
SNAPSHOT=${SNAPSHOT:-clean}
BASE_URL=${BASE_URL:-https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img}

DISK="$IMAGES/$NAME.qcow2"
SEED="$ISODIR/$NAME-seed.iso"
BASE_IMG="$CACHE/jammy-server-cloudimg-amd64.img"

for tool in qemu-img virt-install virt-customize genisoimage virsh curl; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
[ -f "$CAPE_DIR/agent/agent.py" ] || { echo "no CAPE agent at $CAPE_DIR" >&2; exit 1; }

echo "=== 1. base image ==="
mkdir -p "$CACHE" "$ISODIR"
[ -s "$BASE_IMG" ] || curl -4 -sSL --max-time 2400 -o "$BASE_IMG" "$BASE_URL"
ls -la "$BASE_IMG"

echo "=== 2. remove any previous $NAME ==="
virsh destroy "$NAME" 2>/dev/null || true
virsh snapshot-delete "$NAME" "$SNAPSHOT" --metadata 2>/dev/null || true
virsh undefine "$NAME" --snapshots-metadata 2>/dev/null || true
rm -f "$DISK"

echo "=== 3. disk ==="
# convert, never cp: a clone that still carries a snapshot is what
# 08-clone-guests.sh refuses, because a qcow2 internal snapshot holds guest
# memory and therefore the NIC identity.
qemu-img convert -O qcow2 "$BASE_IMG" "$DISK"
if qemu-img snapshot -l "$DISK" 2>/dev/null | grep -q .; then
    echo "base image carries a snapshot — refusing" >&2
    exit 1
fi

# GROW THE CONTAINER, THEN THE PARTITION IN PLACE. Two wrong turns first, both
# worth recording because each looked correct:
#
# 1. `qemu-img resize` ALONE grows the container and nothing else. The image
#    reported 20G while `virt-df` showed the root filesystem still 2.0G with
#    66 MB free, and the package bake died with
#        E: Write error - write (28: No space left on device)
#    on a host with 267 GB free — which reads like a host problem and is not.
#
# 2. `virt-resize --expand /dev/sda1` grows the filesystem and rewrites the
#    whole partition layout onto a new disk. The guest then booted to
#        error: unknown filesystem.  Entering rescue mode...  grub rescue>
#    caught with `virsh screenshot`, which works headlessly.
#
# `growpart` is right because of how this image is laid out. Measured with
# `guestfish part-list`: sda14 (BIOS boot, 4 MB) and sda15 (EFI, 106 MB) sit at
# the FRONT of the disk and the root partition sda1 is LAST. So extending sda1
# moves nothing and touches no boot structure — which is exactly why cloud-init
# does it this way on first boot. We do it here rather than at boot only because
# the packages have to be baked in before the guest ever runs.
qemu-img resize "$DISK" 20G
virt-customize -a "$DISK" \
    --run-command 'growpart /dev/sda 1' \
    --run-command 'resize2fs /dev/sda1' \
    --run-command 'df -h / | tail -1'
virt-df -h -a "$DISK" | head -3

echo "=== 4. bake the guest (host-side, with the host's network) ==="
# THE HOSTNAME MUST RESOLVE WITHOUT DNS, and systemd-resolved stays ON.
#
# Both learned from the first guest, which booted, answered `/`, and then failed
# every `/execute` with an empty response. Its own log said why:
#
#     File "/opt/cape/agent.py", line 660, in do_execute
#         local_ip = socket.gethostbyname(socket.gethostname())
#     socket.gaierror: [Errno -3] Temporary failure in name resolution
#
# The agent resolves its own hostname on every execute. With systemd-resolved
# disabled and no /etc/hosts entry there was nothing to resolve it with, so the
# handler raised before running anything and the connection closed with no body
# — an agent that looks alive and cannot be driven.
#
# Hence the 127.0.1.1 entry, which is the Debian convention and needs no network
# at all. And the resolver is deliberately NOT disabled any more: a detonating
# sample's DNS queries are evidence, they go to INetSim on the guest bridge, and
# they land in the pcap. Turning the resolver off would have thrown that away.
cp "$CAPE_DIR/agent/agent.py" "$CACHE/agent.py"

cat > "$CACHE/cape-agent.service" <<'UNIT'
[Unit]
Description=CAPE guest agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/cape/agent.py 0.0.0.0 8000
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
UNIT

virt-customize -a "$DISK" \
    --install strace,python3,python3-pip,python3-pil,python3-pyinotify,tcpdump,file,sudo \
    --mkdir /opt/cape \
    --copy-in "$CACHE/agent.py:/opt/cape" \
    --copy-in "$CACHE/cape-agent.service:/etc/systemd/system" \
    --run-command 'systemctl enable cape-agent.service' \
    --hostname "$NAME" \
    --run-command "printf '127.0.1.1 %s\n' '$NAME' >> /etc/hosts" \
    --run-command 'systemctl disable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer || true' \
    --run-command 'systemctl disable --now snapd snapd.socket || true' \
    --root-password password:sandbox \
    --run-command 'command -v strace >/dev/null || exit 1' \
    --run-command 'test -x /usr/bin/strace || exit 1' \
    --run-command "grep -q '127.0.1.1 $NAME' /etc/hosts || exit 1"
# Checked against the FILE, not with `getent hosts "$(hostname)"`. --run-command
# runs chrooted into the guest filesystem but `hostname` still answers with the
# libguestfs appliance's own name, so that form failed the build on a guest
# whose /etc/hosts was perfectly correct.

echo "=== 5. cloud-init seed (identity and address only; no package work) ==="
mkdir -p /tmp/$NAME-ci
cat > /tmp/$NAME-ci/meta-data <<EOF
instance-id: $NAME
local-hostname: $NAME
EOF
cat > /tmp/$NAME-ci/user-data <<EOF
#cloud-config
disable_root: false
ssh_pwauth: true
users:
  - name: root
    lock_passwd: false
password: sandbox
chpasswd: { expire: false }
# The address is pinned in libvirt's DHCP by MAC as well (see step 6). The
# Windows guest taught this: the unattend identifier never bound and the guest
# came up on the wrong address, so the reservation is what actually holds.
manage_etc_hosts: false
EOF
genisoimage -quiet -output "$SEED" -volid cidata -joliet -rock \
    /tmp/$NAME-ci/user-data /tmp/$NAME-ci/meta-data
rm -rf /tmp/$NAME-ci

echo "=== 6. pin the address by MAC, before first boot ==="
virsh net-update default delete ip-dhcp-host \
    "<host mac='$MAC'/>" --live --config 2>/dev/null || true
virsh net-update default add ip-dhcp-host \
    "<host mac='$MAC' name='$NAME' ip='$IP'/>" --live --config

echo "=== 7. define and start ==="
virt-install \
    --name "$NAME" \
    --machine pc \
    --memory 2048 --vcpus 2 \
    --cpu host-passthrough \
    --disk "path=$DISK,format=qcow2,bus=virtio" \
    --disk "path=$SEED,device=cdrom" \
    --network "network=default,mac=$MAC,model=virtio" \
    --os-variant ubuntu22.04 \
    --graphics vnc,listen=127.0.0.1 \
    --import --noautoconsole

echo "=== 8. wait for the agent ==="
for _ in $(seq 1 60); do
    if curl -s --max-time 3 "http://$IP:8000/" | grep -q "CAPE Agent"; then
        echo "agent answering on $IP:8000"
        curl -s --max-time 3 "http://$IP:8000/"
        echo
        break
    fi
    sleep 5
done
curl -s --max-time 3 "http://$IP:8000/" | grep -q "CAPE Agent" || {
    echo "agent never answered — leaving the domain running for inspection" >&2
    exit 1
}

echo "=== 9. prove the guest is contained BEFORE snapshotting it ==="
# A snapshot of an uncontained guest is a contained-looking guest for ever.
bash "$(dirname "$0")/verify-containment.sh" 2>/dev/null || true

echo "=== 10. running internal snapshot ==="
virsh snapshot-create-as "$NAME" "$SNAPSHOT" "clean baseline" --atomic
virsh snapshot-list "$NAME"
virsh domstate "$NAME"

echo
echo "Guest built. CAPE has NOT been told about it — run"
echo "  10-enable-linux-analysis.sh"
echo "to add the machine and flip the three config switches, reversibly."
