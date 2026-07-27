#!/bin/bash
# Build the detonation guest.
#
# BIOS on purpose: libvirt 8.0.0 refuses internal snapshots on pflash firmware,
# and CAPE reverts with revertToSnapshot(flags=0) on a RUNNING snapshot then
# immediately waits for RUNNING - verified empirically on this host.
#
# NEVER use `virsh undefine --remove-all-storage` here. It deletes every volume
# attached to the domain, and this domain has two CD-ROMs attached: it silently
# ate a freshly built 5 GB Windows ISO. Remove only the disk we own, by name.
set -euo pipefail
ISO="${1:?usage: 04-create-guest.sh /path/to/windows.iso}"
PROV=/var/lib/libvirt/iso/cape-provision.iso
DISK=/var/lib/libvirt/images/cape1.qcow2

for f in "$ISO" "$PROV"; do
  [ -f "$f" ] || { echo "missing: $f" >&2; exit 1; }
done

virsh destroy cape1 2>/dev/null || true
virsh undefine cape1 2>/dev/null || true
rm -f "$DISK"
qemu-img create -f qcow2 "$DISK" 80G >/dev/null

virt-install \
  --name cape1 --memory 4096 --vcpus 2 --cpu host-passthrough,-hypervisor \
  --machine pc --os-variant win10 \
  --disk path="$DISK",format=qcow2,bus=sata \
  --disk path="$ISO",device=cdrom,bus=sata \
  --disk path="$PROV",device=cdrom,bus=sata \
  --network network=default,model=e1000e,mac=52:54:00:9a:11:05 \
  --graphics vnc,listen=127.0.0.1 \
  --video qxl --sound none --boot cdrom,hd --noautoconsole
echo "cape1 defined; VNC on $(virsh vncdisplay cape1)"
