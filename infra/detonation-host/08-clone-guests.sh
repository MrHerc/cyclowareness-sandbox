#!/usr/bin/env bash
# Clone the golden guest so more than one sample can be analysed at a time.
#
# One guest means one detonation at a time, and a detonation is 4-5 minutes:
# about 12 samples an hour, which is a demo, not a service. Each clone costs
# 4 GB of RAM and ~15 GB of disk.
#
# The disk is copied WITHOUT its snapshot on purpose. A qcow2 internal snapshot
# holds the guest's memory, and that memory contains the NIC's identity - copy it
# and the clone reverts to a machine that believes it is 192.168.122.105 with the
# original MAC, so two guests fight over one address and CAPE talks to whichever
# answers. Each clone therefore boots fresh, is given its own MAC and its own
# DHCP reservation, and gets its own snapshot taken after Windows has settled.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BASE=${BASE:-cape1}
COUNT=${COUNT:-2}
IMAGES=${IMAGES:-/var/lib/libvirt/images}
SNAPSHOT=${SNAPSHOT:-clean}

command -v qemu-img >/dev/null || { echo "qemu-img missing" >&2; exit 1; }
virsh dominfo "$BASE" >/dev/null 2>&1 || { echo "no such domain: $BASE" >&2; exit 1; }

echo "== preflight =="
[[ "$(virsh domstate "$BASE")" == "shut off" ]] || {
  echo "$BASE must be shut off so its disk is quiescent — run: virsh destroy $BASE" >&2
  exit 1
}
free_gb=$(df -BG --output=avail "$IMAGES" | tail -1 | tr -dc '0-9')
need=$(( COUNT * 20 ))
(( free_gb > need )) || { echo "need ~${need}G free, have ${free_gb}G" >&2; exit 1; }
ram_gb=$(free -g | awk '/^Mem:/{print $2}')
echo "   host: ${ram_gb} GB RAM, ${free_gb} GB free — cloning $COUNT guest(s) from $BASE"

for n in $(seq 2 $((COUNT + 1))); do
  NAME="cape$n"
  MAC=$(printf '52:54:00:9a:11:%02x' "$((0x05 + n - 1))")
  IP="192.168.122.$((105 + n - 1))"
  DISK="$IMAGES/$NAME.qcow2"

  echo
  echo "== $NAME  mac=$MAC  ip=$IP =="
  virsh destroy "$NAME" 2>/dev/null || true
  # --snapshots-metadata, or the second run fails. A plain `undefine` refuses
  # while snapshots exist, so the domain survived, and virt-install then said
  # "Disk cape2.qcow2 is already in use by other guests ['cape2']" - a confusing
  # message for what is really "you never removed the old one". Invisible on a
  # first clone, guaranteed on every re-clone after a golden-image change.
  virsh snapshot-delete "$NAME" "$SNAPSHOT" --metadata 2>/dev/null || true
  virsh undefine "$NAME" --snapshots-metadata --nvram 2>/dev/null \
    || virsh undefine "$NAME" --snapshots-metadata 2>/dev/null || true
  virsh dominfo "$NAME" >/dev/null 2>&1 && {
    echo "   $NAME still defined after undefine - refusing to continue" >&2; exit 1; }
  rm -f "$DISK"

  # -o compat=1.1 and no -s: a plain convert drops the internal snapshots.
  echo "   copying disk without snapshots"
  qemu-img convert -O qcow2 "$IMAGES/$BASE.qcow2" "$DISK"
  qemu-img snapshot -l "$DISK" 2>/dev/null | grep -q . \
    && { echo "   clone still carries a snapshot — refusing" >&2; exit 1; }

  echo "   pinning $IP to $MAC in libvirt's DHCP"
  virsh net-update default delete ip-dhcp-host \
    "<host mac='$MAC'/>" --live --config 2>/dev/null || true
  virsh net-update default add ip-dhcp-host \
    "<host mac='$MAC' name='$NAME' ip='$IP'/>" --live --config

  virt-install \
    --name "$NAME" --memory 4096 --vcpus 2 --cpu host-passthrough,-hypervisor \
    --machine pc --os-variant win10 --import \
    --disk path="$DISK",format=qcow2,bus=sata \
    --network network=default,model=e1000e,mac="$MAC" \
    --graphics vnc,listen=127.0.0.1 --video qxl --sound none \
    --boot hd --noautoconsole

  echo "   waiting for the agent on $IP (Windows re-detects the NIC)"
  for _ in $(seq 1 60); do
    curl -s --max-time 4 "http://$IP:8000/" >/dev/null 2>&1 && break
    sleep 5
  done
  curl -s --max-time 6 "http://$IP:8000/" | grep -q 'CAPE Agent' || {
    echo "   agent never answered on $IP" >&2; exit 1; }
  echo "   agent up"

  echo "   taking its own running snapshot"
  virsh snapshot-create-as "$NAME" "$SNAPSHOT" \
    --description "Cyclowareness golden image, clone of $BASE" >/dev/null
  [[ "$(virsh snapshot-info "$NAME" "$SNAPSHOT" | awk '/State/{print $2}')" == "running" ]] \
    || { echo "   snapshot is not in running state; CAPE will not accept it" >&2; exit 1; }
  virsh destroy "$NAME" >/dev/null
  echo "   $NAME ready"
done

echo
echo "== add them to CAPE =="
echo "   conf/kvm.conf must list every machine, e.g.  machines = cape1,cape2,cape3"
echo "   then: systemctl restart cape"
