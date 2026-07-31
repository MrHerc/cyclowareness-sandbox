#!/usr/bin/env bash
# Build a bootable Windows 10 22H2 install ISO from Microsoft's own media.
#
# Where the bits come from: the product catalog the Media Creation Tool itself
# reads. `https://go.microsoft.com/fwlink/?LinkId=841361` returns products.cab,
# which contains products.xml, which carries plain unauthenticated
# dl.delivery.mp.microsoft.com ESD URLs. No form, no key.
#
# Why not the ISO download page: its link API answers
# {"Errors":[{"Key":"ErrorSettings.SentinelReject"}]} to anything that is not a
# real browser - from a datacenter IP and from a home connection alike. That is
# bot protection, and going around it is not something to attempt.
#
# Why not Windows 11: it requires UEFI, and CAPE cannot revert a UEFI guest here.
# See 07-golden-snapshot.sh and the README.
set -euo pipefail

ISO_DIR=${ISO_DIR:-/var/lib/libvirt/iso}
TREE=${TREE:-/var/lib/libvirt/build/win10}
ESD="$ISO_DIR/win10-22h2-x64-en-us.esd"
OUT="$ISO_DIR/win10-22h2-x64.iso"
EDITION=${EDITION:-"Windows 10 Pro"}
LOG=${LOG:-/var/log/win10-iso-build.log}

exec > >(tee -a "$LOG") 2>&1
echo "=== $(date -Is) build start ==="

for tool in wimlib-imagex xorriso cabextract curl; do
  command -v "$tool" >/dev/null || {
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wimtools xorriso cabextract curl
    break
  }
done
mkdir -p "$ISO_DIR" "$(dirname "$TREE")"

if [[ ! -s $ESD ]]; then
  echo "[1/5] resolving the ESD from Microsoft's product catalog"
  work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
  curl -4 -sSL --max-time 60 -o "$work/products.cab" "https://go.microsoft.com/fwlink/?LinkId=841361"
  cabextract -q -d "$work" "$work/products.cab"
  url=$(grep -oE 'http://dl\.delivery\.mp\.microsoft\.com/[^<]*\.esd' "$work/products.xml" \
        | grep -i 'x64fre' | grep -i 'en-us' | grep -iE '19045|22h2' \
        | grep -i 'CLIENTCONSUMER' | sort -u | head -1)
  [[ -n $url ]] || { echo "no Windows 10 22H2 x64 en-US ESD in the catalog" >&2; exit 1; }
  echo "       $url"
  curl -4 -sSL -C - --max-time 3600 -o "$ESD" "$url"
fi
printf '       ESD %s (%s bytes)\n' "$(basename "$ESD")" "$(stat -c %s "$ESD")"

echo "[2/5] applying the Windows Setup Media tree (index 1)"
rm -rf "$TREE"; mkdir -p "$TREE"
wimlib-imagex apply "$ESD" 1 "$TREE" --no-acls

echo "[3/5] boot.wim <- WinPE + Setup"
rm -f "$TREE/sources/boot.wim"
wimlib-imagex export "$ESD" 2 "$TREE/sources/boot.wim" --compress=LZX
wimlib-imagex export "$ESD" 3 "$TREE/sources/boot.wim" --compress=LZX --boot

echo "[4/5] install.wim <- $EDITION"
# Looked up by name, not hardcoded: the index of an edition differs between ESDs.
INDEX=$(wimlib-imagex info "$ESD" \
        | awk -v want="$EDITION" '/^Index:/{i=$2} $0 ~ "^Name: +" want "$" {print i; exit}')
[[ -n $INDEX ]] || { echo "edition '$EDITION' not present in $ESD" >&2; exit 1; }
echo "       index $INDEX"
rm -f "$TREE/sources/install.wim"
wimlib-imagex export "$ESD" "$INDEX" "$TREE/sources/install.wim" --compress=LZX

echo "[5/5] mastering a BIOS-bootable ISO"
# -N and -d are load-bearing. Without them mkisofs writes the ISO 9660 name as
# `BOOTMGR.;1` (trailing period, version number) while Microsoft's CDBOOT matches
# `BOOTMGR` exactly, and the image boots only as far as
# `CDBOOT: Couldn't find BOOTMGR`. Case was never the problem.
rm -f "$OUT"
xorriso -as mkisofs -iso-level 4 -R -J -joliet-long -D -N -d -relaxed-filenames \
  -volid "WIN10_22H2_X64" \
  -b boot/etfsboot.com -no-emul-boot -boot-load-size 8 -hide boot.catalog \
  -o "$OUT" "$TREE"

echo "=== verifying ==="
isoinfo -i "$OUT" -l 2>/dev/null | sed -n '/Directory listing of \/$/,/^$/p' \
  | grep -qE '(^| )BOOTMGR( |$)' \
  || { echo "BOOTMGR is not a plain name in the ISO - it will not boot" >&2; exit 1; }
xorriso -indev "$OUT" -report_el_torito plain 2>/dev/null | grep -q 'etfsboot.com' \
  || { echo "no El Torito boot image" >&2; exit 1; }
printf '   %s  %s bytes  bootable\n' "$(basename "$OUT")" "$(stat -c %s "$OUT")"
echo "=== $(date -Is) done ==="
