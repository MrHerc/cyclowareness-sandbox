#!/usr/bin/env bash
#
# Cyclowareness Sandbox — detonation host bootstrap (Phase 1)
# =============================================================================
# Prepares a fresh Ubuntu 22.04 host to run real malware detonation:
# KVM/QEMU virtualization, Docker, packet capture, a locked-down firewall, and a
# non-root service user. It does NOT install CAPEv2 yet (that is Phase 2) — the
# goal of this script is to get the box to a proven, virtualization-capable,
# hardened baseline and TELL YOU CLEARLY whether nested virtualization works.
#
# SAFETY: this machine will execute live malware. It MUST be a disposable,
# network-isolated host that you control — never on a network with production
# systems, never your daily machine.
#
# Run as root on a FRESH box:   sudo bash 01-bootstrap.sh
# =============================================================================
set -euo pipefail

log(){ printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
ok(){  printf '  \033[1;32m[ok]\033[0m %s\n' "$*"; }
warn(){ printf '  \033[1;33m[!!]\033[0m %s\n' "$*"; }

if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo bash $0"; exit 1; fi

SVC_USER="${SVC_USER:-sandbox}"

log "1/7  System update"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

log "2/7  Virtualization support check (CPU)"
VMX=$(grep -Ec '(vmx|svm)' /proc/cpuinfo || true)
if [[ "$VMX" -gt 0 ]]; then ok "CPU virtualization extensions present ($VMX threads)"
else warn "No vmx/svm in /proc/cpuinfo — this host CANNOT run VMs. You need bare-metal or a nested-virt-enabled instance."; fi

log "3/7  Install KVM / QEMU / libvirt + tooling"
apt-get install -y \
  qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virtinst virt-manager \
  cpu-checker tcpdump tshark net-tools jq git curl unzip python3 python3-venv python3-pip \
  ufw fail2ban
systemctl enable --now libvirtd
ok "KVM stack installed"

log "4/7  Docker"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker
ok "Docker $(docker --version | awk '{print $3}' | tr -d ,)"

log "5/7  Service user + groups"
if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$SVC_USER"
fi
usermod -aG kvm,libvirt,docker "$SVC_USER"
ok "User '$SVC_USER' in kvm, libvirt, docker groups"

log "6/7  Firewall (deny inbound except SSH; malware egress is controlled later)"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw --force enable
systemctl enable --now fail2ban
ok "ufw active (SSH only inbound)"

log "7/7  Nested virtualization check"
kvm-ok || warn "kvm-ok reported a problem — see message above"
NESTED="unknown"
if [[ -e /sys/module/kvm_intel/parameters/nested ]]; then
  NESTED=$(cat /sys/module/kvm_intel/parameters/nested)
elif [[ -e /sys/module/kvm_amd/parameters/nested ]]; then
  NESTED=$(cat /sys/module/kvm_amd/parameters/nested)
fi

echo
echo "============================================================"
echo " BOOTSTRAP COMPLETE — report this block back to Claude"
echo "============================================================"
echo " CPU virt extensions : $([[ $VMX -gt 0 ]] && echo yes || echo NO)"
echo " KVM device present  : $([[ -e /dev/kvm ]] && echo yes || echo NO)"
echo " Nested virt flag    : $NESTED   (want Y or 1)"
echo " Docker              : $(docker --version 2>/dev/null | awk '{print $3}' | tr -d , || echo missing)"
echo " libvirt             : $(systemctl is-active libvirtd)"
echo " Kernel / arch       : $(uname -r) / $(uname -m)"
echo " RAM (GB)            : $(free -g | awk '/Mem:/{print $2}')"
echo " CPU threads         : $(nproc)"
echo "============================================================"
echo
if [[ "$NESTED" == "Y" || "$NESTED" == "1" ]]; then
  ok "Nested virtualization is ON — this host can run CAPEv2 analysis VMs. Proceed to Phase 2."
else
  warn "Nested virtualization is OFF or unknown."
  warn "On BARE METAL this is fine (VMs run directly). On a CLOUD VM you must enable"
  warn "nested virt on the instance, or the analysis VM will not boot. Send the block above."
fi
