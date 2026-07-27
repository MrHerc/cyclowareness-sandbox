#!/usr/bin/env bash
# Give the guests a simulated internet, so a sample keeps walking.
#
# Without one, containment means the guest reaches nothing: a downloader's first
# fetch fails and it exits, and the report shows the domain it wanted and nothing
# else. With INetSim answering, DNS resolves, HTTP serves a plausible payload,
# SMTP accepts mail — so the sample proceeds to its second and third stage and
# the report gets the URLs, the user agents, the POST bodies and the mail
# recipients that are the actual IOCs.
#
# Nothing reaches the real internet. FORWARD stays DROP in both directions; the
# only thing that changed is that the host now answers on the guest bridge.
#
# Two traps, both hit while building this:
#
#   * The packaged config is REWRITTEN, not replaced. Writing one from scratch
#     silently dropped its http_fakefile table, so every request 404'd and a
#     downloader stopped at its first fetch — the exact failure this exists to
#     prevent, reintroduced by the fix.
#   * A regex that edits `^#?\s*<key>` also matches the commented example line
#     above the real one, so every key it touched ended up defined twice and
#     INetSim refused the whole file and restart-looped.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BRIDGE_IP=${BRIDGE_IP:-192.168.122.1}
CONF=/etc/inetsim/inetsim.conf

command -v inetsim >/dev/null || {
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq inetsim
}
# The packaged unit binds wherever the packaged config says. We drive our own,
# bound to the guest bridge only.
systemctl disable --now inetsim 2>/dev/null || true

echo "== configuration =="
if [[ -f $HERE/sinkhole/inetsim.conf ]]; then
  install -m 644 "$HERE/sinkhole/inetsim.conf" "$CONF"
  echo "   installed the repository's config"
else
  echo "   $HERE/sinkhole/inetsim.conf missing" >&2
  exit 1
fi
grep -q "^service_bind_address[[:space:]]*$BRIDGE_IP" "$CONF" || {
  echo "   config does not bind to $BRIDGE_IP — refusing to start a simulator on a public NIC" >&2
  exit 1
}
printf '   binds to %s, %s services, %s fake-file mappings\n' \
  "$BRIDGE_IP" "$(grep -c '^start_service' "$CONF")" "$(grep -c '^http_fakefile' "$CONF")"

echo
echo "== hand DNS to the simulator, keep libvirt's DHCP =="
# dnsmasq owns 192.168.122.1:53 for both DNS and DHCP. Disabling only its DNS
# frees the port while the guests keep their pinned addresses.
virsh net-dumpxml default > /tmp/cyclo-net.xml
if ! grep -q "<dns enable='no'/>" /tmp/cyclo-net.xml; then
  python3 - <<'PY'
x = open('/tmp/cyclo-net.xml').read()
x = x.replace('<ip address=', "  <dns enable='no'/>\n  <ip address=", 1)
open('/tmp/cyclo-net.xml', 'w').write(x)
PY
  virsh net-define /tmp/cyclo-net.xml >/dev/null
  virsh net-destroy default >/dev/null 2>&1 || true
  virsh net-start default >/dev/null
  echo "   libvirt DNS disabled, DHCP still serving"
else
  echo "   already configured"
fi

echo
echo "== service =="
install -m 644 "$HERE/systemd/cyclo-sinkhole.service" /etc/systemd/system/
mkdir -p /var/log/inetsim/report /var/lib/inetsim
systemctl daemon-reload
systemctl enable --now cyclo-sinkhole
for _ in $(seq 1 12); do
  [[ "$(systemctl is-active cyclo-sinkhole)" == active ]] && break
  sleep 5
done
[[ "$(systemctl is-active cyclo-sinkhole)" == active ]] || {
  echo "   sinkhole did not start:" >&2
  journalctl -u cyclo-sinkhole -n 15 --no-pager >&2
  exit 1
}
listeners=$(ss -lntu | grep -c "$BRIDGE_IP:")
echo "   active, $listeners listeners on $BRIDGE_IP"
(( listeners >= 10 )) || { echo "   too few services bound — check /var/log/inetsim/main.log" >&2; exit 1; }

echo
echo "== open the simulator to the guests, and only the simulator =="
install -m 700 "$HERE/guest-isolation.sh" /usr/local/sbin/cyclo-guest-isolation.sh
/usr/local/sbin/cyclo-guest-isolation.sh
echo "   firewall re-applied"

echo
echo "Now run verify-containment.sh with a guest up. It must report that names"
echo "resolve to the sinkhole AND that raw internet addresses are still blocked."
