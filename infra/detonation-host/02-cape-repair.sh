#!/usr/bin/env bash
# Fix what CAPEv2's own installer leaves broken on Ubuntu 22.04.
#
# Each of these was found by watching the `cape` unit crash-loop, not by reading
# documentation, and every one of them fails in a way that is easy to misread.
# Run after cape2.sh has installed CAPE, and before creating a guest.
#
# Safe to re-run: everything here is idempotent.
set -euo pipefail

CAPE_DIR=${CAPE_DIR:-/opt/CAPEv2}
POETRY=${POETRY:-/etc/poetry/bin/poetry}
GUEST_NET=${GUEST_NET:-192.168.122}
LIBVIRT_VERSION=$(libvirtd --version | awk '{print $3}')

[[ -d $CAPE_DIR ]] || { echo "no CAPE at $CAPE_DIR" >&2; exit 1; }

echo "== 1/5 libvirt-python inside CAPE's poetry environment =="
# The unit dies with `ModuleNotFoundError: No module named 'libvirt'` and a
# message blaming the Python environment. The real cause is that the KVM
# machinery needs libvirt-python, which is not in CAPE's lockfile, and building
# it needs libvirt-dev. Pin it to the host's libvirt or the build mismatches.
if ! sudo -u cape "$POETRY" run python -c 'import libvirt' 2>/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libvirt-dev pkg-config
  ( cd "$CAPE_DIR" && sudo -u cape "$POETRY" run pip install -q "libvirt-python==${LIBVIRT_VERSION}" )
fi
( cd "$CAPE_DIR" && sudo -u cape "$POETRY" run python -c \
  'import libvirt; print("   libvirt-python", libvirt.getVersion())' )

echo "== 2/5 result server address =="
# Shipped as 192.168.1.1 - an address that does not exist on this box. The guest
# posts its behavioural log there, so nothing errors: every analysis simply comes
# back empty. This is the single most expensive default in the file.
CONF="$CAPE_DIR/conf/cuckoo.conf"
CURRENT=$(awk '/^\[resultserver\]/{f=1} f&&/^ip[[:space:]]*=/{print $3; exit}' "$CONF")
if [[ "$CURRENT" != "${GUEST_NET}.1" ]]; then
  cp "$CONF" "$CONF.bak.$(date +%s)"
  python3 - "$CONF" "${GUEST_NET}.1" <<'PY'
import re, sys
path, want = sys.argv[1], sys.argv[2]
text = open(path).read()
def fix(m):
    return m.group(1) + re.sub(r'^ip\s*=.*$', f'ip = {want}', m.group(2), flags=re.M)
text = re.sub(r'(\[resultserver\])(.*?)(?=\n\[|\Z)', fix, text, flags=re.S)
open(path, 'w').write(text)
PY
fi
echo "   resultserver ip = $(awk '/^\[resultserver\]/{f=1} f&&/^ip[[:space:]]*=/{print $3; exit}' "$CONF")"

echo "== 3/5 libvirt storage pool =="
# A stock install defines none, and virt-install then refuses paths it cannot
# resolve to a pool.
if ! virsh pool-info default >/dev/null 2>&1; then
  virsh pool-define-as default dir --target /var/lib/libvirt/images >/dev/null
  virsh pool-autostart default >/dev/null
  virsh pool-start default >/dev/null
fi
virsh pool-list --all | sed 's/^/   /'

echo "== 4/5 pin the guest's address by MAC =="
# Set here rather than inside Windows: the unattend file's
# <Identifier>Ethernet</Identifier> never binds to the real adapter, and the
# guest silently comes up on a DHCP address that conf/kvm.conf does not expect.
MAC=${GUEST_MAC:-52:54:00:9a:11:05}
IP=${GUEST_IP:-${GUEST_NET}.105}
if ! virsh net-dumpxml default | grep -q "$MAC"; then
  virsh net-update default add ip-dhcp-host \
    "<host mac='$MAC' name='DESKTOP-J4K2P8' ip='$IP'/>" --live --config
fi
virsh net-dumpxml default | grep 'host mac' | sed 's/^/   /'


echo "== 5/5 upload limit, taken from the backend rather than typed twice =="
# The API accepts MAX_SAMPLE_BYTES and CAPE refused anything over its own
# max_sample_size. The two were chosen independently -- 33554432 against
# 30000000 -- and the band between them is a class of sample the product
# accepts, analyses statically, and can never detonate. Live jobs sat in it,
# refused with "Sample size is: 30 Allowed size is: 29".
#
# Read from the source of truth so it cannot drift again. If the backend is not
# beside this checkout the step says so and leaves the file alone rather than
# guessing a number.
BACKEND_STORAGE="$(dirname "$0")/../../backend/app/engine/storage.py"
if [[ -f $BACKEND_STORAGE ]]; then
  LIMIT=$(python3 - "$BACKEND_STORAGE" <<'PY'
import ast, sys

def fold(node):
    """32 * 1024 * 1024 is an expression, not a literal, so literal_eval
    refuses it. Fold the two operators the constant actually uses rather
    than reaching for eval on a value that decides what the sandbox will
    accept."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.BinOp):
        left, right = fold(node.left), fold(node.right)
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Add):
            return left + right
    raise ValueError("MAX_SAMPLE_BYTES is no longer plain integer arithmetic")

tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
for node in tree.body:
    if isinstance(node, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == "MAX_SAMPLE_BYTES" for t in node.targets
    ):
        print(fold(node.value))
        break
PY
)
  if [[ -n ${LIMIT:-} ]]; then
    sed -i "s/^max_sample_size = .*/max_sample_size = ${LIMIT}/" "$CAPE_DIR/conf/web.conf"
    grep -n '^max_sample_size' "$CAPE_DIR/conf/web.conf" | sed 's/^/   /'
    systemctl restart cape-web 2>/dev/null || true
  else
    echo "   could not read MAX_SAMPLE_BYTES; conf/web.conf left alone" >&2
  fi
else
  echo "   backend not beside this checkout; conf/web.conf left alone" >&2
fi

echo
echo "Done. CAPE will still refuse to start until a guest domain exists —"
echo "that is 03-build-windows-iso.sh and 04-create-guest.sh."
