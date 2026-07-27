# Detonation host — runbook

The machine that **actually runs the malware**. The web tier never executes a
sample; behaviour data only ever comes from here.

Everything below has been executed end to end on a real host and produced a real
detonation of WannaCry. Where a step exists because something failed, the failure
is written down — those are the expensive parts.

> **Safety.** This host runs live malware. It must be disposable, network
> isolated and fully yours. `06-isolate-guest.sh` is a gate, not a suggestion:
> it verifies containment **from inside the guest** and exits non-zero if the
> guest can reach the internet or any host port other than the result server.
> A sample that reaches the internet from a rented server earns an abuse
> complaint against whoever rents it.

## What it runs on

Measured configuration: **Hetzner AX41-NVMe** — Ryzen 5 3600 (12 threads), 62 GB
RAM, 2×476 GB NVMe, Ubuntu 22.04.5, ~€69/mo. Minimum sensible: 8 threads, 32 GB,
250 GB SSD, Ubuntu 22.04, AMD-V/VT-x.

**Confirm the recovery path before touching the network steps.** In Hetzner
Robot: the *Rescue* tab offers `linux/amd64` with your SSH key uploaded, and
*Support → Remote console (KVM)* is orderable (free for 3 hours). With those, a
firewall mistake costs a reboot instead of the machine.

## Windows media

Windows 10 Enterprise Evaluation **no longer exists** — the Evaluation Center
page carries a retirement notice and the old download link redirects to a blog
post. Windows 11 Enterprise Evaluation is still offered, but see *Why BIOS*
below: it cannot be snapshot-reverted here.

`03-build-windows-iso.sh` therefore builds installation media from Microsoft's
own product catalog — the feed the Media Creation Tool itself reads:

```
https://go.microsoft.com/fwlink/?LinkId=841361  ->  products.cab  ->  products.xml
```

which carries unauthenticated `dl.delivery.mp.microsoft.com` ESD URLs. The
consumer ISO *link API* is not usable: it answers
`{"Errors":[{"Key":"ErrorSettings.SentinelReject"}]}` to anything that is not a
real browser, from a datacenter IP and from a home connection alike.

The ESD is rebuilt into a bootable ISO with `wimlib-imagex` and `xorriso`. Note
`-N -d` in the xorriso invocation: without them the image boots and then says
`CDBOOT: Couldn't find BOOTMGR`, because mkisofs writes `BOOTMGR.;1` while
CDBOOT matches `BOOTMGR` exactly.

## Run order

| Step | Does | Needs you |
|---|---|---|
| `01-bootstrap.sh` | KVM/QEMU/libvirt, Docker, tcpdump, ufw, `sandbox` user | no |
| *(upstream)* `cape2.sh base` + `mongo` | installs CAPEv2 itself | no |
| `02-cape-repair.sh` | libvirt-python, result-server address, storage pool, DHCP reservation | no |
| `03-build-windows-iso.sh` | fetches the ESD, masters a bootable Windows 10 22H2 ISO | no |
| `04-create-guest.sh <iso>` | builds the provisioning CD if absent, then defines and boots `cape1`; the install is fully unattended | no |
| `05-harden-guest.sh` | silences guest telemetry, reboots, verifies | no |
| `06-isolate-guest.sh` | installs the containment rules, then runs the gate below | no |
| `07-golden-snapshot.sh` | takes the running snapshot and proves a revert discards state | no |

Two helpers the numbered steps call, and which are worth running on their own:

| Helper | Does |
|---|---|
| `build-provision-iso.sh` | masters the second CD: `autounattend.xml`, `setup.cmd`, `harden.py`, the CAPE agent taken from the local checkout, and a Python runtime. Verifies the answer file is at the root of **both** filesystem trees — plain 8.3 truncates it to `AUTOUNAT.XML`, and Setup then silently ignores it and stops on the language prompt. |
| `verify-containment.sh` | **the safety gate.** Changes nothing; answers only "is this host safe to detonate on right now". Run it before every real-malware run and after anything that touches the firewall. |

`verify-containment.sh` is separate from `06` on purpose. When the checks lived
inside `06` they ran *after* it had applied the rules, so it verified a state it
had just created: with a hole punched allowing guest → host:22, the combined
script still printed "Safe to detonate", because it closed the hole before
looking. A gate that cannot fail manufactures confidence.

Nobody clicks anything. `guest/autounattend.xml` partitions the disk, selects
Windows 10 Pro, skips OOBE, creates `analyst`, and `guest/setup.cmd` installs
Python, stages the CAPE agent as a logon task with `/rl highest`, and turns off
UAC, the firewall and Windows Update.

**Do not run** `cape2.sh` stages `systemd`, `suricata`, `nginx` or `redsocks`.
They rewrite `NETWORK_IFACE`/`IFACE_IP`, and this host has one WAN NIC.

## Constraints that decide the design

**Why BIOS and not UEFI.** CAPE reverts with `revertToSnapshot(flags=0)` and then
waits for the domain to be RUNNING — it never starts the domain itself, and says
so: *"Your snapshot MUST BE in running state!"*. Measured here with libvirt
8.0.0:

| firmware | snapshot | result |
|---|---|---|
| UEFI (OVMF pflash) | running | `internal snapshots of a VM with pflash based firmware are not supported` |
| UEFI | powered off | works — but CAPE will not accept it |
| BIOS | running | created and reverted; the only usable shape |

Windows 11 requires UEFI, so it cannot be the guest here. Upgrading libvirt does
not help: its changelog restores only *inactive* internal snapshots on UEFI.

**The result-server address.** Ships as `192.168.1.1`, an address that does not
exist on this box. The guest posts its behavioural log there, so nothing errors —
every analysis simply comes back empty. `02-cape-repair.sh` fixes it.

**The guest's IP is pinned in libvirt, not in Windows.** The unattend file's
`<Identifier>Ethernet</Identifier>` never binds to the real adapter; the guest
comes up on a DHCP address `conf/kvm.conf` does not expect.

**Firewall rule order.** An *appended* `-i virbr0 -j DROP` never fires — ufw's
"allow 22/tcp from anywhere" is in a chain INPUT jumps to first, and the guest
could reach the host's SSH. And `ESTABLISHED,RELATED` must be accepted *before*
that DROP, or CAPE's own connections to the agent lose their replies and the
sandbox goes silent. `guest-isolation.sh` gets both right, and a systemd timer
re-applies it every minute because CAPE's rooter rewrites the whole ruleset when
it stops.

## Operating it

- **CAPE requires the guest powered off** before a task. A manual
  `virsh snapshot-revert` leaves it running and the task dies with *"Trying to
  start a virtual machine that has not been turned off"*.
- One such failure marks the machine `CuckooDeadMachine: cape1 is dead!` and
  drops it from the pool; every later task then fails with *"no matching machine
  … Available machine tags: {}"*. Only `systemctl restart cape` brings it back.
- `conf/kvm.conf` here is the working configuration: one machine, `arch = x64`,
  `snapshot = clean`, `resultserver_ip = 192.168.122.1`.

## After a rebuild

`worker/engines/baseline_networks.txt` describes **this exact golden image** —
the networks an idle guest contacts, used to keep platform noise out of reported
IOCs. Rebuild the image, regenerate that file: run three idle detonations of a
sample that only sleeps, collect `network.hosts` and `network.dead_hosts`, and
collapse to /24. A stale baseline suppresses the wrong things, which is the one
failure mode that costs an analyst a real finding.
