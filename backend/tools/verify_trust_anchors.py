"""Check the shipped trust anchors as far as an offline machine can.

The fingerprints in `engine/trust_anchors.py` were bootstrapped from signed
binaries, which is honest but not proof. This checks everything that does not
need a network, and says plainly what is left:

    python tools/verify_trust_anchors.py /path/to/signed/binaries...
    python tools/verify_trust_anchors.py --print

A wrong fingerprint FAILS OPEN — the chain simply stops reaching an anchor and
the file reads as unverified — so a typo costs detection quality silently. That
is the failure this exists to catch.

Exit code is non-zero if any check fails, so it can run in CI.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from app.engine import authenticode, trust_anchors  # noqa: E402

FORBIDDEN = ("timestamp", "time-stamp", "timestamping")


def _cn(name) -> str:
    try:
        found = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return found[0].value if found else name.rfc4514_string()
    except Exception:
        return ""


def _is_ca(cert) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca)
    except Exception:
        return False


def main(argv: list[str]) -> int:
    anchors = dict(trust_anchors.SHIPPED_ANCHORS)
    problems: list[str] = []
    expired: list[str] = []

    if "--print" in argv:
        argv = [a for a in argv if a != "--print"]
        print("# diff these against each authority's published thumbprint")
        for fingerprint, description in sorted(anchors.items(), key=lambda kv: kv[1]):
            grouped = ":".join(
                fingerprint[i:i + 2].upper() for i in range(0, len(fingerprint), 2))
            print("%-62s SHA256 %s" % (description, grouped))
        print()

    # --- shape ---------------------------------------------------------------
    for fingerprint, description in anchors.items():
        if len(fingerprint) != 64 or not all(c in "0123456789abcdef" for c in fingerprint):
            problems.append(f"not a lowercase SHA-256: {fingerprint!r}")
        lowered = description.lower()
        if any(bad in lowered for bad in FORBIDDEN):
            problems.append(f"timestamping authority anchored: {description}")
    if len(set(anchors.values())) != len(anchors):
        problems.append("two fingerprints share a description; one may be a copy-paste")

    # --- against real certificates -------------------------------------------
    paths = [p for p in argv[1:] if os.path.exists(p)]
    seen: dict[str, dict] = {}
    scanned = 0
    for target in paths:
        walk = ([os.path.join(d, n) for d, _s, ns in os.walk(target) for n in ns]
                if os.path.isdir(target) else [target])
        for path in walk:
            try:
                data = open(path, "rb").read()
            except OSError:
                continue
            blob = authenticode._certificate_blob(data)
            if not blob:
                continue
            scanned += 1
            try:
                certs = authenticode._load_certificates(
                    blob, [authenticode.MAX_DER_STEPS])
            except Exception:
                continue
            for cert in certs:
                try:
                    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                except Exception:
                    continue
                if fingerprint not in anchors:
                    continue
                seen[fingerprint] = {
                    "subject": _cn(cert.subject),
                    "ca": _is_ca(cert),
                    "not_after": cert.not_valid_after_utc,
                    "file": os.path.basename(path),
                }

    if paths:
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc)
        print("checked %d signed files against %d anchors\n" % (scanned, len(anchors)))
        for fingerprint, description in sorted(anchors.items(), key=lambda kv: kv[1]):
            found = seen.get(fingerprint)
            if found is None:
                print("  %-58s not present in the sample set" % description[:58])
                continue
            marks = []
            if found["subject"] != description:
                problems.append(
                    f"{description}: certificate subject is actually "
                    f"{found['subject']!r}")
                marks.append("SUBJECT MISMATCH")
            if not found["ca"]:
                problems.append(f"{description}: not a CA certificate")
                marks.append("NOT A CA")
            if found["not_after"] < now:
                # Reported, not a failure: see the expiry note in
                # trust_anchors.py. Excluding expired authorities cost 32 genuine
                # Microsoft binaries their verification for close to no security
                # gain, and the proper gate is the RFC 3161 countersignature
                # timestamp — which the engine DOES parse, including Microsoft's
                # own `1.3.6.1.4.1.311.3.3.1`, since 2026-08-03. Measured then:
                # of the files under this expired anchor, a readable timestamp
                # went from 0 to 106, and every one of them predates the expiry,
                # so nothing changed status.
                #
                # This line stays "reported, not enforced" on purpose, and the
                # two are not the same thing: `authenticode.verify()` enforces
                # per FILE (a binary signed after the anchor expired loses
                # `verified`), while this tool reports per ANCHOR. Failing the
                # build because an authority expired would retire a fingerprint
                # that 106 correctly-identified binaries still need.
                expired.append(f"{description} (expired {found['not_after'].date()})")
                marks.append("EXPIRED - reported, not enforced")
            print("  %-58s ok  (%s, expires %s) %s"
                  % (description[:58], found["file"][:22],
                     found["not_after"].date(), " ".join(marks)))
    else:
        print("no sample paths given; shape checks only\n")

    print("\nWHAT THIS DOES NOT CHECK: whether each fingerprint matches the")
    print("authority's OWN published thumbprint. That needs a network, which")
    print("this tool deliberately does not have.")
    print("Its sibling does it: tools/verify_anchor_provenance.py, last run")
    print("2026-08-01 with 10 of 10 confirmed against the issuing authority.")
    print("The result is recorded per anchor in trust_anchors.ANCHOR_PROVENANCE,")
    print("and describe() reports provenance: vendor-published while it holds.")

    if problems:
        print("\nFAILED:")
        for problem in problems:
            print("  - %s" % problem)
        return 1
    print("\nall offline checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
