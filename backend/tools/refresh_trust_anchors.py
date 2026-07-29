"""Print the SHIPPED_ANCHORS block for `engine/trust_anchors.py`.

Reads the certificate chains out of signed binaries you point it at and emits
the issuing certificates it found, each with its subject, its issuer and its
SHA-256. It PRINTS; it does not write. Pasting the result into the engine is a
decision about who this deployment trusts, and a decision should be made by a
person.

    python tools/refresh_trust_anchors.py /path/to/signed/*.exe

Only CA certificates are offered — an end-entity signing certificate expires in
a year or two and pinning one would quietly stop working. Check every
fingerprint against the vendor's published thumbprint before you paste it.
"""
from __future__ import annotations

import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402

from app.engine import authenticode  # noqa: E402


def _is_ca(cert) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca)
    except Exception:
        return False


def _cn(name) -> str:
    from cryptography.x509.oid import NameOID
    try:
        found = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return found[0].value if found else name.rfc4514_string()
    except Exception:
        return ""


def main(paths: list[str]) -> int:
    found: dict[str, dict] = {}
    seen_files: dict[str, list[str]] = defaultdict(list)
    scanned = signed = 0

    for path in paths:
        if not os.path.isfile(path):
            continue
        scanned += 1
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        blob = authenticode._certificate_blob(data)
        if not blob:
            continue
        signed += 1
        try:
            certs = authenticode._load_certificates(blob, [authenticode.MAX_DER_STEPS])
        except Exception:
            continue
        for cert in certs:
            if not _is_ca(cert):
                continue
            try:
                fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            except Exception:
                continue
            found.setdefault(fingerprint, {
                "subject": _cn(cert.subject),
                "issuer": _cn(cert.issuer),
                "not_after": cert.not_valid_after_utc.date().isoformat(),
                "self_signed": cert.issuer == cert.subject,
            })
            seen_files[fingerprint].append(os.path.basename(path))

    print("# scanned %d files, %d carried a signature, %d distinct CA certificates\n"
          % (scanned, signed, len(found)), file=sys.stderr)

    print("SHIPPED_ANCHORS: dict[str, str] = {")
    for fingerprint, info in sorted(found.items(), key=lambda kv: kv[1]["subject"]):
        examples = sorted(set(seen_files[fingerprint]))[:3]
        kind = "root" if info["self_signed"] else "intermediate"
        print("    # %s" % info["subject"])
        print("    #   %s, issued by %s, expires %s"
              % (kind, info["issuer"], info["not_after"]))
        print("    #   seen on: %s" % ", ".join(examples))
        print('    "%s":\n        "%s",' % (fingerprint, info["subject"][:150]))
    print("}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
