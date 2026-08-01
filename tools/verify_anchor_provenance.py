#!/usr/bin/env python3
"""Compare every shipped trust anchor with the authority's own published copy.

    python3 tools/verify_anchor_provenance.py [--json]

`app/engine/trust_anchors.py` reads its fingerprints out of the certificate
chains embedded in signed binaries on the detonation host. That is honest
bootstrapping and the module says so — but it is trust-on-first-use, and the
module's docstring names the missing step: *comparing each fingerprint with the
authority's own published thumbprint*.

That comparison needs a network, which is exactly what the engine does not have
and must not acquire. So it lives here, outside the product, to be run by an
operator before production and again whenever an anchor is added. Its output is
meant to be pasted into `ANCHOR_PROVENANCE`.

Sibling of `tools/verify_trust_anchors.py`, which checks everything that CAN be
checked offline (well-formedness, uniqueness, that each anchor is a real CA a
sample chains to, that none is a timestamping authority, that the fingerprint
recomputes from the bytes). This one answers the only question that one cannot:
is this fingerprint really that authority's certificate?

Three outcomes, and the difference between them is the whole point:

  match      the authority publishes a certificate whose SHA-256 is exactly the
             pinned value. Proof.
  same-key   the published certificate differs but carries the SAME subject
             public key — a cross-certificate. Anchoring either trusts the same
             key, so this is a confirmation, not a discrepancy. Certum is this
             case: it publishes the self-signed `Certum Trusted Network CA 2`
             while signed software carries the cross-signed issuance.
  unconfirmed  nothing was retrieved, or what was retrieved is a different key.
             NEVER treated as a pass. An anchor that reaches production
             unconfirmed keeps the store at `provenance: bootstrapped`.

Exit status is 0 only when every shipped anchor is `match` or `same-key`.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "backend"))

from app.engine.trust_anchors import SHIPPED_ANCHORS  # noqa: E402

#: The authorities' own documented distribution points, keyed by the anchor
#: description rather than by fingerprint — a fingerprint written twice is a
#: fingerprint that can disagree with itself.
#:
#: More than one candidate per authority where a vendor uses several naming
#: conventions. A URL that 404s is not a failure of the anchor; only exhausting
#: every candidate is.
PUBLISHED: dict[str, list[str]] = {
    "DigiCert CS RSA4096 Root G5": [
        "https://cacerts.digicert.com/DigiCertCSRSA4096RootG5.crt",
    ],
    "DigiCert Trusted Root G4": [
        "https://cacerts.digicert.com/DigiCertTrustedRootG4.crt",
    ],
    "GlobalSign Code Signing Root R45": [
        "https://secure.globalsign.com/cacert/codesigningrootr45.crt",
    ],
    "Microsoft Identity Verification Root Certificate Authority 2020": [
        "https://www.microsoft.com/pkiops/certs/Microsoft%20Identity%20Verification"
        "%20Root%20Certificate%20Authority%202020.crt",
    ],
    "Microsoft Code Signing PCA 2011": [
        "https://www.microsoft.com/pkiops/certs/MicCodSigPCA2011_2011-07-08.crt",
        "http://www.microsoft.com/pki/certs/MicCodSigPCA2011_2011-07-08.crt",
    ],
    "Microsoft Code Signing PCA 2024": [
        "https://www.microsoft.com/pkiops/certs/Microsoft%20Code%20Signing%20PCA%202024.crt",
    ],
    "Microsoft ID Verified Code Signing PCA 2021": [
        "https://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20Code"
        "%20Signing%20PCA%202021.crt",
    ],
    "Microsoft Windows Third Party Component CA 2013": [
        "https://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Third%20Party"
        "%20Component%20CA%202013.crt",
    ],
    "Certum Trusted Network CA 2": [
        "https://repository.certum.pl/ctnca2.cer",
    ],
    "Sectigo Public Code Signing CA R36": [
        # HTTPS first on purpose. Sectigo's TLS endpoint refused the connection
        # from the detonation host on 2026-08-01, so the http URL is the
        # fallback and the result records which one answered.
        "https://crt.sectigo.com/SectigoPublicCodeSigningCAR36.crt",
        "http://crt.sectigo.com/SectigoPublicCodeSigningCAR36.crt",
    ],
}

TIMEOUT = 45
MAX_BYTES = 4 * 1024 * 1024
_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


def fetch(url: str) -> bytes | None:
    request = urllib.request.Request(
        url, headers={"User-Agent": "cyclowareness-anchor-provenance/1.0"})
    try:
        with urllib.request.urlopen(
                request, timeout=TIMEOUT, context=ssl.create_default_context()) as response:
            return response.read(MAX_BYTES)
    except Exception:                                           # noqa: BLE001
        return None


def as_der(blob: bytes) -> bytes | None:
    """DER in, DER out; PEM in, DER out; anything else is not a certificate."""
    if blob[:1] == b"\x30":
        return blob
    found = _PEM.search(blob)
    if not found:
        return None
    try:
        return base64.b64decode(re.sub(rb"\s+", b"", found.group(1)))
    except Exception:                                           # noqa: BLE001
        return None


def _openssl(args: list[str], data: bytes) -> bytes:
    return subprocess.run(["openssl", *args], input=data, capture_output=True).stdout or b""


def public_key_sha256(der: bytes) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo — what a cross-certificate shares."""
    pem = _openssl(["x509", "-inform", "DER", "-noout", "-pubkey"], der)
    if not pem:
        return ""
    key = _openssl(["pkey", "-pubin", "-outform", "DER"], pem)
    return hashlib.sha256(key).hexdigest() if key else ""


def subject(der: bytes) -> str:
    out = _openssl(["x509", "-inform", "DER", "-noout", "-subject"], der)
    return out.decode("utf-8", "replace").strip()[:150]


def check(sha256: str, name: str) -> dict:
    """One anchor against every published URL its authority offers."""
    result = {"anchor": sha256, "name": name, "status": "unconfirmed",
              "url": "", "detail": ""}
    for url in PUBLISHED.get(name, []):
        blob = fetch(url)
        if not blob:
            continue
        der = as_der(blob)
        if not der:
            continue
        result["url"] = url
        if hashlib.sha256(der).hexdigest() == sha256:
            result["status"] = "match"
            result["detail"] = subject(der)
            return result
        # Not the same certificate. It may still be the same AUTHORITY: a
        # cross-certificate re-issues one subject public key under a different
        # issuer, and signed software carries whichever issuance its vendor
        # chained through.
        published_key = public_key_sha256(der)
        result["detail"] = (
            "published certificate is %s, subject %s"
            % (hashlib.sha256(der).hexdigest()[:16], subject(der))
        )
        result["published_key"] = published_key
        result["status"] = "different-certificate"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--anchor-key",
        metavar="SHA256",
        help="SHA-256 of the SubjectPublicKeyInfo of a pinned anchor, so a "
             "`different-certificate` result can be resolved to `same-key` "
             "without this tool needing the signed binary it came from",
    )
    args = parser.parse_args()

    results = [check(sha, name) for sha, name in sorted(SHIPPED_ANCHORS.items(),
                                                        key=lambda kv: kv[1])]
    for row in results:
        if row["status"] == "different-certificate" and args.anchor_key:
            if row.get("published_key") == args.anchor_key:
                row["status"] = "same-key"

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for row in results:
            print("%-9s %-62s %s" % (row["status"], row["name"][:62], row["url"][:60]))
            if row["detail"]:
                print("          %s" % row["detail"][:110])

    good = sum(1 for r in results if r["status"] in ("match", "same-key"))
    print("\n%d of %d anchors confirmed against the issuing authority"
          % (good, len(results)))
    if good != len(results):
        print("NOT CONFIRMED — these must not be recorded in ANCHOR_PROVENANCE:")
        for row in results:
            if row["status"] not in ("match", "same-key"):
                print("  %s  %s" % (row["name"], row["status"]))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
