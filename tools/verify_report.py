#!/usr/bin/env python3
"""Verify a Cyclowareness Sandbox signed report. Standalone — no access to the system.

    python verify_report.py report.signed.json
    python verify_report.py report.signed.json --public-key <base64>

Exit status is the answer: 0 verified, 1 not verified, 2 the file could not be read.

This file is deliberately self-contained. A regulator, an auditor or opposing
counsel must be able to check a report without installing the product, without
network access and without our cooperation, so the only dependency is the
`cryptography` package (`pip install cryptography`) and the only input is the
report file. That is also why the canonical encoder below is a copy of the
engine's rather than an import of it: an import would make verification depend on
the thing being verified. The backend test suite asserts the two copies agree
byte for byte, so the duplication cannot silently drift.

WHAT A PASS MEANS
    The holder of the named public key signed exactly these bytes, and no byte of
    the report, the engine manifest or the schema has changed since.

WHAT A PASS DOES NOT MEAN
    That the verdict is correct. A signature is a chain-of-custody claim, not a
    second opinion. It also does not tell you the key belongs to who you think:
    compare the printed key id against a key you obtained independently of this
    file (from the operator's contract, or GET /api/attestation/pubkey over a
    channel you trust). A report that carries its own key proves only internal
    consistency, and this tool says so on every run.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import sys
from datetime import datetime, timezone

CANONICALIZATION = "cyclowareness/json-canonical-1"
FLOAT_PRECISION = 6

#: Exactly the keys the signature covers. Named explicitly rather than derived as
#: "everything except the signature", so a field added beside the signature in a
#: later version cannot silently change what this tool believes was signed.
SIGNED_KEYS = ("schema", "manifest", "report")


# --- canonical encoding (mirror of backend/app/engine/attestation.py) ---------


def _canonical(value):
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return round(value, FLOAT_PRECISION) + 0.0
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, dict):
        return {str(k): _canonical(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    return str(value)


def canonical_bytes(document) -> bytes:
    return json.dumps(
        _canonical(document),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def signed_payload(envelope: dict) -> bytes:
    return canonical_bytes({key: envelope[key] for key in SIGNED_KEYS})


def verify(report_bytes: bytes, signature: str, public_key: str) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:  # pragma: no cover - environment problem, not a verdict
        print("ERROR: this verifier needs the `cryptography` package: pip install cryptography")
        raise SystemExit(2)
    try:
        loaded = ed25519.Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_key, validate=True)
        )
        loaded.verify(base64.b64decode(signature, validate=True), report_bytes)
        return True
    except Exception:
        # Every failure is one answer: not verified. Distinguishing "bad
        # signature" from "malformed base64" would invite a caller to treat the
        # second as harmless, which is how tampering gets excused as corruption.
        return False


def key_id(public_key: str) -> str:
    return hashlib.sha256(public_key.encode("ascii")).hexdigest()[:16]


# --- reporting ----------------------------------------------------------------
# Everything printed below stays 7-bit ASCII. This runs on whatever console the
# recipient has, and a Windows cp1252 terminal renders an em dash as a
# replacement character, and mojibake in the middle of a verification result is
# exactly the wrong impression to give an auditor.


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", help="the .signed.json export to check")
    parser.add_argument(
        "--public-key",
        default=None,
        help=(
            "base64 Ed25519 public key obtained independently of the report. "
            "Strongly recommended: without it the report is checked against the "
            "key it carries, which proves only that the file is internally consistent."
        ),
    )
    args = parser.parse_args(argv)

    try:
        with open(args.path, "rb") as handle:
            envelope = json.loads(handle.read().decode("utf-8"))
    except OSError as exc:
        print(f"ERROR: cannot read {args.path}: {exc}")
        return 2
    except ValueError as exc:
        print(f"ERROR: {args.path} is not valid JSON: {exc}")
        return 2

    if not isinstance(envelope, dict) or any(k not in envelope for k in SIGNED_KEYS):
        print(f"ERROR: {args.path} is not a Cyclowareness Sandbox signed export")
        return 2

    schema = envelope.get("schema")
    manifest = envelope.get("manifest") or {}
    report = envelope.get("report") or {}
    submission = report.get("submission") or {}
    reproducible = report.get("reproducible") or {}

    print(f"file            : {args.path}")
    print(f"schema          : {schema}")
    print(f"product         : {manifest.get('product')} {manifest.get('app_version')}")
    print(f"job             : {submission.get('job_id')}")
    print(f"sample sha256   : {reproducible.get('sha256')}")
    print(f"verdict         : {(reproducible.get('verdict') or {}).get('verdict')} "
          f"/ risk {reproducible.get('risk_level')} / score {reproducible.get('final_score')}")
    print(f"engine manifest : {manifest.get('digest')}")
    print(f"reproducible    : {report.get('reproducible_digest')}")

    if not envelope.get("signed"):
        print()
        print("RESULT: NOT VERIFIED - this report is UNSIGNED.")
        print(envelope.get("unsigned_reason") or "No signature is present.")
        return 1

    stated = envelope.get("canonicalization")
    if stated != CANONICALIZATION:
        print()
        print(f"RESULT: NOT VERIFIED - unknown canonicalization {stated!r}.")
        print(f"This verifier only implements {CANONICALIZATION}. Use a matching version.")
        return 1

    payload = signed_payload(envelope)
    computed = "sha256:" + hashlib.sha256(payload).hexdigest()
    stated_digest = envelope.get("payload_digest")
    print(f"payload digest  : {computed}")
    if stated_digest and stated_digest != computed:
        # A mismatch here localises the tampering to the report body before the
        # signature check reports the same thing less usefully.
        print(f"  (the file claims {stated_digest} - the document has been altered)")

    embedded = envelope.get("public_key") or ""
    trusted = args.public_key or embedded
    ok = verify(payload, envelope.get("signature") or "", trusted)

    print(f"key id          : {key_id(trusted) if trusted else '(none)'}")
    print()
    if not ok:
        print("RESULT: NOT VERIFIED - the signature does not cover these bytes.")
        if args.public_key and args.public_key != embedded:
            print("Note: you supplied a key that differs from the one in the file.")
        return 1

    print("RESULT: VERIFIED.")
    print(
        "The holder of this key signed exactly these bytes; nothing in the report "
        "or the engine manifest has changed since."
    )
    if not args.public_key:
        print(
            "CAUTION: the key came from the report itself, so this proves internal "
            "consistency only. Re-run with --public-key using a key obtained from "
            "the operator through a channel independent of this file."
        )
    print(
        "This does not attest that the verdict is correct - only that it is "
        "authentic and unaltered."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
