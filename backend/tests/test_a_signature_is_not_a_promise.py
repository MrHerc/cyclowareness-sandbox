"""What an Authenticode signature is allowed to buy, and what it must not.

Measured on the detonation host, a verified signature is the strongest
discriminator the engine has and the only one an attacker cannot manufacture by
editing bytes:

    benign PEs     104 signed of 140,  94 fully verified
    real malware     8 signed of  85,   0 verified — every one self-signed,
                                        every one under SHA-1

So it is worth having, and it is worth being extremely careful with, because a
waiver is the entire reason a code-signing certificate gets stolen. These tests
pin the four ways this could be got wrong:

1. treating PRESENCE as verification (`pe.signature_present` did exactly that
   for the product's whole life, and said so in its own detail string);
2. trusting a chain by NAME — an attacker staples the genuine, public Microsoft
   intermediate next to a leaf they issued themselves, and the chain "reaches"
   an anchored fingerprint without Microsoft having signed anything;
3. accepting a signature that does not cover the bytes being analysed;
4. letting a signature excuse BEHAVIOUR. It may only quiet facts about how the
   binary was built.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import struct

import pytest

from app.engine import authenticode, scoring, trust_anchors
from app.engine.contracts import Signal

cryptography = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402


# --- helpers ------------------------------------------------------------------


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cert(subject: str, key, issuer_name=None, issuer_key=None, *, ca: bool,
          code_signing: bool = False):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer_name = issuer_name or name
    issuer_key = issuer_key or key
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if code_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _fingerprint(cert) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _pe(extra: bytes = b"", cert_table: bytes = b"") -> bytes:
    """A minimal but structurally real PE32+, optionally with a certificate table."""
    e_lfanew = 0x80
    header = bytearray(b"MZ" + b"\x00" * (e_lfanew - 2))
    struct.pack_into("<I", header, 0x3C, e_lfanew)
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x22)
    optional = bytearray(240)
    struct.pack_into("<H", optional, 0, 0x20B)          # PE32+
    body = bytes(header) + coff + bytes(optional)
    padding = b"\x00" * 512
    data = bytearray(body + padding + extra)
    if cert_table:
        offset = len(data)
        data.extend(cert_table)
        dd = e_lfanew + 24 + 112
        struct.pack_into("<II", data, dd + 4 * 8, offset, len(cert_table))
    return bytes(data)


# --- 1. the DER reader survives hostile input ---------------------------------


@pytest.mark.parametrize("payload", [
    b"",
    b"\x30",
    b"\x30\x80",                                  # indefinite length
    b"\x30\x84\xff\xff\xff\xff",                  # length far beyond the buffer
    b"\x30\x82\xff\xff" + b"A" * 10,
    b"\x1f\x01\x02",                              # multi-byte tag
    b"\x30\x03\x06\x7f" + b"\xff" * 200,          # OID that never terminates
    bytes([0x30, 0x06]) + bytes([0x30, 0x04]) * 400,
    b"\xa0" * 4096,
    bytes(range(256)) * 40,
])
def test_hostile_der_raises_rather_than_crashing(payload) -> None:
    """Every byte here is attacker-controlled. The contract is DerError or a
    clean result — never a hang, a MemoryError or a RecursionError."""
    try:
        node = authenticode._read(payload, 0, len(payload))
    except authenticode.DerError:
        return
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"{type(exc).__name__}: {exc}")
    budget = [5000]
    try:
        for _element, _level in authenticode._find(payload, node, budget):
            pass
    except authenticode.DerError:
        pass
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"{type(exc).__name__}: {exc}")


def test_deep_nesting_does_not_reach_the_stack() -> None:
    """Built iteratively for this reason: 5000 nested SEQUENCEs would end a
    recursive walker with a RecursionError, which is a crash, not a verdict."""
    payload = b""
    for _ in range(5000):
        payload = bytes([0x30, len(payload) & 0x7F]) + payload if len(payload) < 0x80 else payload
    try:
        node = authenticode._read(payload, 0, len(payload))
        for _e, _l in authenticode._find(payload, node, [200_000]):
            pass
    except authenticode.DerError:
        pass


def test_a_file_that_is_not_a_pe_is_simply_unsigned() -> None:
    for payload in (b"", b"MZ", b"not a program at all", b"MZ" + b"\x00" * 4096):
        result = authenticode.verify(payload)
        assert not result.verified
        assert not result.present or result.reason


# --- 2. the Authenticode hash covers the right bytes --------------------------


def test_the_hash_ignores_the_checksum_and_the_certificate_table() -> None:
    """Those three regions change when a file is signed, so signing would
    invalidate its own signature if they were included."""
    base = _pe(extra=b"payload", cert_table=b"\x10\x00\x00\x00\x00\x02\x02\x00" + b"C" * 8)
    original = authenticode.authenticode_digest(base, "sha256")
    assert original is not None

    e_lfanew = struct.unpack_from("<I", base, 0x3C)[0]
    checksum = e_lfanew + 24 + 64
    poked = bytearray(base)
    struct.pack_into("<I", poked, checksum, 0xDEADBEEF)
    assert authenticode.authenticode_digest(bytes(poked), "sha256") == original

    tampered = bytearray(base)
    tampered[600] ^= 0xFF
    assert authenticode.authenticode_digest(bytes(tampered), "sha256") != original


def test_data_appended_after_the_certificate_table_is_hashed() -> None:
    """Otherwise a payload could be stapled onto a signed file and inherit its
    signature — the whole point of the check."""
    table = b"\x10\x00\x00\x00\x00\x02\x02\x00" + b"C" * 8
    base = _pe(cert_table=table)
    with_extra = base + b"a stapled payload"
    assert (authenticode.authenticode_digest(base, "sha256")
            != authenticode.authenticode_digest(with_extra, "sha256"))


# --- 3. a chain is trusted by KEY, never by name ------------------------------


def test_a_stapled_intermediate_does_not_forge_a_chain(monkeypatch) -> None:
    """THE attack this design has to survive.

    A real intermediate certificate is public — anyone can lift Microsoft's out
    of any signed binary. An attacker issues themselves a leaf that merely
    CLAIMS that intermediate as its issuer, staples the genuine intermediate
    beside it, and the chain now "reaches" an anchored fingerprint. Only
    verifying each link cryptographically stops it.
    """
    real_ca_key = _key()
    real_ca = _cert("Trusted Code Signing CA", real_ca_key, ca=True)

    impostor_key = _key()
    impostor = _cert(
        "Totally Legitimate Software", impostor_key,
        issuer_name=real_ca.subject, issuer_key=impostor_key,   # self-issued!
        ca=False, code_signing=True,
    )

    monkeypatch.setattr(
        trust_anchors, "SHIPPED_ANCHORS",
        {_fingerprint(real_ca): "Trusted Code Signing CA"})
    trust_anchors.reset_cache()

    chain = authenticode._order_chain([impostor, real_ca])
    assert chain[0] is impostor and real_ca in chain

    reach = authenticode._links_verified(chain)
    assert reach == 0, "the impostor leaf was not issued by the CA it names"
    assert not trust_anchors.anchor_for(chain[: reach + 1])
    # and the anchor IS found once the link is genuine
    assert trust_anchors.anchor_for(chain)


def test_a_genuine_chain_verifies_link_by_link(monkeypatch) -> None:
    ca_key = _key()
    ca = _cert("Trusted Code Signing CA", ca_key, ca=True)
    leaf_key = _key()
    leaf = _cert("Honest Software Ltd", leaf_key,
                 issuer_name=ca.subject, issuer_key=ca_key,
                 ca=False, code_signing=True)

    monkeypatch.setattr(trust_anchors, "SHIPPED_ANCHORS",
                        {_fingerprint(ca): "Trusted Code Signing CA"})
    trust_anchors.reset_cache()

    chain = authenticode._order_chain([leaf, ca])
    assert authenticode._links_verified(chain) == 1
    assert trust_anchors.anchor_for(chain) == "Trusted Code Signing CA"


def test_a_self_signed_certificate_anchors_nothing() -> None:
    key = _key()
    solo = _cert("Definitely Microsoft", key, ca=False, code_signing=True)
    trust_anchors.reset_cache()
    assert not trust_anchors.anchor_for([solo])


def test_the_publisher_is_the_code_signing_certificate() -> None:
    """An Authenticode bag carries the TIMESTAMP authority's certificates too.
    Picking the first end-entity named COMODO CA Limited as the publisher of
    BlueScreenView, which is what happened."""
    ca_key = _key()
    ca = _cert("Some CA", ca_key, ca=True)
    signer = _cert("The Real Publisher", _key(), issuer_name=ca.subject,
                   issuer_key=ca_key, ca=False, code_signing=True)
    timestamper = _cert("Timestamp Responder", _key(), issuer_name=ca.subject,
                        issuer_key=ca_key, ca=False)
    chain = authenticode._order_chain([timestamper, signer, ca])
    assert "The Real Publisher" in chain[0].subject.rfc4514_string()


# --- 4. the trust store is data, and it is a decision -------------------------


def test_no_timestamping_authority_is_ever_an_anchor() -> None:
    """A timestamp authority attests to WHEN, not to WHO. If one could anchor a
    chain, anything it ever stamped would be trusted as code."""
    for description in trust_anchors.SHIPPED_ANCHORS.values():
        lowered = description.lower()
        assert "timestamp" not in lowered and "time-stamp" not in lowered, description


def test_every_shipped_anchor_is_a_sha256_fingerprint() -> None:
    for fingerprint in trust_anchors.SHIPPED_ANCHORS:
        assert len(fingerprint) == 64, fingerprint
        assert all(c in "0123456789abcdef" for c in fingerprint), fingerprint


def test_the_operator_can_replace_the_list_entirely(tmp_path, monkeypatch) -> None:
    """Sovereignty is not a slogan here: an operator who wants to trust only
    authorities they chose must be able to discard ours."""
    path = tmp_path / "anchors.json"
    path.write_text(json.dumps({"anchors": {"aa" * 32: "our own CA"}, "replace": True}))
    monkeypatch.setenv("CYCLO_TRUST_ANCHORS", str(path))
    trust_anchors.reset_cache()
    try:
        effective = trust_anchors.anchors()
        assert effective == {"aa" * 32: "our own CA"}
        assert trust_anchors.describe()["replaced_shipped_list"] is True
    finally:
        trust_anchors.reset_cache()


def test_a_broken_anchors_file_does_not_take_the_engine_down(tmp_path, monkeypatch) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{ not json")
    monkeypatch.setenv("CYCLO_TRUST_ANCHORS", str(path))
    trust_anchors.reset_cache()
    try:
        assert trust_anchors.anchors() == dict(trust_anchors.SHIPPED_ANCHORS)
    finally:
        trust_anchors.reset_cache()


def test_the_report_never_implies_revocation_was_checked() -> None:
    """There is no network in this engine. A certificate withdrawn after signing
    still verifies here, and the report has to say so."""
    assert trust_anchors.describe()["revocation_checked"] is False
    assert authenticode.SignatureResult().to_dict()["revocation_checked"] is False


# --- 5. what a signature is allowed to buy ------------------------------------


def _signal(sid: str, severity: str = "high") -> Signal:
    return Signal(id=sid, title=sid, severity=severity, detail="", evidence={})


VERIFIED = _signal(scoring.VERIFIED_PUBLISHER_SIGNAL, "info")


def test_a_verified_publisher_quiets_how_the_binary_was_built() -> None:
    for sid in ("generic.high_entropy_overall", "pe.overlay_present",
                "pe.packer_section_name", "pe.high_entropy_section",
                "yara.upx_packed_executable"):
        assert scoring.effective_severity(_signal(sid)) == "high"
        assert scoring.effective_severity(
            _signal(sid), verified_publisher=True) == "low"


def test_a_verified_publisher_excuses_no_behaviour() -> None:
    """Ten of the malware samples on the detonation host are signed. A stolen
    certificate is stolen to buy exactly this, and it does not."""
    for sid in ("capev2.mass_data_encryption", "capev2.deletes_shadow_copies",
                "capev2.persistence_autorun", "capev2.credential_dumping",
                "script.download_and_execute", "office.autoexec_macro",
                "generic.embedded_executable", "generic.extension_mismatch",
                "generic.double_extension", "archive.malicious_member"):
        assert scoring.effective_severity(
            _signal(sid), verified_publisher=True) == "high", sid


def test_the_two_signals_that_lose_wannacry_are_only_waived_when_signed() -> None:
    """`generic.high_entropy_overall` and `pe.overlay_present` were REJECTED from
    AMBIENT_SIGNALS because demoting them for everything loses WannaCry. They are
    in STRUCTURAL_SIGNALS, and that is not a contradiction — WannaCry is not
    signed. This is what a real discriminator buys that tuning cannot."""
    for sid in ("generic.high_entropy_overall", "pe.overlay_present"):
        assert sid not in scoring.AMBIENT_SIGNALS
        assert sid in scoring.STRUCTURAL_SIGNALS
        assert scoring.effective_severity(_signal(sid)) == "high"


def test_the_waiver_needs_the_verified_signal_not_merely_a_signature() -> None:
    packed = [_signal("pe.packer_section_name"), _signal("generic.high_entropy_overall")]
    merely_present = packed + [_signal("pe.signature_present", "info")]
    score_present, _ = scoring.rule_score(merely_present)
    score_verified, _ = scoring.rule_score(packed + [VERIFIED])
    assert score_verified < score_present


def _classify(signals, family="pe", mime="application/x-dosexec"):
    from app.engine.contracts import AnalyzerResult

    results = [AnalyzerResult(analyzer="pe", ran=True, signals=signals)]
    assessment = scoring.assess(results, ioc_total=0, family=family)
    from app.engine import verdict as verdict_mod

    return verdict_mod.classify(family, mime, results, __import__(
        "app.engine.contracts", fromlist=["IOCs"]).IOCs(), assessment.final_score)


def test_a_verified_publisher_is_not_called_a_backdoor() -> None:
    """Process Explorer installs a helper driver as a service, so
    `capev2.persistence_autorun` fires — and that signal is pinned as
    never-demote, because it IS the persistence signal. So `suspicious` is
    correct and stays. `Win32.Backdoor.PersistenceAutorun` on a binary whose
    signature verifies to Microsoft was not: the honest word for a dual-use tool
    is Riskware, which is what commercial engines call Sysinternals too."""
    behaviour = [_signal("capev2.persistence_autorun"),
                 _signal("capev2.modify_certs", "medium")]
    accused = _classify(behaviour)
    excused = _classify(behaviour + [VERIFIED])
    assert accused.verdict == excused.verdict, "the verdict must not change"
    assert accused.category in ("Backdoor", "Downloader", "Trojan"), accused.to_dict()
    if excused.verdict == "suspicious":
        assert excused.category == "Riskware", excused.to_dict()
        assert "Backdoor" not in excused.threat_name


def test_a_signed_malicious_sample_keeps_its_accusing_name() -> None:
    """Deliberately narrow: signed malware exists — eight samples on the
    detonation host are signed — so a `malicious` verdict keeps its category."""
    heavy = [_signal("capev2.mass_data_encryption"),
             _signal("capev2.deletes_shadow_copies"),
             _signal("capev2.credential_dumping"),
             _signal("capev2.persistence_autorun"),
             VERIFIED]
    got = _classify(heavy)
    if got.verdict == "malicious":
        assert got.category != "Riskware", got.to_dict()


def test_the_structural_list_holds_no_behaviour() -> None:
    """A later edit that drops a `capev2` behaviour signal in here would hand
    every signed publisher a free pass on what their program did."""
    behavioural = [s for s in scoring.STRUCTURAL_SIGNALS
                   if s.startswith("capev2.") and not any(
                       token in s for token in ("pe_", "packer", "overlay", "static_pe"))]
    assert not behavioural, behavioural
