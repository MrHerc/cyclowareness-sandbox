"""`trust_anchors` named the missing piece; this is the piece.

An expired authority stays anchored on purpose. Excluding them was tried and
dropped verification from 94 benign files to 62, because Microsoft Code Signing
PCA 2011 expired on 2026-07-08 and thirty-two genuine Microsoft binaries sit
under it. The note says what would properly gate it:

    "What would properly gate an expired anchor is the RFC 3161 countersignature
     timestamp, i.e. 'was this signed while the authority was valid', which is
     what Windows checks and this engine does not yet parse."

It parses it now, in both forms that occur in the wild: the RFC 3161 token
(OID 1.2.840.113549.1.9.16.2.14, whose value is a whole CMS ContentInfo wrapping
a TSTInfo with a genTime) and the legacy countersignature
(OID 1.2.840.113549.1.9.6, a SignerInfo carrying signingTime).

What the timestamp is allowed to decide is deliberately narrow:

    present, at or before the anchor's expiry -> unchanged, verified
    present, AFTER the anchor expired         -> not verified
    absent                                    -> unchanged

Only the middle line is new. Requiring a timestamp inside validity would instead
strip the waiver from every binary whose timestamp this parser cannot read -- a
false positive invented to fix a theoretical one, which is the thing
`trust_anchors` was avoiding in the first place.

Measured over every signed PE on the detonation host, before and after:
**23 signed, 7 verified, both times.** No waiver moved.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.engine import authenticode
from app.engine.authenticode import _Node, _der_time


def _node(tag: int, body: bytes):
    """A `_Node` over `body`, with the buffer it indexes into."""
    buf = bytes([tag, len(body)]) + body
    return buf, _Node(tag=tag, start=0, header=2, length=len(body), value=2)


# --- reading the two time forms ---------------------------------------------

@pytest.mark.parametrize("text,expected", [
    (b"20240115103000Z", datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)),
    (b"19991231235959Z", datetime(1999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)),
    (b"20260708000000Z", datetime(2026, 7, 8, 0, 0, 0, tzinfo=timezone.utc)),
])
def test_generalized_time(text, expected) -> None:
    buf, node = _node(0x18, text)
    assert _der_time(buf, node) == expected


@pytest.mark.parametrize("text,expected", [
    # RFC 5280: 00-49 is 2000-2049, 50-99 is 1950-1999.
    (b"2401151030Z", datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)),
    (b"240115103045Z", datetime(2024, 1, 15, 10, 30, 45, tzinfo=timezone.utc)),
    (b"991231235959Z", datetime(1999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)),
    (b"490101000000Z", datetime(2049, 1, 1, 0, 0, 0, tzinfo=timezone.utc)),
    (b"500101000000Z", datetime(1950, 1, 1, 0, 0, 0, tzinfo=timezone.utc)),
])
def test_utc_time_and_the_fifty_year_pivot(text, expected) -> None:
    buf, node = _node(0x17, text)
    assert _der_time(buf, node) == expected


@pytest.mark.parametrize("tag,text", [
    (0x18, b"not a time at all"),
    (0x18, b"20241301000000Z"),          # month 13
    (0x18, b"20240115103000"),           # no Z: local time, not read on purpose
    (0x18, b"20240115103000+0200"),      # offset form, likewise
    (0x17, b"241315103000Z"),            # month 13
    (0x17, b"24Z"),                      # too short
    (0x18, b""),
    (0x04, b"20240115103000Z"),          # right text, wrong tag
])
def test_anything_unreadable_is_none_and_never_raises(tag, text) -> None:
    """A timestamp this parser cannot read must leave the verdict alone.

    Raising here would turn a limitation of ours into a failed verification for
    a file that has done nothing wrong.
    """
    buf, node = _node(tag, text)
    assert _der_time(buf, node) is None


# --- the helper that decides whether to gate --------------------------------

class _FakeCert:
    def __init__(self, subject, not_after=None):
        self.subject = subject
        if not_after is not None:
            self.not_valid_after_utc = not_after


class _Rfc4514:
    def __init__(self, text: str) -> None:
        self._text = text

    def rfc4514_string(self) -> str:
        return self._text


def test_anchor_expiry_reads_an_x509_name_not_a_string() -> None:
    """The bug this cost: `subject` is a Name, and `in` on it is a TypeError.

    It raised on audacity.exe, handbrake.exe, putty.exe and winmerge.exe --
    four correctly-signed benign binaries turned into an exception by a helper
    that is only supposed to be able to tighten a verdict.
    """
    expiry = datetime(2026, 7, 8, tzinfo=timezone.utc)
    chain = [_FakeCert(_Rfc4514("CN=Microsoft Code Signing PCA 2011"), expiry)]
    assert authenticode._anchor_expiry(chain, "Microsoft Code Signing PCA 2011") == expiry


def test_anchor_expiry_returns_none_rather_than_raising() -> None:
    """None means "do not gate", and that is the safe direction."""
    assert authenticode._anchor_expiry([], "anything") is None
    assert authenticode._anchor_expiry([_FakeCert(object())], "anything") is None
    assert authenticode._anchor_expiry([_FakeCert(_Rfc4514("CN=X"))], "CN=X") is None
    assert authenticode._anchor_expiry([_FakeCert(_Rfc4514("CN=X"), "not-a-date")], "CN=X") is None
    assert authenticode._anchor_expiry([_FakeCert(_Rfc4514("CN=X"), expiry_str())], "CN=X") is not None


def expiry_str() -> str:
    return "2026-07-08T00:00:00+00:00"


def test_an_unnamed_anchor_is_not_gated() -> None:
    """No anchor name, nothing to compare against."""
    assert authenticode._anchor_expiry([_FakeCert(_Rfc4514("CN=X"))], "") is None


# --- the field is carried out to the report ---------------------------------

def test_the_result_reports_when_it_was_signed() -> None:
    result = authenticode.SignatureResult(present=True, parsed=True, signed_at="2024-01-15T10:30:00+00:00")
    assert result.to_dict()["signed_at"] == "2024-01-15T10:30:00+00:00"


def test_an_unsigned_file_reports_an_empty_timestamp_not_now() -> None:
    """Absence of a timestamp must never render as "signed recently"."""
    assert authenticode.SignatureResult().to_dict()["signed_at"] == ""


def test_verify_of_a_non_pe_is_still_quiet() -> None:
    """The parser additions must not have made an ordinary miss noisy."""
    result = authenticode.verify(b"not a PE at all" * 100)
    assert result.present is False
    assert result.to_dict()["signed_at"] == ""


# --- the OID Microsoft actually uses ----------------------------------------
#
# The parsers above were right and the dispatcher was wrong. `_signing_time`
# routed on the CMS OID 1.2.840.113549.1.9.16.2.14, which Microsoft does not
# use: Authenticode carries its RFC 3161 token under szOID_RFC3161_counterSign,
# 1.3.6.1.4.1.311.3.3.1.
#
# Measured over every signed PE on the detonation host, before the fix:
#
#     signed PEs on disk                         181
#     with a timestamp the engine READ            11
#     anchored to the EXPIRED Microsoft CS PCA 2011  106
#       of those, timestamp read                     0
#
# So the expiry gate could not fire on a single one of the files it exists to
# judge, and the CMS OID occurs zero times in the whole corpus. After the fix,
# same populations, same command:
#
#     with a timestamp the engine READ           178
#       of the 106 under the expired anchor      106
#     verified                                   167  (unchanged, both runs)
#
# Nothing lost a waiver. The gate simply stopped being a no-op.


def _der(tag: int, body: bytes) -> bytes:
    """Minimal DER TLV. Long form only where the body needs it."""
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body


def _timestamp_token(gen_time: bytes) -> bytes:
    """A TimeStampToken shaped exactly as `_timestamp_from_rfc3161` walks it.

        ContentInfo  ::= SEQUENCE { contentType OID, [0] SignedData }
        SignedData   ::= SEQUENCE { version, digestAlgorithms, encapContentInfo }
        encap        ::= SEQUENCE { eContentType OID, [0] OCTET STRING(TSTInfo) }
        TSTInfo      ::= SEQUENCE { version, ..., genTime GeneralizedTime }
    """
    tst = _der(0x30, _der(0x02, b"\x01") + _der(0x18, gen_time))
    encap = _der(0x30, _der(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x04")
                 + _der(0xA0, _der(0x04, tst)))
    signed = _der(0x30, _der(0x02, b"\x03") + _der(0x31, b"") + encap)
    return _der(0x30, _der(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02")
                + _der(0xA0, signed))


def _oid_der(dotted: str) -> bytes:
    """Encode a dotted OID, so the test states the OID rather than a blob."""
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append((part & 0x7F) | 0x80)
            part >>= 7
        body += bytes(reversed(chunk))
    return _der(0x06, body)


def _unsigned_attrs(oid: str, token: bytes):
    """An `unsignedAttrs` [1] holding one attribute, and its buffer."""
    attribute = _der(0x30, _oid_der(oid) + _der(0x31, token))
    body = attribute
    buf = _der(0xA1, body)
    return buf, _Node(tag=0xA1, start=0, header=len(buf) - len(body),
                      length=len(body), value=len(buf) - len(body))


@pytest.mark.parametrize("oid", [
    "1.3.6.1.4.1.311.3.3.1",        # szOID_RFC3161_counterSign — 169 corpus files
    "1.2.840.113549.1.9.16.2.14",   # the CMS OID — zero corpus files, kept working
])
def test_both_rfc3161_oids_are_dispatched(oid) -> None:
    buf, node = _unsigned_attrs(oid, _timestamp_token(b"20240115103000Z"))
    found = authenticode._signing_time(buf, node, [100_000])
    assert found is not None, f"{oid} was not dispatched to the RFC 3161 reader"
    assert found == datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc)


def test_the_microsoft_oid_is_named_not_inlined() -> None:
    """A bare string in a dispatch is a fact nobody can look up."""
    assert authenticode.OID_MS_TIMESTAMP_TOKEN == "1.3.6.1.4.1.311.3.3.1"


def test_an_unknown_unsigned_attribute_is_still_ignored() -> None:
    """Widening the dispatch must not make it credulous: an attribute this
    module does not recognise still yields no timestamp."""
    buf, node = _unsigned_attrs("1.3.6.1.4.1.311.2.4.1",     # SPC_NESTED_SIGNATURE
                                _timestamp_token(b"20240115103000Z"))
    assert authenticode._signing_time(buf, node, [100_000]) is None
