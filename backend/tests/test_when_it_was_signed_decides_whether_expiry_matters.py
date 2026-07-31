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
