"""NIST 800-53 was called `PDF.Trojan.HighEntropyOverall`.

`generic.high_entropy_overall` says "packed, encrypted, or otherwise obfuscated
content. Legitimate files of this type are normally well below this." For a PDF
that sentence is simply false: a PDF is a container of Flate streams and embedded
JPEG/JBIG2 images, so any substantial one sits near 8.00 whatever it holds.

`_entropy_is_meaningful` already knew the principle -- it exempts archives,
images, audio, video, OOXML and the already-compressed MIMEs, and the OOXML line
spells out the reason. PDF was missed.

Measured across every PDF the deployment had analysed before the fix:

    verdict      n   entropy min/median/max   entropy-flagged
    clean        7   4.81 / 4.85 / 7.93       1
    suspicious   5   5.00 / 7.98 / 7.98       4

All five it fired on were 7.93-7.98 -- NIST 800-53, NIST CSF, two malware-corpus
samples and a clean addendum. It separated nothing. Worse, the two NIST
publications came out with byte-identical signal sets and identical scores to two
corpus malware samples: 30.8 and 17.0, matching pair for pair. A SOC's own
compliance library scored the same as the malware it is meant to be compared
against.

This does not touch the PDF analyzer's real evidence -- JavaScript, an
OpenAction, an embedded file all still fire. It removes one signal that could
only ever be true.
"""
from __future__ import annotations

import pytest

from app.engine.analyzers.generic import _entropy_is_meaningful


class _Sample:
    """Only the two attributes the predicate reads."""

    def __init__(self, mime: str) -> None:
        self.mime = mime


#: Containers whose bytes are compressed by construction. Whole-file entropy is a
#: fact about the format, not about the sample.
COMPRESSED_BY_DESIGN = [
    ("application/pdf", "pdf"),
    ("application/zip", "archive"),
    ("application/gzip", "archive"),
    ("application/x-7z-compressed", "archive"),
    ("image/png", "image"),
    ("image/jpeg", "image"),
    ("video/mp4", "video"),
    ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "office"),
]


@pytest.mark.parametrize("mime,family", COMPRESSED_BY_DESIGN)
def test_whole_file_entropy_says_nothing_here(mime, family) -> None:
    assert _entropy_is_meaningful(_Sample(mime), family) is False


#: Formats that are NOT compressed by design, where near-8.00 entropy is real
#: evidence of packing. The exemption must not have swallowed these.
MEANINGFUL = [
    ("application/x-dosexec", "pe"),
    ("application/x-executable", "elf"),
    ("text/plain", "script"),
    ("application/x-msdownload", "pe"),
]


@pytest.mark.parametrize("mime,family", MEANINGFUL)
def test_entropy_still_means_something_on_an_executable(mime, family) -> None:
    assert _entropy_is_meaningful(_Sample(mime), family) is True


def test_a_pdf_is_exempt_by_family_even_if_the_mime_is_missing() -> None:
    """Identification can produce a family without a usable MIME."""
    assert _entropy_is_meaningful(_Sample(""), "pdf") is False


def test_a_pdf_is_exempt_by_mime_even_if_the_family_is_missing() -> None:
    """...and the reverse, when identification failed but libmagic did not."""
    assert _entropy_is_meaningful(_Sample("application/pdf"), "") is False


def test_the_mime_check_is_case_insensitive() -> None:
    assert _entropy_is_meaningful(_Sample("Application/PDF"), "") is False
