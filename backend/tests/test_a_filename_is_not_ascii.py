"""People name files in their own language, and the PDF export 500'd on it.

Found by uploading nine files the way a customer would. Eight were fine. The
ninth was called `raport-2026-ə-ü.txt`, and `GET …/export.pdf` answered **500**
while every other export of the same job answered 200.

HTTP header values are latin-1. The sanitiser kept any character for which
`str.isalnum()` is true, and `str.isalnum()` is true for `ə`, for `ж`, for `文` —
Python is right that those are letters, and latin-1 has nowhere to put them. So
`Content-Disposition` was built with a character that cannot be encoded, and
Starlette raised while constructing the response.

This deployment is being built for Azerbaijani users. `ə` is in the alphabet.

Two names go out now, per RFC 6266: `filename*` with the real one as
percent-encoded UTF-8, and an ASCII `filename=` for older clients. The ASCII
reduction is also what makes header injection impossible.
"""
from __future__ import annotations

import pytest

from app.api.sandbox import _attachment
from tests.test_api import _poll_until_done, _submit

NAMES = [
    "raport-2026-ə-ü.txt",            # Azerbaijani
    "отчёт.txt",                       # Cyrillic
    "报告.txt",                         # Chinese
    "rapport-été.txt",                 # French
    "naïve café.txt",                  # spaces and diacritics
    "🔥.txt",                           # emoji
    "ﬁle​with​zwsp.txt",     # zero-width joiners
]


@pytest.mark.parametrize("name", NAMES)
def test_every_export_works_whatever_the_file_is_called(client, auth, name) -> None:
    public_id = _submit(client, auth, name, b"# a note\nnothing to see here\n")
    _poll_until_done(client, auth, public_id)
    for export in ("export.json", "export.stix", "export.pdf", "export.incident", "export.signed"):
        response = client.get(f"/api/jobs/{public_id}/{export}", headers=auth)
        assert response.status_code == 200, (
            f"{name!r} -> {export} -> {response.status_code}"
        )
        assert response.content, f"{name!r} -> {export} returned nothing"


@pytest.mark.parametrize("name", NAMES)
def test_the_header_is_encodable_and_carries_the_real_name(name) -> None:
    value = _attachment(name, "fallback-id", ".pdf")
    # The property Starlette needs and the old code broke.
    value.encode("latin-1")
    assert "filename*=UTF-8''" in value
    assert 'filename="sandbox-' in value


# --- and a name is attacker-controlled --------------------------------------


@pytest.mark.parametrize("name", [
    'evil"; filename="pwned.exe',
    "evil\r\nX-Injected: yes",
    "evil\nSet-Cookie: session=stolen",
    "../../../../etc/passwd",
    "a" * 500 + ".txt",
    "",
])
def test_a_hostile_name_cannot_shape_the_header(name) -> None:
    """`original_name` comes from the multipart body, so it is whatever the
    submitter typed. A quote would end the quoted string early and a CRLF would
    start a header of the attacker's choosing."""
    value = _attachment(name, "fallback-id", ".pdf")
    value.encode("latin-1")
    ascii_part = value.split(";")[1]
    assert "\r" not in value and "\n" not in value
    assert ascii_part.count('"') == 2, ascii_part
    assert "/" not in ascii_part and ".." not in ascii_part
    assert len(ascii_part) < 100, "an unbounded name makes an unbounded header"


def test_an_unnamed_job_still_gets_a_filename() -> None:
    assert 'filename="sandbox-fallback-id.pdf"' in _attachment(None, "fallback-id", ".pdf")
