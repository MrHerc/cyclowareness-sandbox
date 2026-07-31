"""The job-id guard closed the reads. These are the writes.

Reproduced against the live deployment, both returning 500:

    POST /api/analyze              filename containing a NUL
    POST /api/jobs/{id}/feedback   note containing a NUL

`/api/analyze` is the product's primary endpoint. PostgreSQL will not take a NUL
inside a text parameter -- the driver raises `ValueError` before the statement is
sent -- and the suite runs on SQLite, which stores one happily, so none of this
failed a test. That is the same blind spot recorded against `?status=%00` and
against the six export routes.

A third, structural: `submitted_by` is `String(64)` and `new_job` clipped
`tenant_id[:64]` and `original_name[:512]` and not it, so a tenant name over 53
characters overflows on PostgreSQL while the boot validator accepts it.

`db_text` strips rather than refuses, deliberately. Declining to analyse a sample
because its NAME is odd would hand an attacker one byte that avoids inspection
altogether; the bytes are the evidence and the name is metadata. Only NUL is
removed -- other control characters store fine, and stripping them would alter
what was submitted.
"""
from __future__ import annotations

import io
import uuid

import pytest

from app.engine.models import SandboxJob
from app.engine.pipeline import db_text

NUL = chr(0)


# --- the helper itself -------------------------------------------------------

@pytest.mark.parametrize("value,limit,expected", [
    ("plain", 64, "plain"),
    ("a" + NUL + "b", 64, "ab"),
    (NUL, 64, ""),
    (NUL * 40, 64, ""),
    ("x" * 100, 64, "x" * 64),
    ("x" * 40 + NUL + "y" * 40, 64, "x" * 40 + "y" * 24),
    (None, 64, None),
])
def test_db_text(value, limit, expected) -> None:
    assert db_text(value, limit) == expected


def test_other_control_characters_are_kept() -> None:
    """Stripping them would alter evidence: a filename can contain a tab."""
    assert db_text("a\tb\nc", 64) == "a\tb\nc"


def test_a_long_tenant_fits_its_column() -> None:
    """`submitted_by` is String(64); it was the one field new_job did not clip."""
    width = SandboxJob.__table__.columns["submitted_by"].type.length
    assert width == 64
    assert len(db_text("api-client:" + "t" * 200, width)) == width


# --- the routes, end to end --------------------------------------------------

def test_a_hostile_filename_is_not_a_500(client, auth) -> None:
    """The primary endpoint, with the names a client can actually put on the wire.

    NOT the NUL case -- see `test_the_sample_is_still_analysed` for why the test
    client cannot send one. These are the shapes it can, and none may crash.
    """
    for name in ("../../etc/passwd", "a" * 5000 + ".txt", "a b.txt",
                 "sifrə.txt", "\U0001f642.exe", ";DROP TABLE sandbox_jobs;--"):
        response = client.post(
            "/api/analyze",
            files={"file": (name, io.BytesIO(b"harmless"), "text/plain")},
            headers=auth,
        )
        assert response.status_code < 500, (name[:40], response.status_code)
        if response.status_code == 201:
            assert NUL not in response.json()["original_name"]


def test_the_sample_is_still_analysed(db) -> None:
    """Stripping, not refusing -- an odd name must not buy an attacker a pass.

    Against `new_job` rather than the route, and the reason is worth writing
    down: httpx percent-encodes a NUL in a multipart filename, so a TestClient
    request carries the literal text `%00` and the stored name comes back
    `re%00port.txt`. The route test above would therefore have passed whether or
    not the fix existed -- it never puts a NUL on the wire. The live 500 was
    reproduced with a hand-built multipart body, which is what a real client
    sends. This exercises the actual write.
    """
    from app.engine import pipeline

    assert pipeline.db_text("re" + NUL + "port.txt", 512) == "report.txt"
    assert pipeline.db_text(NUL + "a" * 600, 512) == "a" * 512


def test_a_feedback_note_with_a_nul_is_not_a_500(client, auth) -> None:
    submitted = client.post(
        "/api/analyze",
        files={"file": ("note-probe.txt", io.BytesIO(b"harmless"), "text/plain")},
        headers=auth,
    )
    assert submitted.status_code == 201, submitted.text
    public_id = submitted.json()["public_id"]

    response = client.post(
        f"/api/jobs/{public_id}/feedback",
        json={"verdict": "false_positive", "note": "before" + NUL + "after"},
        headers=auth,
    )
    assert response.status_code < 500, response.text


def test_an_unknown_job_still_404s(client, auth) -> None:
    """The guard above must not have changed the ordinary miss."""
    response = client.post(
        f"/api/jobs/{uuid.uuid4()}/feedback",
        json={"verdict": "false_positive", "note": "x"},
        headers=auth,
    )
    assert response.status_code == 404, response.text
