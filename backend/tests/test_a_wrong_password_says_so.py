"""A password that did not work is an answer, not a fresh prompt.

Walked end to end against the deployed image with a real encrypted zip:

    submit                 201
    status                 awaiting_password
    POST wrong password    200
    status                 awaiting_password, error = None   <-
    POST right password    200
    status                 completed, 1 member

The job returns to `awaiting_password` either way and nothing recorded which of
the two had happened, so the interface re-drew the same box. From the analyst's
side, typing the wrong password and clicking a dead button look identical — and
the natural conclusion is that the product is broken rather than that the
password is.

The password itself is still never stored. What is recorded is that one was
tried and did not open the archive.
"""
from __future__ import annotations

import pytest

from tests.test_api import _poll_until_done, _submit

#: 7z rather than zip. `zipfile` cannot WRITE an encrypted archive, and shelling
#: out to the `zip` binary made this file skip itself on any machine without it —
#: including the container the suite runs in, where it did exactly that and
#: proved nothing. `py7zr` is already a dependency of the archive analyzer, so
#: the archive is built by the same library that will be asked to open it.
py7zr = pytest.importorskip("py7zr")


def _encrypted_archive(tmp_path, password: str = "infected") -> bytes:
    inner = tmp_path / "inner.txt"
    inner.write_text("payload\n")
    archive = tmp_path / "locked.7z"
    with py7zr.SevenZipFile(archive, "w", password=password) as handle:
        handle.write(inner, "inner.txt")
    return archive.read_bytes()


def _until(client, auth, public_id, predicate, timeout=25.0):
    """Poll until `predicate(detail)`.

    `_poll_until_done` is no use here: the job is ALREADY in a terminal state
    (`awaiting_password`) when the password is posted, so it returns the old row
    before the re-run has even started.
    """
    import time

    deadline = time.time() + timeout
    detail = None
    while time.time() < deadline:
        detail = client.get(f"/api/result/{public_id}", headers=auth).json()
        if predicate(detail):
            return detail
        time.sleep(0.1)
    raise AssertionError(f"condition never held; last: status={detail and detail['status']} "
                         f"error={detail and detail.get('error')!r}")


def test_a_wrong_password_is_reported_and_a_right_one_still_works(client, auth, tmp_path) -> None:
    public_id = _submit(client, auth, "locked.7z", _encrypted_archive(tmp_path))
    detail = _poll_until_done(client, auth, public_id)
    assert detail["status"] == "awaiting_password", detail["status"]
    assert not detail["error"], "nothing has been tried yet, so there is nothing to report"

    assert client.post(
        f"/api/jobs/{public_id}/password", json={"password": "not-the-one"}, headers=auth
    ).status_code == 200
    detail = _until(client, auth, public_id, lambda d: bool(d.get("error")))
    assert detail["status"] == "awaiting_password", (
        "a wrong password must ask again, not finish the job — a 7z opened with the "
        "wrong password fails as LZMA corruption, which sent it down the "
        "container-could-not-be-inspected path and lost the prompt entirely"
    )
    assert "password" in detail["error"].lower(), detail["error"]

    assert client.post(
        f"/api/jobs/{public_id}/password", json={"password": "infected"}, headers=auth
    ).status_code == 200
    detail = _until(client, auth, public_id, lambda d: d["status"] == "completed")
    assert detail["children"], "the archive unlocked but produced no members"


def test_the_password_is_never_stored(client, auth, tmp_path) -> None:
    """It is used once. Nothing in the row, the analysis or the audit trail may
    carry it — an encrypted archive's password is often the customer's."""
    secret = "correct-horse-battery"
    public_id = _submit(client, auth, "locked.7z", _encrypted_archive(tmp_path, secret))
    _poll_until_done(client, auth, public_id)
    client.post(f"/api/jobs/{public_id}/password", json={"password": secret}, headers=auth)
    _until(client, auth, public_id, lambda d: d["status"] == "completed")

    body = client.get(f"/api/jobs/{public_id}/export.json", headers=auth).text
    assert secret not in body
    detail = client.get(f"/api/result/{public_id}", headers=auth).text
    assert secret not in detail
