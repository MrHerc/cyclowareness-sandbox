"""Reading CAPE's refusal — the reason is in the response, not in `error_value`.

Every refusal on the submission path answers with the same generic string,
whatever the cause:

    {"error": true, "error_value": "Error adding task to database"}

There are at least a dozen distinct causes behind it (`web_utils.py`: empty
file, over the size limit, duplicate hash, unwritable temp path, disabled
platform, a machine whose platform disagrees with the sample). CAPE does not log
which — `web_utils.py:916`, the one that refused our eight ELF samples, is a
bare `return` with no log call. The only place the answer exists is the sibling
`errors` array, and the client dropped it.

The payloads below are the real shapes, captured from this deployment.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

WORKER = Path(__file__).resolve().parents[2] / "worker"


@pytest.fixture()
def cape():
    sys.path.insert(0, str(WORKER))
    try:
        from engines.opensource import CapeV2Engine  # type: ignore

        yield CapeV2Engine
    finally:
        sys.path.remove(str(WORKER))


def test_the_real_reason_survives_unwrapping(cape) -> None:
    """Captured verbatim from this host, submitting an ELF to CAPE's API."""
    payload = {
        "error": True,
        "error_value": "Error adding task to database",
        "errors": [
            {"6d6f62080ab1efc1e777.elf": {"error": "Linux binaries analysis isn't enabled"}}
        ],
    }
    data, err = cape._unwrap(payload)
    assert data is None
    assert "Linux binaries analysis isn't enabled" in err, err
    # The generic half is kept too — it is what appears in CAPE's own logs and
    # in every other report of this failure, so it is the searchable term.
    assert "Error adding task to database" in err


def test_several_refusals_are_all_reported(cape) -> None:
    payload = {
        "error": True,
        "error_value": "Error adding task to database",
        "errors": [
            {"a.elf": {"error": "Linux binaries analysis isn't enabled"}},
            {"b.exe": {"error": "You uploaded an empty file."}},
        ],
    }
    _, err = cape._unwrap(payload)
    assert "Linux binaries" in err and "empty file" in err, err


def test_a_reason_is_never_repeated(cape) -> None:
    payload = {
        "error": True,
        "error_value": "Error adding task to database",
        "errors": [
            {"a.elf": {"error": "Error adding task to database"}},
        ],
    }
    _, err = cape._unwrap(payload)
    assert err.count("Error adding task to database") == 1, err


@pytest.mark.parametrize(
    "errors",
    [None, [], [{}], ["a bare string"], [{"a.elf": "a bare string"}], [{"a.elf": {}}]],
)
def test_a_malformed_errors_array_never_crashes_the_worker(cape, errors) -> None:
    """This runs on every failed submission; it must not be the thing that breaks."""
    data, err = cape._unwrap(
        {"error": True, "error_value": "Error adding task to database", "errors": errors}
    )
    assert data is None
    assert "Error adding task to database" in err


def test_success_is_untouched(cape) -> None:
    """`error` is `[]` on a successful create — truthiness, not presence."""
    data, err = cape._unwrap({"error": [], "data": {"task_ids": [42]}})
    assert err is None
    assert data == {"task_ids": [42]}
