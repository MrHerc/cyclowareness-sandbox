"""Regression against a real detonation, using the sandbox's real output.

`data/wannacry_signatures.json` is the verbatim signature list CAPEv2 2.5
produced on our own guest for
``ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa`` — 68
signatures with their severities and categories. It is a fixture rather than a
hand-written list because hand-written ids are exactly what hid the bug: matching
capabilities by signature *name* left **50 of these 68 unmapped**, since a
sandbox writes ``unbacked_process_creation`` where a developer writes
``process_create`` and ``antivm_checks_available_memory`` where a developer
writes ``anti_vm``.

Reading the ``categories`` the sandbox already attaches takes that to 11, and the
eleven that remain are categorised ``generic`` / ``malware`` / ``lateral`` or
carry no category at all — correctly unmapped, because inventing a capability for
them would put a claim in a report that the evidence does not support.

What this file guards:

* coverage does not silently regress toward name-guessing again;
* ransomware is scored destructive on any of its tells, not one lucky one;
* the rating reflects it, on both availability and confidentiality;
* and none of it fires on ordinary behaviour.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.engine import capabilities
from app.engine.contracts import Signal

FIXTURE = Path(__file__).parent / "data" / "wannacry_signatures.json"
_CAPE_SEVERITY = {0: "info", 1: "low", 2: "medium", 3: "high"}


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _load() -> list[Signal]:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))["signatures"]
    out = []
    for s in raw:
        sev = _CAPE_SEVERITY.get(min(int(s.get("severity") or 1), 3), "low")
        out.append(
            Signal(
                id=f"capev2.{_slug(s['name'])}",
                title=s["name"],
                severity=sev,
                detail="",
                evidence={"categories": s.get("categories") or []},
            )
        )
    return out


@pytest.fixture(scope="module")
def wannacry() -> list[Signal]:
    return _load()


def test_the_fixture_is_the_real_thing(wannacry) -> None:
    meta = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert meta["_sample_sha256"] == (
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
    )
    assert len(wannacry) == 68


def test_most_signals_map_to_a_capability(wannacry) -> None:
    """Name-guessing left 50 of 68 unmapped. That must not come back."""
    scored = [s for s in wannacry if capabilities.SEVERITY_ORDER.get(s.severity, 0) >= 1]
    unmapped = [s for s in scored if not capabilities.detect([s])]
    assert len(unmapped) <= 12, (
        f"{len(unmapped)}/{len(scored)} signals demonstrate no capability: "
        + ", ".join(s.title for s in unmapped[:15])
    )


def test_what_remains_unmapped_is_genuinely_generic(wannacry) -> None:
    """The leftovers must be uninformative categories, not real evidence we drop."""
    allowed = {"generic", "malware", "lateral", "command", "static", "ipc", ""}
    for s in wannacry:
        if capabilities.detect([s]):
            continue
        if capabilities.SEVERITY_ORDER.get(s.severity, 0) < 1:
            continue
        cats = {c.lower() for c in (s.evidence or {}).get("categories", [])} or {""}
        assert cats <= allowed, f"{s.title} dropped despite categories {sorted(cats)}"


def test_the_detonation_yields_the_expected_capabilities(wannacry) -> None:
    caps = capabilities.detect(wannacry)
    for expected in (
        "destruction",
        "credential",
        "persistence",
        "network",
        "discovery",
        "evasion",
        "execution",
        "injection",
    ):
        assert expected in caps, f"missing {expected}; got {sorted(caps)}"


def test_the_sandbox_category_is_what_carries_it(wannacry) -> None:
    """Strip the categories and coverage must collapse — proving where it comes from."""
    stripped = [
        Signal(id=s.id, title=s.title, severity=s.severity, detail="", evidence={})
        for s in wannacry
    ]
    assert len(capabilities.detect(stripped)) < len(capabilities.detect(wannacry))


# --- ransomware specifically -------------------------------------------------


@pytest.mark.parametrize(
    "name,categories",
    [
        ("ransomware_file_modifications", ["ransomware"]),
        ("mass_data_encryption", ["ransomware"]),
        ("deletes_shadow_copies", ["wiper"]),
        ("mass_ransom_note_drop", ["ransomware"]),
        ("ransomware_message", ["ransomware"]),
        ("deletes_system_state_backup", ["wiper"]),
    ],
)
def test_each_ransomware_tell_alone_proves_destruction(name, categories) -> None:
    """Relying on the ransom note was the bug: a variant without one scored none."""
    sig = Signal(
        id=f"capev2.{name}", title=name, severity="high", detail="",
        evidence={"categories": categories},
    )
    assert "destruction" in capabilities.detect([sig]), name


def test_observed_credential_theft_is_recognised() -> None:
    for name in ("infostealer_browser", "infostealer_cookies"):
        sig = Signal(id=f"capev2.{name}", title=name, severity="high", detail="",
                     evidence={"categories": ["infostealer"]})
        assert "credential" in capabilities.detect([sig]), name


def test_the_rating_reflects_what_ransomware_does(wannacry) -> None:
    from app.engine import impact

    data = impact.assess("pe", wannacry, None).to_dict()
    assert data["base_score"] >= 7.0, f"ransomware rated {data['base_score']}"
    assert data["severity"] in ("high", "critical")
    assert "/A:H" in data["vector"], f"availability not High: {data['vector']}"
    assert "/C:H" in data["vector"], f"confidentiality not High: {data['vector']}"


# --- and none of it on ordinary software -------------------------------------


def test_the_severity_gate_still_applies() -> None:
    sig = Signal(id="capev2.ransomware_file_modifications", title="x", severity="info",
                 detail="", evidence={"categories": ["ransomware"]})
    assert "destruction" not in capabilities.detect([sig])


@pytest.mark.parametrize(
    "categories",
    [["generic"], ["malware"], ["lateral"], ["static"], [], ["unheard-of-category"]],
)
def test_uninformative_categories_claim_nothing(categories) -> None:
    sig = Signal(id="capev2.some_observation", title="x", severity="high", detail="",
                 evidence={"categories": categories})
    assert capabilities.detect([sig]) == set()


@pytest.mark.parametrize(
    "name",
    [
        "capev2.queries_computer_name",
        "capev2.accesses_public_folder",
        "capev2.file_written",
        "capev2.backup_service_query",
        "capev2.shadow_volume_query_read_only",
    ],
)
def test_broadened_tokens_do_not_invent_destruction(name: str) -> None:
    sig = Signal(id=name, title=name, severity="high", detail="", evidence={})
    assert "destruction" not in capabilities.detect([sig])
