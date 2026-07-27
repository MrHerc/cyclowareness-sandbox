"""Regression locked to a real detonation, not to an invented one.

Every signal id below was emitted by CAPEv2 on our own sandbox detonating the
canonical WannaCry sample
``ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa`` — 36
processes, 3 425 files written, 3 305 deleted, 68 signatures. Using the real
vocabulary matters: the capability model looked correct against hand-written
ids and missed almost all of these, because a sandbox writes
``deletes_shadow_copies`` where a developer writes ``delete_shadow``.

What this guards:

* Ransomware must be scored as destructive on *any* of its several tells, not on
  one that happened to match. A variant that drops no ransom note previously
  scored no destruction capability at all.
* Availability impact must reach the rating. Ransomware that does not move the
  A metric is a rating nobody should trust.
* And the whole thing must stay off benign software — the tokens are broad
  enough to be worth a false-positive guard of their own.
"""
from __future__ import annotations

import pytest

from app.engine import capabilities
from app.engine.contracts import Signal

#: The high-severity half of the real report, verbatim.
WANNACRY_SIGNAL_IDS = [
    "capev2.mass_data_encryption",
    "capev2.mass_file_modification_access",
    "capev2.ransomware_attribute_stripping",
    "capev2.ransomware_file_modifications",
    "capev2.mass_ransom_note_drop",
    "capev2.ransomware_message",
    "capev2.ransomware_files",
    "capev2.deletes_shadow_copies",
    "capev2.deletes_system_state_backup",
    "capev2.bcdedit_command",
    "capev2.modify_desktop_wallpaper",
    "capev2.persistence_autorun",
    "capev2.network_tor",
    "capev2.network_bind",
    "capev2.infostealer_browser",
    "capev2.infostealer_cookies",
    "capev2.recon_systeminfo",
    "capev2.unbacked_process_creation",
    "capev2.unbacked_crypto_operations",
    "capev2.stealth_file",
    "capev2.folder_enumeration",
    "capev2.hardware_id_profiling",
]


def _signals(ids, severity="high"):
    return [Signal(id=i, title=i, severity=severity, detail="", evidence={}) for i in ids]


@pytest.mark.parametrize(
    "signal_id",
    [
        "capev2.ransomware_file_modifications",
        "capev2.mass_data_encryption",
        "capev2.deletes_shadow_copies",
        "capev2.mass_ransom_note_drop",
        "capev2.ransomware_message",
        "capev2.ransomware_files",
        "capev2.deletes_system_state_backup",
        "capev2.ransomware_attribute_stripping",
    ],
)
def test_each_ransomware_tell_alone_proves_destruction(signal_id: str) -> None:
    """Any one of these is enough. Relying on the ransom note was the bug."""
    caps = capabilities.detect(_signals([signal_id]))
    assert "destruction" in caps, f"{signal_id} did not demonstrate destruction"


def test_the_real_report_yields_the_expected_capabilities() -> None:
    caps = capabilities.detect(_signals(WANNACRY_SIGNAL_IDS))
    for expected in ("destruction", "persistence", "network", "discovery"):
        assert expected in caps, f"missing {expected} from {sorted(caps)}"


def test_observed_credential_theft_is_recognised() -> None:
    """`infostealer_*` was the same whole-token miss as the destruction set."""
    for sid in ("capev2.infostealer_browser", "capev2.infostealer_cookies"):
        assert "credential" in capabilities.detect(_signals([sid])), sid


def test_destruction_reaches_the_impact_rating() -> None:
    from app.engine import impact

    data = impact.assess("pe", _signals(WANNACRY_SIGNAL_IDS), None).to_dict()
    assert data["base_score"] >= 7.0, f"ransomware rated {data['base_score']}"
    assert data["severity"] in ("high", "critical")
    # The two metrics ransomware-with-a-stealer exists to attack. Availability
    # was already right; confidentiality was N until `infostealer` was matched.
    assert "/A:H" in data["vector"], f"availability not High: {data['vector']}"
    assert "/C:H" in data["vector"], f"confidentiality not High: {data['vector']}"


def test_low_severity_behaviour_still_does_not_count() -> None:
    """The severity gate is what keeps the broadened tokens honest."""
    caps = capabilities.detect(_signals(["capev2.ransomware_file_modifications"], severity="info"))
    assert "destruction" not in caps


@pytest.mark.parametrize(
    "signal_id",
    [
        # Benign behaviour that mentions neighbouring words. None of these are
        # destruction, and the broadened tokens must not make them so.
        "capev2.uses_windows_utilities",
        "capev2.queries_computer_name",
        "capev2.accesses_public_folder",
        "capev2.crypto_api_usage",
        "capev2.file_written",
        "capev2.backup_service_query",
        "capev2.shadow_volume_query_read_only",
    ],
)
def test_broadened_tokens_do_not_fire_on_ordinary_behaviour(signal_id: str) -> None:
    assert "destruction" not in capabilities.detect(_signals([signal_id]))
