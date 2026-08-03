"""A trace that is shown and not believed has to say so — on every surface.

The engine had four separate rules for refusing to conclude from a detonation,
and not one of them left a mark a reader could find. On the nine ELF jobs that
have really detonated on the live deployment, no surface — the JSON API, the
React UI, the PDF case file, the STIX bundle, the DORA/NIS2 record or the
Ed25519-signed evidence — contained a word about calibration.

AND THE ROWS DO NOT LOOK DEMOTED. `effective_severity` is a scoring function: it
does not rewrite the stored signal, and it must not, because CAPE reported
`deletes_files` at severity 3 and a signed artifact has to keep saying so. So the
PDF prints

    [high] Deletes files from disk

in the exported case file while that same row contributes 0.0 to the score, names
no capability, sets no verdict and maps to no technique — and nothing anywhere
connected the two. A reader has no way to tell a suppressed finding from a
counted one.

The regulatory record was worse than silent. `incident._evidence` fell back to
the literal "All configured analysis tiers ran." Every tier HAD run. The sentence
was true and the impression it left was not.

One test per surface, because the failure mode this file exists to prevent is
fixing one and believing that fixed the rest.
"""
from __future__ import annotations

import pytest

from app.engine import incident, report as report_mod, scoring
from app.engine.contracts import Signal

DELETES = Signal(id="capev2.deletes_files", title="Deletes files from disk",
                 severity="high", detail="", evidence={})
STEALTH = Signal(id="capev2.stealth_network", title="Network without a network call",
                 severity="high", detail="", evidence={})
STATIC = Signal(id="elf.packed", title="Packed", severity="high", detail="", evidence={})


class _Job:
    """The shape the report/incident builders read. Not a SQLAlchemy row: these
    functions take `getattr`-style duck types everywhere, and a real row would
    drag a database into a test about sentences."""

    def __init__(self, breakdown):
        self.score_breakdown = breakdown
        self.tiers = {
            "static": {"ran": True, "detail": "Parsers and YARA."},
            "dynamic": {"ran": True, "detail": "Detonated on the capev2 worker."},
        }
        self.family = "elf"
        self.analysis = {}
        self.iocs = {}
        self.sample_deleted_at = None


def _note():
    return scoring.uncalibrated_note("elf", [STATIC, DELETES, STEALTH])


# ---------------------------------------------------------------- the builder


def test_an_uncalibrated_platform_produces_a_note() -> None:
    note = _note()
    assert note is not None
    assert note["family"] == "elf"
    #: The two dynamic ids, not the static one.
    assert note["signal_count"] == 2, note
    assert "not yet measured" in note["reason"] or "has not yet measured" in note["reason"]


def test_a_calibrated_platform_produces_none() -> None:
    """No note on PE, and no note on an ELF with nothing dynamic to gag."""
    assert scoring.uncalibrated_note("pe", [STATIC, DELETES, STEALTH]) is None
    assert scoring.uncalibrated_note("elf", [STATIC]) is None


def test_the_note_does_not_call_the_evidence_unreliable() -> None:
    """Wording matters here more than usual. The signals are real observations;
    the deployment simply has not measured them against benign software. An
    analyst who reads "unreliable" stops reading the trace, and 5 of the 9 live
    ELF jobs would be `medium` if the trace counted."""
    reason = _note()["reason"].lower()
    for word in ("unreliable", "false", "wrong", "ignore"):
        assert word not in reason, f"{word!r} in: {reason}"
    assert "recorded in full" in reason


def test_the_note_warns_that_the_rows_still_read_high() -> None:
    """The specific confusion this exists to prevent."""
    reason = _note()["reason"].lower()
    assert "medium or high" in reason, reason


# ---------------------------------------------------------------- the surfaces


def test_the_caveat_reaches_the_shared_prose_helper() -> None:
    job = _Job({"dynamic_uncalibrated": _note()})
    caveats = report_mod._tier_caveats(job)
    assert any("not yet measured" in c or "has not yet measured" in c for c in caveats), caveats


def test_stix_carries_it_with_no_further_change() -> None:
    """`as_stix` is the other consumer of `_tier_caveats`; it should have needed
    no edit at all. Asserted rather than assumed."""
    job = _Job({"dynamic_uncalibrated": _note()})
    assert report_mod._excluded_tier_caveats(job), "the helper STIX joins must be non-empty"


def test_the_regulatory_record_stops_claiming_completeness() -> None:
    """The export designed to be handed to a regulator is the last place an
    unstated exclusion belongs."""
    job = _Job({"dynamic_uncalibrated": _note()})
    limitations = incident._evidence(job)["limitations"]
    assert "All configured analysis tiers ran." not in limitations, limitations
    assert any("excluded from the score" in line for line in limitations), limitations


def test_a_clean_job_still_says_every_tier_ran() -> None:
    """The fallback is correct when it is correct. Removing it entirely would
    trade one wrong impression for another."""
    assert incident._evidence(_Job({}))["limitations"] == ["All configured analysis tiers ran."]


def test_the_other_axis_uses_the_same_road() -> None:
    """`dynamic_not_attributable` has been written to `score_breakdown` for a
    while and reached the JSON API and the signed bundle only, because those two
    dump the breakdown verbatim. It now travels with its sibling."""
    job = _Job({
        "dynamic_not_attributable": {
            "claimed_extension": "", "mime": "text/html",
            "reason": "Windows has no way to run a file of this type, so everything "
                      "the guest was observed doing belongs to the guest.",
        }
    })
    assert any("belongs to the guest" in c for c in report_mod._tier_caveats(job))
    assert any("belongs to the guest" in line
               for line in incident._evidence(job)["limitations"])


@pytest.mark.parametrize("key", ["dynamic_uncalibrated", "dynamic_not_attributable"])
def test_both_keys_are_in_the_shared_tuple(key: str) -> None:
    """One list, so a third axis cannot be added to the engine and forgotten by
    every renderer — which is exactly how the first two got here."""
    assert key in report_mod._RAN_BUT_EXCLUDED_KEYS


def test_the_severities_are_not_rewritten() -> None:
    """NOT proposed and never to be: forcing the stored rows to `info` would
    falsify the evidence. CAPE said severity 3; the signed bundle keeps saying
    so, and the report explains it instead."""
    before = DELETES.severity
    scoring.uncalibrated_note("elf", [DELETES])
    scoring.effective_severity(DELETES, family="elf")
    assert DELETES.severity == before == "high"
