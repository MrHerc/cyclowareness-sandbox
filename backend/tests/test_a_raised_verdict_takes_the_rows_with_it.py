"""A container's panel must not show two names for one file.

`classify()` stamps every row that reports a detection with the sample's threat
name — its own comment states that rule. `raised_to()` then rebuilds the name
when a container inherits a worse verdict from a member, and it used to leave the
rows behind. Measured on the live deployment, one panel carried both at once:

    headline             Archive.Malware.PowershellDownloadCr
    CS-archive-contents  Archive.Suspicious.PowershellDownloadCr

Found by walking the deployed interface, not by a unit test — the two strings sit
about four inches apart on the report page.
"""
from __future__ import annotations

from app.engine.verdict import VerdictResult


def _panel() -> VerdictResult:
    """A container classified on its own evidence, before any inheritance."""
    return VerdictResult(
        verdict="suspicious",
        threat_name="Archive.Suspicious.PowershellDownloadCr",
        detection_ratio="2 / 7",
        detected=2,
        total_engines=7,
        platform="Archive",
        category="Suspicious",
        family="PowershellDownloadCr",
        engines=[
            {"engine": "CS-Static/Generic", "detected": False, "result": "undetected"},
            {
                "engine": "CS-YARA/powershell_download_cradle",
                "detected": True,
                # A YARA row carries the matched RULE's description, not the
                # sample's name. `classify` leaves it alone and so must this.
                "result": "PowerShell download-and-execute cradle (WebClient / IWR + IEX)",
            },
            {
                "engine": "CS-archive-contents",
                "detected": True,
                "result": "Archive.Suspicious.PowershellDownloadCr",
            },
        ],
    )


def test_the_rows_follow_the_raised_name() -> None:
    """The finding, exactly."""
    raised = _panel().raised_to("malicious", because="update.ps1 was assessed malicious.")

    assert raised.threat_name == "Archive.Malware.PowershellDownloadCr"
    stamped = [r for r in raised.engines if r["engine"] == "CS-archive-contents"]
    assert stamped[0]["result"] == raised.threat_name, raised.engines


def test_no_row_keeps_the_pre_raise_name() -> None:
    """The whole panel, not just the row this test happens to name."""
    before = _panel()
    raised = before.raised_to("malicious", because="x")
    assert before.threat_name not in [r["result"] for r in raised.engines]


def test_a_yara_row_keeps_the_rule_description() -> None:
    """Its `result` is a different and more useful thing than the sample's name,
    and overwriting it would lose the only place the rule explains itself."""
    raised = _panel().raised_to("malicious", because="x")
    yara = [r for r in raised.engines if r["engine"].startswith("CS-YARA")][0]
    assert yara["result"] == "PowerShell download-and-execute cradle (WebClient / IWR + IEX)"


def test_an_undetected_row_is_left_alone() -> None:
    """A row that cleared the sample is not reporting a name, and stamping one
    onto it would read as a detection."""
    raised = _panel().raised_to("malicious", because="x")
    generic = [r for r in raised.engines if r["engine"] == "CS-Static/Generic"][0]
    assert generic["result"] == "undetected"
    assert generic["detected"] is False


def test_the_original_is_not_mutated() -> None:
    """`raised_to` returns a new result; the rows must not be shared with it, or
    a caller that keeps the pre-raise panel finds it silently rewritten."""
    before = _panel()
    rows_before = [dict(r) for r in before.engines]
    before.raised_to("malicious", because="x")
    assert [dict(r) for r in before.engines] == rows_before


def test_the_reason_travels_and_is_bounded() -> None:
    raised = _panel().raised_to("malicious", because="m" * 500)
    assert raised.raised_because.startswith("m")
    assert len(raised.raised_because) == 300


def test_a_suspicious_raise_names_the_right_category() -> None:
    """A clean container inheriting `suspicious` gets `Suspicious`, not `Malware`."""
    clean = VerdictResult(
        verdict="clean", threat_name="Archive.Clean", detection_ratio="0 / 3",
        detected=0, total_engines=3, platform="Archive", category="Clean",
        family="Gen",
        engines=[{"engine": "CS-Static/Archive", "detected": False, "result": "undetected"}],
    )
    raised = clean.raised_to("suspicious", because="a member was suspicious")
    assert raised.threat_name == "Archive.Suspicious.Gen"
    assert raised.category == "Suspicious"
