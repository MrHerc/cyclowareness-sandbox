"""Does the dynamic tier tell malware apart from software? Measured, on real runs.

`data/detonation_corpus.json` is eleven real CAPEv2 detonations from our own
host: eight malware (WannaCry, Locky, AgentTesla, Emotet, Zeus, njRAT, and two
samples pulled from MalwareBazaar the day they were seen) and three signed,
current releases downloaded from their vendors — the 7-Zip, Notepad++ and PuTTY
installers. VirusTotal's ratio that day is recorded alongside as an independent
opinion.

This file exists because the first honest measurement of the dynamic tier was
bad enough to invalidate it. Before the fixes these tests lock in:

    7-Zip installer   CIR 8.3  "Win32.Ransom.HardwareIdProfiling"   malicious
    WannaCry          CIR 8.3  "Win32.Ransom.HardwareIdProfiling"   malicious

A signed archiver was rated identically to ransomware, given a `destruction`
capability, and named after a random signal. Meanwhile real Locky scored 0.0,
because its C2 was dead so it never encrypted anything.

Three things caused it, and each is now guarded here:

* a sandbox categorises a signature by the threat class it helps *detect*, not
  by what it proves — `mountpoint_manager_access` is filed under `ransomware`
  because ransomware enumerates volumes, and so does every installer;
* "we detected something" fired on any capability at all, including discovery,
  which every program performs;
* identification (a named family, an extracted config, a YARA hit in process
  memory) was thrown away, and it is the one signal that separated the corpus
  cleanly — 8/8 malware, 0/3 benign, where the sandbox's own aggregate score did
  not separate them at all (7-Zip scored 9.0, higher than Locky's 8.0).

Eleven samples is a small corpus and these thresholds are tuned against it, so
treat a failure as "look at the evidence again", not "adjust the number".
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.engine import capabilities, impact, scoring, verdict
from app.engine.contracts import IOCs, AnalyzerResult, Signal

CORPUS = Path(__file__).parent / "data" / "detonation_corpus.json"
_CAPE_SEVERITY = {0: "info", 1: "low", 2: "medium", 3: "high"}


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")


def _signals(sample: dict) -> list[Signal]:
    out = [
        Signal(
            id=f"capev2.{_slug(s['name'])}",
            title=s["name"],
            severity=_CAPE_SEVERITY.get(min(int(s.get("severity") or 1), 3), "low"),
            detail="",
            evidence={"categories": s.get("categories") or []},
        )
        for s in sample["signatures"]
    ]
    for family in sample.get("families") or []:
        out.append(Signal(
            id=f"capev2.detection.{_slug(family)}",
            title=f"Identified as {family}", severity="critical", detail="",
            evidence={"family": family, "categories": ["identification"]},
        ))
    for cfg in sample.get("configs") or []:
        out.append(Signal(
            id=f"capev2.config.{_slug(cfg)}",
            title=f"{cfg} configuration extracted", severity="critical", detail="",
            evidence={"family": cfg, "categories": ["identification"]},
        ))
    return out


def _assess(sample: dict) -> dict:
    signals = _signals(sample)
    results = [AnalyzerResult(
        analyzer="dynamic.capev2", ran=True, signals=signals, facts={}, iocs=IOCs()
    )]
    risk = scoring.assess(results, ioc_total=0)
    return {
        "caps": capabilities.detect(signals),
        "impact": impact.assess("pe", signals, None).to_dict(),
        "verdict": verdict.classify(
            "pe", "application/x-dosexec", results, None, risk.final_score
        ).to_dict(),
        "risk": risk.final_score,
    }


CORPUS_DATA = json.loads(CORPUS.read_text(encoding="utf-8"))["samples"]
MALWARE = [s for s in CORPUS_DATA if s["kind"] == "malware"]
BENIGN = [s for s in CORPUS_DATA if s["kind"] == "benign"]


def _ids(samples):
    return [s["name"] for s in samples]


def test_the_corpus_is_what_it_claims_to_be() -> None:
    assert len(MALWARE) == 8 and len(BENIGN) == 3
    # If VirusTotal disagreed with our labelling, the corpus itself is wrong.
    for s in MALWARE:
        hit, total = (int(x) for x in s["virustotal"].split("/"))
        assert hit >= 20, f"{s['name']} is labelled malware but VT says {s['virustotal']}"
    for s in BENIGN:
        hit, _ = (int(x) for x in s["virustotal"].split("/"))
        assert hit <= 1, f"{s['name']} is labelled benign but VT says {s['virustotal']}"


# --- the headline claim ------------------------------------------------------


@pytest.mark.parametrize("sample", MALWARE, ids=_ids(MALWARE))
def test_every_malware_sample_is_called_malicious(sample) -> None:
    assert _assess(sample)["verdict"]["verdict"] == "malicious"


@pytest.mark.parametrize("sample", BENIGN, ids=_ids(BENIGN))
def test_no_signed_installer_is_called_malicious(sample) -> None:
    """The failure that makes a sandbox unusable: flagging ordinary software."""
    got = _assess(sample)["verdict"]["verdict"]
    assert got != "malicious", f"{sample['name']} (VT {sample['virustotal']}) -> {got}"


# --- and the reasons hold up -------------------------------------------------


@pytest.mark.parametrize("sample", BENIGN, ids=_ids(BENIGN))
def test_no_installer_is_accused_of_a_high_consequence_capability(sample) -> None:
    """Destruction, credential theft, exploitation and injection are accusations."""
    accused = _assess(sample)["caps"] & capabilities.HIGH_CONSEQUENCE
    assert not accused, f"{sample['name']} accused of {sorted(accused)}"


@pytest.mark.parametrize("sample", BENIGN, ids=_ids(BENIGN))
def test_installers_are_not_rated_as_severe_as_ransomware(sample) -> None:
    assert _assess(sample)["impact"]["base_score"] < 7.0


def test_ransomware_is_rated_severe_on_availability() -> None:
    wannacry = next(s for s in MALWARE if "WannaCry" in s["name"])
    data = _assess(wannacry)["impact"]
    assert data["base_score"] >= 7.0
    assert "/A:H" in data["vector"]
    assert "destruction" in _assess(wannacry)["caps"]


def test_a_named_family_becomes_the_threat_name() -> None:
    """Not a random signal: a real WannaCry run was `Ransom.HardwareIdProfiling`."""
    for name, expected in (("WannaCry", "WanaCry"), ("AgentTesla", "AgentTesla"),
                           ("njRAT", "Njrat"), ("Formbook", "Formbook")):
        sample = next(s for s in MALWARE if name in s["name"])
        assert expected in _assess(sample)["verdict"]["threat_name"]


def test_a_sample_that_never_ran_is_still_identified() -> None:
    """Locky's C2 was dead, so it encrypted nothing: no capability, CIR 0.0.

    Behaviour alone therefore misses it entirely. The sandbox still matched it in
    process memory, and that is what has to carry the verdict.
    """
    locky = next(s for s in MALWARE if "Locky" in s["name"])
    result = _assess(locky)
    assert not (result["caps"] & capabilities.HIGH_CONSEQUENCE)
    assert result["impact"]["base_score"] == 0.0
    assert result["verdict"]["verdict"] == "malicious"


def test_identification_separates_the_corpus_completely() -> None:
    """8/8 and 0/3 — the only signal in the report that did."""
    def identified(sample):
        engines = _assess(sample)["verdict"]["engines"]
        return any(e["engine"] == "CS-SandboxID" and e["detected"] for e in engines)

    assert all(identified(s) for s in MALWARE)
    assert not any(identified(s) for s in BENIGN)
