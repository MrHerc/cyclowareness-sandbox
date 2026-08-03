"""An ATT&CK technique publishes the footing of its own claim.

`mitre.map_techniques` matches its rule table against the signal id AND the
signal's prose title, and the title is where a sandbox writes what a behaviour
*could* mean. Measured over 751 stored jobs: 1,012 of 4,551 assertions (22%)
rest on the description alone, and the descriptions doing it hedge --

    "Queried the FIPS cryptography policy, can be used to adapt C2 network
     behaviour"                                              -> T1071
    "Queries registry mount points to identify historical or
     connected removable drives"                             -> T1091
    "Performs high-volume NtQueryInformationToken calls"     -> T1486

the last one on PsInfo64.exe, which this engine calls clean.

TWO REPAIRS WERE MEASURED AND BOTH COST MORE THAN THE DEFECT.

    matching ids only          897-1105 techniques lost on MALICIOUS samples
    ignoring hedged titles     603 lost on MALICIOUS samples
    the bar this codebase set   28   (mitre.py:148; a severity gate was
                                      rejected at exactly that price)

The coverage genuinely rests on prose, so deleting prose deletes the mapping.
The claim is therefore kept and its footing is published, which is the move this
product makes everywhere else it cannot measure something: state the limit
rather than hide it.
"""
from __future__ import annotations

from app.engine import mitre
from app.engine.contracts import Signal


def _sig(sid: str, title: str) -> Signal:
    return Signal(id=sid, title=title, severity="medium", detail="", evidence={})


#: The real pair from the live deployment: the id says "FIPS policy query", the
#: prose says "can be used to adapt C2 network behaviour", and T1071 followed.
FIPS = _sig(
    "capev2.query_fips_reconnaissance",
    "Queried the FIPS cryptography policy, can be used to adapt C2 network behaviour",
)
#: The id itself carries the keyword ("upx"), so this one is id-backed.
PACKED = _sig("yara.upx_packed_executable", "Executable compressed with a known packer")
#: CORRECT, AND STILL PROSE-BACKED. `office.vba_present` maps to T1204.002 via
#: the keyword "macro", which appears only in the sentence -- the identifier says
#: `vba_present`. It is a mapping nobody would want to lose, and it is exactly
#: why the repair here is a label rather than a deletion.
MACROS = _sig("office.vba_present", "Document contains VBA macros")


def _by_id(techniques):
    return {t["technique_id"]: t for t in techniques}


def test_a_technique_from_prose_is_labelled_as_inferred() -> None:
    found = _by_id(mitre.map_techniques([FIPS]))
    assert "T1071" in found, "the claim is kept -- deleting it costs more than it saves"
    assert found["T1071"]["basis"] == "description", found["T1071"]


def test_a_technique_from_an_identifier_is_not() -> None:
    found = _by_id(mitre.map_techniques([PACKED]))
    assert found, "yara.upx_packed_executable must still map"
    for tid, t in found.items():
        assert t["basis"] == "signal-id", (tid, t)


def test_a_correct_mapping_can_still_be_prose_backed() -> None:
    """`basis` is not a quality score and must not be read as one.

    A document containing VBA macros really is T1204.002, and the only place the
    word "macro" appears is the sentence. Labelling it `description` says where
    the match came from, not that it is wrong -- which is the distinction the
    UI copy and the PDF sentence both have to preserve.
    """
    found = _by_id(mitre.map_techniques([MACROS]))
    assert "T1204.002" in found, found
    assert found["T1204.002"]["basis"] == "description", found["T1204.002"]


def test_one_identifier_promotes_the_whole_technique() -> None:
    """The strongest available footing wins. It is a property of the claim, not
    of whichever signal happened to be visited last -- so the same two signals
    in either order must produce the same basis."""
    both = [
        FIPS,
        _sig("capev2.c2_beacon_observed", "Beaconed to a command and control host"),
    ]
    forward = _by_id(mitre.map_techniques(both))
    backward = _by_id(mitre.map_techniques(list(reversed(both))))
    assert forward["T1071"]["basis"] == "signal-id", forward["T1071"]
    assert backward["T1071"]["basis"] == forward["T1071"]["basis"]


def test_every_technique_declares_a_basis() -> None:
    """Including the anti-analysis branch, which builds its entry separately.

    A field that is present on one code path and absent on another teaches a
    consumer to treat it as optional, and an optional disclosure is one nobody
    renders.
    """
    signals = [
        FIPS,
        MACROS,
        _sig("capev2.antidebug_setunhandledexceptionfilter", "Anti-debug via exception filter"),
        _sig("capev2.stealth_timeout", "Delayed execution"),
    ]
    for t in mitre.map_techniques(signals):
        assert t.get("basis") in ("signal-id", "description"), t


def test_the_basis_survives_the_exclusion_filter() -> None:
    """`map_techniques` takes an `exclude` set for the dynamic guards. Filtering
    must not strip the field off the survivors."""
    found = mitre.map_techniques([FIPS, MACROS], exclude={"office.vba_present"})
    assert found, "excluding one signal must not empty the mapping"
    for t in found:
        assert "basis" in t, t
