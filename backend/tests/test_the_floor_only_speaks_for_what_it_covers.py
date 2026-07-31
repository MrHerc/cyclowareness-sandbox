"""`MIN_MALWARE_DETECTED = 69` says nothing whatever about PDFs.

The detonation corpus is 93 real detonations and it is the product's regression
floor, so it is easy to read it as "the engine is measured". Measured on what,
by analyzer, sample count:

    generic          93
    yara             93
    dynamic.capev2   93
    pe               76
    script           10
    office            4
    pdf               0

`.pdf` is in `SUPPORTED_EXTENSIONS`, the PDF analyzer ships, and PDFs are
accepted and scored -- with zero corpus coverage. That gap is not academic. It is
exactly where the worst false positives of 2026-07-31 were found: NIST 800-53 and
the NIST CSF, the compliance library a SOC actually keeps on disk, came out
`suspicious` with signal sets and scores byte-identical to two malware-corpus
PDFs, pair for pair. The floor could not have caught it, and did not.

One of those two malware PDFs also reported `capev2.completed` with no flagged
behaviour, so "the malware sample scores like the NIST document" may partly be a
statement about the sample.

What this test does is keep the gap visible. It does not tune anything: with no
covered samples of a type there is no measurement to tune against, and changing
detection behaviour on a type the floor cannot see is how a regression ships
quietly. The remaining PDF signals -- `pdf.open_action`, `pdf.uri_action`,
`pdf.object_stream_obfuscation`, `generic.suspicious_tld` -- are structural facts
about ordinary documents, and they are still enough to reach `suspicious` and to
name a document `PDF.Trojan.OpenAction`. That is **open**, recorded here rather
than hidden, in the same spirit as the `MAX_BENIGN_CIR` note about WinMerge.

Fixing it needs PDF samples in the corpus first. That is the next piece of work,
not a number to adjust.
"""
from __future__ import annotations

import collections
import json
from pathlib import Path

CORPUS = Path(__file__).parent / "data" / "detonation_corpus.json"
SAMPLES = json.loads(CORPUS.read_text(encoding="utf-8"))["samples"]

#: Analyzers that ship and can be reached by a supported extension. If one of
#: these has no corpus sample, the floor is silent about that whole file type.
SHIPPED_ANALYZERS = {"generic", "pe", "yara", "dynamic.capev2", "script", "office", "pdf"}

#: Measured 2026-07-31. A ratchet: coverage may grow, never shrink.
COVERAGE_FLOOR = {
    "generic": 93,
    "yara": 93,
    "dynamic.capev2": 93,
    "pe": 76,
    "script": 10,
    "office": 4,
    "pdf": 0,
}

#: The types the floor cannot speak for. Shrinking this is the goal.
UNCOVERED = {"pdf"}


def _coverage() -> collections.Counter:
    seen: collections.Counter = collections.Counter()
    for sample in SAMPLES:
        for name, result in (sample.get("analyzers") or {}).items():
            if result.get("ran"):
                seen[name] += 1
    return seen


def test_coverage_never_shrinks() -> None:
    """A sample removed from the corpus silently narrows what the floor proves."""
    seen = _coverage()
    lost = {
        name: (floor, seen.get(name, 0))
        for name, floor in COVERAGE_FLOOR.items()
        if seen.get(name, 0) < floor
    }
    assert not lost, f"corpus coverage fell (analyzer: was, now): {lost}"


def test_the_uncovered_types_are_still_exactly_the_ones_recorded() -> None:
    """Fails when PDF coverage arrives — which is the good failure.

    When it does: add the samples, then update `UNCOVERED` and `COVERAGE_FLOOR`
    and re-read the PDF paragraph in this module's docstring, because tuning the
    PDF signals becomes possible at that point and not before.
    """
    seen = _coverage()
    uncovered = {name for name in SHIPPED_ANALYZERS if seen.get(name, 0) == 0}
    assert uncovered == UNCOVERED, (
        f"the set of file types the floor cannot speak for changed: "
        f"recorded {sorted(UNCOVERED)}, now {sorted(uncovered)}"
    )


def test_the_thinly_covered_types_are_named() -> None:
    """Ten scripts and four office documents is coverage, but it is thin.

    Not a failure — a reminder that a floor of 69 is overwhelmingly a statement
    about PE malware, and should be quoted as one.
    """
    seen = _coverage()
    thin = {name: seen[name] for name in ("script", "office") if seen[name] < 20}
    assert thin == {"script": 10, "office": 4}, thin
