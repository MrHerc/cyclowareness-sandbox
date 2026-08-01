"""RTF: the format that carries an OLE object and calls it a document.

Five real RTF samples went through this engine and produced NOTHING. Not a weak
verdict -- `family=unknown`, no analyzer, no signals, no detonation, `clean` at
1.7. Identification already knew they were RTF; `_family_for` had no case for the
MIME, so the answer was thrown away and nothing ran.

That is a gap worth closing properly. RTF is one of the two formats attackers
moved to when Microsoft blocked macros, and the samples show exactly why: two of
the five (DBatLoader, Smoke Loader) carry `\\object`, `\\objdata`, `\\objupdate`
and `\\objemb` -- an embedded OLE object plus the control word that renders it
WITHOUT the user clicking anything.

What this reads, and why each one is evidence rather than structure:

* ``\\objupdate`` forces the embedded object to update, i.e. execute, on open.
  Word itself does not emit it; it exists in the wild almost exclusively to
  remove the click.
* ``\\objdata`` is the object's payload as hex. Inflating it reveals what is
  actually embedded -- an OLE2 header, a PE, a URL moniker.
* The Equation Editor CLSID is CVE-2017-11882 and CVE-2018-0802, still the most
  common RTF exploit chain years later.
* ``\\objocx`` / an OLE2Link moniker is remote-template loading: the document
  fetches its payload when opened.
* Junk control words. Every sample here is padded with ``{\\*\\j60dMM2Pnz...}``
  style groups -- meaningless to a reader, present to break signatures. A
  document that is mostly control words nobody defined is obfuscated by
  construction.

Deliberately NOT a signal: the mere presence of ``\\object``. A legitimate RTF
can embed a chart or an equation, and this analyzer's whole reason for existing
is that saying so falsely is worse than saying nothing.
"""
from __future__ import annotations

import binascii
import re
import time

from ..contracts import AnalyzerResult, IOCs, Sample, Signal

NAME = "rtf"

#: How much of the file is read. RTF exploits live in the first object; a
#: 600 MB "document" is not a document, and the cap is what stops one becoming a
#: memory bill.
MAX_READ = 16 * 1024 * 1024

#: How much decoded objdata is examined. Enough to see an OLE2 header, a PE
#: header and a moniker; far short of reconstructing the payload, which is the
#: detonation tier's job.
MAX_OBJDATA_BYTES = 512 * 1024

#: Bounded on both sides: no unbounded quantifier can backtrack catastrophically.
#: The same rule scripts.py records after measuring a denial of service.
_RE_OBJDATA = re.compile(rb"\\objdata[\s]{0,16}([0-9a-fA-F\s]{16,})", re.I)
_RE_CONTROL = re.compile(rb"\\\*?\\?([a-zA-Z]{1,32})")
_RE_URL = re.compile(rb"(?:https?|ftp)://[^\s\"'<>)\\}]{1,2000}", re.I)

#: Microsoft Equation Editor, CLSID {0002CE02-0000-0000-C000-000000000046}.
#: CVE-2017-11882 and CVE-2018-0802 both reach code through it, and it is still
#: the most common RTF exploit chain years after the component was retired.
#:
#: These are the bytes as they appear INSIDE objdata, which is not the order the
#: CLSID is written in: the first three fields are little-endian, so 0002CE02
#: lands as 02 CE 02 00.
_EQUATION_CLSID = "0002CE02-0000-0000-C000-000000000046"
_EQUATION_BYTES = bytes.fromhex("02ce020000000000c000000000000046")

_OLE2_HEADER = bytes.fromhex("d0cf11e0a1b11ae1")


def _hex_to_bytes(blob: bytes) -> bytes:
    """Decode an `\\objdata` hex run, ignoring the whitespace RTF wraps it in."""
    cleaned = bytes(c for c in blob if c not in b" \t\r\n")
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    try:
        return binascii.unhexlify(cleaned[: MAX_OBJDATA_BYTES * 2])
    except (binascii.Error, ValueError):
        return b""


def analyze(sample: Sample) -> AnalyzerResult:
    started = time.perf_counter()
    result = AnalyzerResult(analyzer=NAME)
    try:
        data = sample.read(MAX_READ)
    except OSError as exc:
        return AnalyzerResult.unavailable(
            NAME, f"could not read the quarantined sample ({type(exc).__name__})")
    if not data:
        return AnalyzerResult.unavailable(NAME, "sample is empty")

    lowered = data.lower()
    facts = result.facts
    signals = result.signals

    facts["bytes_examined"] = len(data)
    facts["truncated"] = sample.size_bytes > len(data)

    # --- the object, and whether it runs itself ------------------------------
    objects = lowered.count(b"\\object")
    updates = lowered.count(b"\\objupdate")
    embedded = lowered.count(b"\\objemb")
    ocx = lowered.count(b"\\objocx")
    facts["object_count"] = objects
    facts["objupdate_count"] = updates

    if updates:
        signals.append(Signal(
            id="rtf.object_auto_executes",
            title="Embedded object set to run when the document opens",
            severity="high",
            detail=(
                f"\\objupdate x{updates}. The control word forces the embedded object to "
                "update — that is, to execute — without the reader clicking it. Word does "
                "not emit this; it exists to remove the click."
            ),
            evidence={"objupdate": updates, "object": objects},
        ))

    # --- what is actually inside the object ----------------------------------
    decoded_total = 0
    carries_ole2 = False
    carries_pe = False
    equation = False
    for match in _RE_OBJDATA.finditer(data):
        decoded = _hex_to_bytes(match.group(1))
        if not decoded:
            continue
        decoded_total += len(decoded)
        if _OLE2_HEADER in decoded[:4096]:
            carries_ole2 = True
        if b"MZ" == decoded[:2] or b"This program cannot be run in DOS mode" in decoded:
            carries_pe = True
        if _EQUATION_BYTES in decoded:
            equation = True
        if decoded_total >= MAX_OBJDATA_BYTES:
            break
    facts["objdata_bytes_decoded"] = decoded_total

    if equation:
        signals.append(Signal(
            id="rtf.equation_editor_object",
            title="Embedded Microsoft Equation Editor object",
            severity="critical",
            detail=(
                "The embedded object's CLSID is Microsoft Equation Editor "
                "(0002CE02-…). It is the vehicle for CVE-2017-11882 and CVE-2018-0802 "
                "and is years out of support; a document that embeds one in 2026 is "
                "not doing mathematics."
            ),
            evidence={"clsid": _EQUATION_CLSID},
        ))
    if carries_pe:
        signals.append(Signal(
            id="rtf.embedded_executable",
            title="An executable is embedded in the document",
            severity="critical",
            detail=(
                "The decoded \\objdata begins with an MZ header. A document carrying a "
                "Windows executable inside itself is delivering it."
            ),
            evidence={"decoded_bytes": decoded_total},
        ))
    elif carries_ole2:
        signals.append(Signal(
            id="rtf.embedded_ole_package",
            title="An OLE2 package is embedded in the document",
            severity="high",
            detail=(
                "The decoded \\objdata is an OLE2 compound document. That is how a second "
                "file — a macro-enabled document, a script, an executable — is carried "
                "inside an RTF."
            ),
            evidence={"decoded_bytes": decoded_total},
        ))

    if ocx or b"ole2link" in lowered or b"objautlink" in lowered:
        signals.append(Signal(
            id="rtf.remote_object_link",
            title="Object linked to remote content",
            severity="high",
            detail=(
                "An OLE2Link / \\objocx moniker makes the document fetch its object when "
                "opened. The payload is not in the file you are looking at."
            ),
            evidence={"objocx": ocx},
        ))

    # --- obfuscation ---------------------------------------------------------
    #
    # An RTF reader ignores control words it does not know, so padding a document
    # with thousands of invented ones costs the attacker nothing and breaks
    # naive signatures. Counted as a RATIO rather than a count: a long legitimate
    # document has many control words too.
    controls = _RE_CONTROL.findall(data)
    known = sum(1 for c in controls if c.lower() in _KNOWN_CONTROL_WORDS)
    total = len(controls)
    facts["control_words"] = total
    facts["control_words_known"] = known
    if total >= 200 and known / max(total, 1) < 0.25:
        signals.append(Signal(
            id="rtf.control_word_padding",
            title="Document is mostly control words no reader defines",
            severity="medium",
            detail=(
                f"{total - known} of {total} control words are not part of the RTF "
                "specification. A reader ignores them, which is precisely why they are "
                "there: they break signatures without changing what the document shows."
            ),
            evidence={"control_words": total, "recognised": known},
        ))

    # --- indicators ----------------------------------------------------------
    iocs = IOCs()
    for match in _RE_URL.finditer(data):
        iocs.urls.append(match.group(0).decode("latin-1", "replace")[:2000])
    iocs.urls = list(dict.fromkeys(iocs.urls))[:50]
    result.iocs = iocs

    result.ran = True
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    return result


#: The control words a conforming reader actually defines. Not exhaustive -- it
#: does not need to be. It only has to be large enough that an ORDINARY document
#: lands well above the ratio, which is what the threshold is measured against.
_KNOWN_CONTROL_WORDS = frozenset(b.encode() for b in (
    "rtf", "ansi", "ansicpg", "deff", "deflang", "fonttbl", "f", "fnil", "froman",
    "fswiss", "fmodern", "fscript", "fdecor", "ftech", "fbidi", "fcharset", "fprq",
    "panose", "colortbl", "red", "green", "blue", "stylesheet", "s", "ql", "qr",
    "qj", "qc", "li", "ri", "fi", "sa", "sb", "sl", "slmult", "widctlpar", "wrapdefault",
    "aspalpha", "aspnum", "faauto", "adjustright", "rin", "lin", "itap", "lang",
    "langfe", "cgrid", "langnp", "langfenp", "b", "i", "ul", "ulnone", "strike",
    "scaps", "caps", "super", "sub", "nosupersub", "cf", "cb", "highlight", "fs",
    "par", "pard", "plain", "line", "page", "sect", "sectd", "tab", "tx", "trowd",
    "cell", "row", "cellx", "intbl", "clbrdrt", "clbrdrl", "clbrdrb", "clbrdrr",
    "brdrs", "brdrw", "brdrcf", "trgaph", "trleft", "pict", "pngblip", "jpegblip",
    "wmetafile", "picw", "pich", "picwgoal", "pichgoal", "bin", "shppict",
    "nonshppict", "field", "fldinst", "fldrslt", "info", "title", "author",
    "operator", "creatim", "revtim", "yr", "mo", "dy", "hr", "min", "nofpages",
    "nofwords", "nofchars", "generator", "viewkind", "uc", "u", "ltrpar", "rtlpar",
    "ltrch", "rtlch", "loch", "hich", "dbch", "af", "afs", "object", "objemb",
    "objdata", "objupdate", "objocx", "objw", "objh", "result", "objclass",
    "objattph", "objsetsize", "objalign", "objtransy", "objscalex", "objscaley",
    "cocoartf", "cocoasubrtf", "cocoascreenfonts", "expnd", "expndtw", "kerning",
    "outl", "shad", "nosectexpand", "pgnstart", "pgnrestart", "headery", "footery",
    "margl", "margr", "margt", "margb", "gutter", "paperw", "paperh", "landscape",
    "deftab", "ftnbj", "aenddoc", "hyphhotz", "formshade", "horzdoc", "dghspace",
    "dgvspace", "dghorigin", "dgvorigin", "dghshow", "dgvshow", "jexpand",
    "viewscale", "pgbrdrhead", "pgbrdrfoot", "splytwnine", "ftnlytwnine",
    "htmautsp", "nolnhtadjtbl", "useltbaln", "alntblind", "lytcalctblwd",
    "lyttblrtgr", "lnbrkrule", "nobrkwrptbl", "snaptogridincell", "allowfieldendsel",
))
