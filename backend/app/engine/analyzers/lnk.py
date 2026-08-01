"""A Windows shortcut is a script with an icon.

Four real LNK samples went through this engine and produced NOTHING --
`family=unknown`, no analyzer, no signals, no detonation, `clean` at 2.0.
Identification already knew what they were ("Windows shortcut file"); nothing
consumed the answer.

LNK is the format attackers moved to when Microsoft blocked macros, and it is a
delivery vehicle for one reason: the file the user double-clicks is not the file
that runs. The payload is the COMMAND LINE stored inside the shortcut, and
Explorer does not show it -- the properties dialog truncates the arguments field
at 260 characters, which is less than most of these use.

So this parses the format rather than scanning it. MS-SHLLINK is small and
strictly ordered: a 0x4C-byte header whose CLSID is 00021401-…, LinkFlags saying
which optional structures follow, then the StringData sequence in a fixed order.
The arguments are the fifth of those, and reading them is the difference between
"a shortcut" and "a shortcut that runs `powershell -w hidden -enc …`".

The samples show the two shapes:

* NetSupport, 1.9 kB -- an ordinary-sized shortcut whose command line is the
  whole attack.
* Kimsuky, 68 kB -- a shortcut thirty times larger than any real one, because
  the payload is appended to the file itself and the command line reassembles it.

Every parse step is bounded and none of them raises: a malformed shortcut is
something to report, not something to crash on.
"""
from __future__ import annotations

import re
import struct
import time

from ..contracts import AnalyzerResult, IOCs, Sample, Signal

NAME = "lnk"

#: The whole structure lives in the first few kilobytes. Reading more is only
#: needed to MEASURE the file, which `sample.size_bytes` already gives.
MAX_READ = 4 * 1024 * 1024

#: MS-SHLLINK: HeaderSize is always 0x4C and the CLSID is fixed.
#:
#: {00021401-0000-0000-C000-000000000046}, stored with the first three fields
#: little-endian — so it lands on disk as 01 14 02 00 …, which is exactly what
#: the four real samples begin with after `L\x00\x00\x00`.
_HEADER_SIZE = 0x4C
_LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")

#: LinkFlags bits that say which StringData entries follow, in this order.
_HAS_IDLIST = 1 << 0
_HAS_LINKINFO = 1 << 1
_HAS_NAME = 1 << 2
_HAS_RELPATH = 1 << 3
_HAS_WORKDIR = 1 << 4
_HAS_ARGS = 1 << 5
_HAS_ICON = 1 << 6
_IS_UNICODE = 1 << 7

#: A real shortcut is a pointer. Measured across the Windows Start Menu, they run
#: from a few hundred bytes to about 2 kB; the largest legitimate ones with a
#: full icon path reach ~4 kB. Well past that, the file is carrying something.
_ORDINARY_MAX = 8 * 1024

#: Interpreters a shortcut can name. Naming one is not a finding on its own -- a
#: legitimate admin shortcut opens cmd -- so this is the population, and what is
#: PASSED to them is the evidence.
_INTERPRETERS = (
    "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "msiexec", "certutil", "bitsadmin", "curl.exe", "wget.exe",
    "installutil", "forfiles", "conhost",
)

#: What turns naming an interpreter into running an attack.
_ARGUMENT_MARKERS = (
    ("hidden window", r"-w(?:indowstyle)?\s+h(?:idden)?\b|-windowstyle\s+hidden"),
    ("encoded command", r"-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}"),
    ("execution policy bypass", r"-ep\s+bypass|-executionpolicy\s+bypass"),
    ("no profile", r"-nop(?:rofile)?\b"),
    ("download cradle", r"downloadstring|downloadfile|invoke-webrequest|iwr\b|\bcurl\b|\bwget\b"),
    ("runtime evaluation", r"\biex\b|invoke-expression|\beval\("),
    ("remote script host", r"mshta\s+https?://|regsvr32[^\n]{0,80}scrobj"),
    ("reads its own file", r"get-content[^\n]{0,60}\$?(?:myinvocation|pschome)|findstr[^\n]{0,40}\.lnk"),
)

_RE_URL = re.compile(r"(?:https?|ftp)://[^\s\"'<>)]{1,2000}", re.I)


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0] if off + 2 <= len(data) else 0


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0] if off + 4 <= len(data) else 0


def _string_data(data: bytes, off: int, unicode_: bool) -> tuple[str, int]:
    """One StringData entry: a character COUNT, then that many characters.

    Returns the text and the offset just past it. The count is characters and not
    bytes, which is the detail that makes a hand-rolled parser walk off the end
    of the structure and read the next field as text.
    """
    count = _u16(data, off)
    off += 2
    if count <= 0:
        return "", off
    width = 2 if unicode_ else 1
    size = min(count * width, max(0, len(data) - off))
    raw = data[off:off + size]
    off += size
    try:
        text = raw.decode("utf-16-le" if unicode_ else "latin-1", "replace")
    except Exception:  # noqa: BLE001 — a malformed string is not a crash
        text = ""
    return text.rstrip("\x00"), off


def _parse(data: bytes) -> dict:
    """The header and the StringData sequence. Never raises."""
    out: dict = {"parsed": False}
    if len(data) < _HEADER_SIZE or _u32(data, 0) != _HEADER_SIZE:
        return out
    if data[4:20] != _LINK_CLSID:
        return out

    flags = _u32(data, 20)
    out["flags"] = flags
    out["target_size"] = _u32(data, 0x34)
    out["icon_index"] = _u32(data, 0x38)
    out["show_command"] = _u32(data, 0x3C)
    unicode_ = bool(flags & _IS_UNICODE)

    off = _HEADER_SIZE
    if flags & _HAS_IDLIST:
        off += 2 + _u16(data, off)          # IDListSize, then the list
    if flags & _HAS_LINKINFO:
        off += max(4, _u32(data, off))      # LinkInfoSize covers the whole block

    for bit, key in (
        (_HAS_NAME, "name"),
        (_HAS_RELPATH, "relative_path"),
        (_HAS_WORKDIR, "working_dir"),
        (_HAS_ARGS, "arguments"),
        (_HAS_ICON, "icon_location"),
    ):
        if flags & bit:
            out[key], off = _string_data(data, off, unicode_)
        if off > len(data):
            break

    out["parsed"] = True
    return out


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

    facts = result.facts
    signals = result.signals
    parsed = _parse(data)
    facts.update({k: v for k, v in parsed.items() if k != "flags"})
    facts["size_bytes"] = sample.size_bytes if sample.size_bytes >= 0 else len(data)

    if not parsed.get("parsed"):
        signals.append(Signal(
            id="lnk.header_malformed",
            title="Shortcut header does not match the format",
            severity="medium",
            detail=(
                "The 0x4C header size or the link CLSID is wrong. Windows is tolerant "
                "here, so a shortcut that does not parse is either corrupt or built by "
                "something other than Windows."
            ),
            evidence={"first_bytes": data[:8].hex()},
        ))
        result.ran = True
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    arguments = parsed.get("arguments", "") or ""
    relative = parsed.get("relative_path", "") or ""
    icon = parsed.get("icon_location", "") or ""
    haystack = " ".join((arguments, relative, parsed.get("working_dir", "") or "")).lower()

    named = sorted({i for i in _INTERPRETERS if i in haystack})
    if named:
        facts["interpreters"] = named

    # --- what the shortcut actually runs -------------------------------------
    matched = [label for label, pattern in _ARGUMENT_MARKERS
               if re.search(pattern, arguments, re.I)]
    if matched:
        signals.append(Signal(
            id="lnk.command_line_attack",
            title="Shortcut runs a command line, not a program",
            severity="critical",
            detail=(
                "The shortcut's arguments are " + ", ".join(matched) + ". Explorer does "
                "not show this: the properties dialog truncates the arguments field, and "
                "the user sees only the icon and the name."
            ),
            evidence={"techniques": matched, "arguments": arguments[:400],
                      "interpreters": named},
        ))
    elif named and arguments.strip():
        signals.append(Signal(
            id="lnk.runs_an_interpreter",
            title="Shortcut passes arguments to a script interpreter",
            # `info`, and the controls are why. A shortcut to cmd.exe with
            # `/k cd /d C:\work`, and one to powershell.exe with
            # `-NoExit -Command Set-Location`, are what an ordinary developer
            # machine is full of. At `medium` both scored 8.3 on structure alone.
            #
            # This is the same rule the PE analyzer states about imports: a fact
            # about capability is not a detection on its own. What the shortcut
            # PASSES is the detection, and `lnk.command_line_attack` carries it
            # at `critical`.
            severity="info",
            detail=(
                f"The shortcut targets {', '.join(named)} and passes arguments. An admin "
                "shortcut legitimately does this, so it is recorded rather than judged — "
                "the arguments are in the evidence below."
            ),
            evidence={"interpreters": named, "arguments": arguments[:400]},
        ))

    # --- a shortcut that is not a pointer ------------------------------------
    size = facts["size_bytes"]
    if size > _ORDINARY_MAX:
        signals.append(Signal(
            id="lnk.oversized_for_a_shortcut",
            title=f"Shortcut is {size // 1024} kB",
            severity="high",
            detail=(
                "A shortcut is a pointer; real ones run from a few hundred bytes to about "
                "four kilobytes. One this size is carrying something appended to it, "
                "which the command line then reassembles."
            ),
            evidence={"size_bytes": size, "ordinary_max": _ORDINARY_MAX},
        ))

    # --- the disguise --------------------------------------------------------
    #
    # An icon borrowed from a document viewer, on a shortcut that runs a shell,
    # is the whole trick: the user sees a PDF and double-clicks a command line.
    icon_lower = icon.lower()
    document_icon = any(
        token in icon_lower for token in
        ("acrord32", "winword", "excel", "powerpnt", "notepad", "wordpad",
         "imageres.dll", "shell32.dll", ".pdf", ".doc", ".xls")
    )
    if document_icon and named:
        signals.append(Signal(
            id="lnk.icon_disguise",
            title="Shortcut wears a document's icon and runs an interpreter",
            severity="high",
            detail=(
                f"The icon is taken from {icon[:120]} while the shortcut runs "
                f"{', '.join(named)}. The user sees a document and double-clicks a "
                "command line."
            ),
            evidence={"icon_location": icon[:200], "interpreters": named},
        ))

    iocs = IOCs()
    for match in _RE_URL.finditer(" ".join((arguments, icon, relative))):
        iocs.urls.append(match.group(0)[:2000])
    iocs.urls = list(dict.fromkeys(iocs.urls))[:50]
    result.iocs = iocs

    result.ran = True
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    return result
