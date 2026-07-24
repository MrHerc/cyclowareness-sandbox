"""Static analysis of Microsoft Office documents — legacy OLE2 and OOXML.

Covers the ``office`` family: the OLE2 compound documents (.doc/.xls/.ppt) and
the OOXML zip packages (.docx/.xlsm/.pptm). The analyzer **extracts and scans;
it never executes a macro**. Every interaction with the sample is parsing:
``oletools`` walks the OLE/zip structure as data, ``olevba`` decompresses VBA
source as data, ``msodde`` reads DDE field definitions as data. Nothing is run,
compiled, or handed to anything that would run it — the input is live malware by
definition and a macro is the one place "just open it in Word to see" is fatal.

What this module observes:

* the container format (OLE2, OOXML, Word2003-XML, MHTML, …);
* whether VBA is present, and the truncated source of each module;
* auto-execution triggers (AutoOpen / Document_Open / Workbook_Open / …), named;
* obfuscation shape (Chr() chains, StrReverse, base64, long concatenation);
* dangerous capabilities reachable from the macros, one signal per capability;
* external relationship targets in OOXML — the remote-template-injection vector,
  which needs no macro at all;
* DDE fields — code execution with no macro at all;
* embedded / OLE objects;
* whether the document is encrypted (reported, never brute-forced).

Every URL/domain/IP found in the macro source, the external relationship
targets, and the document body is lifted into ``iocs``. Extraction only: nothing
here is resolved, fetched, or contacted. Every parse is wrapped, every read is
bounded, and every sample-derived string is truncated before it reaches a
Signal — a malformed document is an observation, not a crash, and a 4 GB
decompressed part or a catastrophic-backtracking regex is a denial of service.
"""
from __future__ import annotations

import re
import time
import zipfile
from dataclasses import dataclass
from typing import Any, Iterable

from ..contracts import AnalyzerResult, IOCs, Sample, Severity, Signal

NAME = "office"
FAMILY = "office"

#: Mimes identify.py assigns to the office family.
_OFFICE_MIMES = frozenset({
    "application/x-ole-storage",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
})

#: Extensions this analyzer claims even when identification was uncertain.
_OFFICE_EXTENSIONS = frozenset({
    ".doc", ".dot", ".docx", ".docm", ".dotx", ".dotm",
    ".xls", ".xlt", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb",
    ".ppt", ".pot", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
})

# --- bounds -------------------------------------------------------------------
#: Total VBA source (all modules concatenated) scanned by the detectors. A macro
#: larger than this is scanned truncated, and the fact says so.
MAX_SCAN_CHARS = 1_000_000
#: Per-module VBA source kept in facts. The report needs a readable excerpt, not
#: a megabyte of source per module.
MAX_MODULE_FACT_CHARS = 8_000
#: Modules recorded in facts.
MAX_MODULES = 64
#: OOXML zip entries examined for relationships / body / embeddings.
MAX_ZIP_ENTRIES = 2_000
#: Bytes read from a single zip entry (a .rels or body xml). Guards against a
#: zip-bomb entry — decompression is bounded, never "read it all".
MAX_ENTRY_BYTES = 4 * 1024 * 1024
#: Bytes of a legacy OLE2 file scanned for body IOCs.
MAX_OLE_BODY_BYTES = 8 * 1024 * 1024
#: Per-kind IOC cap.
MAX_IOCS_PER_KIND = 100
#: Any sample-derived string that reaches a Signal or a fact is cut to this.
STR_LIMIT = 200
#: External relationship targets recorded.
MAX_REL_TARGETS = 64


def _clip(value: Any, limit: int = STR_LIMIT) -> str:
    """Sample-derived text, normalised to one printable line and truncated."""
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    else:
        text = str(value)
    flat = re.sub(r"\s+", " ", text[: limit * 4]).strip()
    flat = "".join(ch if 32 <= ord(ch) < 127 or ord(ch) >= 160 else "." for ch in flat)
    return flat[:limit] + ("…" if len(flat) > limit else "")


def _dedup(values: Iterable[str], limit: int = MAX_IOCS_PER_KIND) -> list[str]:
    out: dict[str, None] = {}
    for value in values:
        if len(out) >= limit:
            break
        out.setdefault(value, None)
    return list(out)


# --- auto-execution triggers --------------------------------------------------
# Named so the signal can say *which* trigger, and matched on the Sub/Function
# declaration so a mere mention in a comment does not fire. Ordered pairs of
# (human name, regex over the VBA source).

_AUTOEXEC_TRIGGERS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(rx, re.IGNORECASE))
    for name, rx in (
        # Word
        ("AutoOpen", r"\bsub\s+autoopen\b"),
        ("AutoClose", r"\bsub\s+autoclose\b"),
        ("AutoExec", r"\bsub\s+autoexec\b"),
        ("AutoNew", r"\bsub\s+autonew\b"),
        ("Document_Open", r"\bsub\s+document_open\b"),
        ("Document_Close", r"\bsub\s+document_close\b"),
        ("Document_New", r"\bsub\s+document_new\b"),
        ("Document_ContentControlOnEnter", r"\bsub\s+document_contentcontrolonenter\b"),
        # Excel
        ("Workbook_Open", r"\bsub\s+workbook_open\b"),
        ("Workbook_Activate", r"\bsub\s+workbook_activate\b"),
        ("Workbook_Close", r"\bsub\s+workbook_close\b"),
        ("Workbook_BeforeClose", r"\bsub\s+workbook_beforeclose\b"),
        ("Worksheet_Activate", r"\bsub\s+worksheet_activate\b"),
        ("Auto_Open", r"\bsub\s+auto_open\b"),
        ("Auto_Close", r"\bsub\s+auto_close\b"),
        ("Auto_Exec", r"\bsub\s+auto_exec\b"),
        # PowerPoint
        ("Auto_Open (PPT)", r"\bsub\s+auto_open\b"),
        # Generic COM event handlers used as triggers
        ("Class_Initialize", r"\bsub\s+class_initialize\b"),
        ("App_WorkbookOpen", r"\bsub\s+app_workbookopen\b"),
    )
)


# --- suspicious capability groups ---------------------------------------------
# Each group emits one Signal, id ``office.macro_suspicious_call.<suffix>``.
# Scoring keys off the ``office.macro_suspicious_call`` prefix, so the suffix is
# free to name the capability. Matching is a set of linear regexes (single
# quantifiers over literal/negated classes) run against a bounded window.

@dataclass(frozen=True)
class _Capability:
    suffix: str
    title: str
    severity: Severity
    patterns: tuple[tuple[str, re.Pattern[str]], ...]


def _caps(*rows: tuple[str, str, str]) -> tuple[tuple[str, re.Pattern[str]], ...]:
    return tuple((label, re.compile(rx, re.IGNORECASE)) for label, rx in rows)


_CAPABILITIES: tuple[_Capability, ...] = (
    _Capability(
        "shell", "Macro can launch a process via Shell", "high",
        _caps(
            ("Shell()", r"(?<![a-z0-9_])shell\s*\("),
            ("VBA.Shell", r"\bvba\.shell\b"),
            ("ShellExecute", r"\bshellexecute\b"),
            ("Application.Run", r"\bapplication\.run\b"),
        ),
    ),
    _Capability(
        "create_object", "Macro instantiates COM objects (CreateObject/GetObject)", "medium",
        _caps(
            ("CreateObject", r"\bcreateobject\s*\("),
            ("GetObject", r"\bgetobject\s*\("),
        ),
    ),
    _Capability(
        "wscript_shell", "Macro drives WScript.Shell / WScript.Network", "high",
        _caps(
            ("WScript.Shell", r"wscript\.shell"),
            ("WScript.Network", r"wscript\.network"),
            (".Run(...)", r"\.run\s*[(\"']"),
            (".Exec(...)", r"\.exec\s*[(\"']"),
            ("Shell.Application", r"shell\.application"),
        ),
    ),
    _Capability(
        "powershell", "Macro invokes PowerShell", "high",
        _caps(
            ("powershell(.exe)", r"powershell(?:\.exe)?"),
            ("pwsh", r"\bpwsh\b"),
            ("-EncodedCommand / -enc", r"-e(?:nc(?:odedcommand)?)?\b"),
            ("-NoProfile / -nop", r"-nop(?:rofile)?\b"),
            ("-w hidden / -WindowStyle Hidden", r"-w(?:indowstyle)?\s+hidden"),
            ("IEX / Invoke-Expression", r"\b(?:iex|invoke-expression)\b"),
        ),
    ),
    _Capability(
        "url_download", "Macro downloads a file (URLDownloadToFile)", "high",
        _caps(
            ("URLDownloadToFile", r"urldownloadtofile"),
        ),
    ),
    _Capability(
        "http_client", "Macro makes HTTP requests (MSXML / WinHTTP / Internet*)", "high",
        _caps(
            ("MSXML2.XMLHTTP / ServerXMLHTTP", r"msxml2\.(?:server)?xmlhttp"),
            ("WinHttp.WinHttpRequest", r"winhttp\.winhttprequest"),
            ("InternetOpenUrl / InternetOpenA", r"\binternetopen"),
            ("XMLHTTP", r"\bxmlhttp\b"),
            ('.Open "GET"/"POST"', r"\.open\s*\(?\s*[\"'](?:get|post)[\"']"),
        ),
    ),
    _Capability(
        "create_process", "Macro uses CreateProcess / WMI Win32_Process", "high",
        _caps(
            ("CreateProcess", r"\bcreateprocess[aw]?\b"),
            ("winmgmts / WMI", r"winmgmts:"),
            ("Win32_Process.Create", r"win32_process"),
        ),
    ),
    _Capability(
        "adodb_stream", "Macro writes files to disk via ADODB.Stream", "high",
        _caps(
            ("ADODB.Stream", r"adodb\.stream"),
            ("SaveToFile", r"\bsavetofile\b"),
        ),
    ),
    _Capability(
        "filesystem", "Macro manipulates the filesystem (FileSystemObject)", "medium",
        _caps(
            ("Scripting.FileSystemObject", r"scripting\.filesystemobject"),
            ("FileSystemObject", r"\bfilesystemobject\b"),
            ("Open ... For Binary", r"\bopen\b[^\n]{0,120}\bfor\s+binary\b"),
        ),
    ),
    _Capability(
        "registry", "Macro reads/writes the registry", "medium",
        _caps(
            ("WScript.Shell RegWrite", r"\bregwrite\b"),
            ("WScript.Shell RegRead", r"\bregread\b"),
            ("StdRegProv", r"\bstdregprov\b"),
        ),
    ),
    _Capability(
        "environ_persistence", "Macro drops into a startup / persistence location", "medium",
        _caps(
            ("Startup folder", r"\\microsoft\\windows\\start menu\\programs\\startup|shell:startup"),
            ("Run key", r"currentversion\\run(?:once)?"),
            ("schtasks", r"\bschtasks\b"),
        ),
    ),
)


# --- obfuscation techniques ---------------------------------------------------

_RE_CHR = re.compile(r"\bchr[bw]?\s*\(", re.IGNORECASE)
_RE_STRREVERSE = re.compile(r"\bstrreverse\s*\(", re.IGNORECASE)
_RE_ASC = re.compile(r"\basc[bw]?\s*\(", re.IGNORECASE)
_RE_HEXLIT = re.compile(r"&h[0-9a-f]{2}\b", re.IGNORECASE)
_RE_CONCAT = re.compile(r"[\"']\s*[&+]\s*[\"']")
_RE_XOR = re.compile(r"\bxor\b", re.IGNORECASE)
_RE_B64WORD = re.compile(r"base64|frombase64|msxml2\.domdocument|bin\.base64", re.IGNORECASE)
_RE_B64BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_RE_LONGLINE = 600


def _obfuscation_techniques(code: str) -> list[str]:
    found: list[str] = []
    chr_hits = len(_RE_CHR.findall(code))
    if chr_hits >= 8:
        found.append(f"Chr()/ChrW() reconstruction ({chr_hits} calls)")
    asc_hits = len(_RE_ASC.findall(code))
    if asc_hits >= 8:
        found.append(f"Asc()/AscW() arithmetic ({asc_hits} calls)")
    if _RE_STRREVERSE.search(code):
        found.append("StrReverse() string reversal")
    hex_hits = len(_RE_HEXLIT.findall(code))
    if hex_hits >= 12:
        found.append(f"hex byte literals ({hex_hits} of &Hxx)")
    concat_hits = len(_RE_CONCAT.findall(code))
    if concat_hits >= 12:
        found.append(f"string-splicing concatenation ({concat_hits} joins)")
    xor_hits = len(_RE_XOR.findall(code))
    if xor_hits >= 4:
        found.append(f"Xor decode loop ({xor_hits} occurrences)")
    if _RE_B64WORD.search(code):
        found.append("base64 decoding routine")
    b64_blob = max((len(m.group(0)) for m in _RE_B64BLOB.finditer(code)), default=0)
    if b64_blob >= 200:
        found.append(f"long base64 literal ({b64_blob} chars)")
    longest = max((len(line) for line in code.splitlines()), default=0)
    if longest >= _RE_LONGLINE:
        found.append(f"very long source line ({longest} chars)")
    return found


# --- IOC extraction -----------------------------------------------------------
# Linear regexes over bounded windows; nothing is resolved or fetched.

_RE_URL = re.compile(r"\b(?:https?|ftps?)://[^\s\"'<>)\]}\\^`|]{1,2000}", re.IGNORECASE)
_RE_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_RE_UNC = re.compile(r"\\\\[A-Za-z0-9._-]{1,64}\\[^\s\"'<>|*?\n\r;,()]{1,240}")
_TLDS = (
    "com|net|org|edu|gov|mil|int|info|biz|name|pro|io|co|me|tv|cc|ws|su|ru|cn|jp|kr|in|br|"
    "uk|de|fr|it|es|nl|pl|se|no|fi|dk|cz|ro|gr|pt|tr|ir|az|ge|ua|by|kz|il|sa|ae|eg|za|ng|"
    "au|nz|mx|ar|cl|ca|xyz|top|club|online|site|shop|store|live|link|fun|icu|dev|app|zip|"
    "mov|cloud|space|website|pw|tk|ml|ga|cf|gq|to|st|sh|is|am|fm|gg|vip|work|life|world"
)
_RE_DOMAIN = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]{0,80}\.(?:" + _TLDS + r")\b")

#: Hosts a benign OOXML package always contains — never emitted as indicators.
_HOST_NOISE = frozenset({
    "schemas.openxmlformats.org", "schemas.microsoft.com", "www.w3.org",
    "purl.org", "schemas.xmlsoap.org", "www.microsoft.com", "go.microsoft.com",
})


def _valid_ip(candidate: str) -> bool:
    parts = candidate.split(".")
    return len(parts) == 4 and all(
        p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts
    )


def _valid_domain(candidate: str) -> bool:
    if ".." in candidate or len(candidate) > 253:
        return False
    if candidate.lower() in _HOST_NOISE:
        return False
    labels = candidate.split(".")
    return len(labels) >= 2 and all(
        1 <= len(lbl) <= 63 and not lbl.startswith("-") and not lbl.endswith("-")
        for lbl in labels
    )


def _extract_iocs(text: str) -> IOCs:
    window = text[:MAX_SCAN_CHARS]
    iocs = IOCs()

    def _url_host(url: str) -> str:
        authority = url.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
        return authority.rsplit(":", 1)[0].strip("[]").lower()

    # Drop XML-namespace URLs (schemas.openxmlformats.org, w3.org, …): they are
    # what every OOXML package contains by construction, not indicators.
    urls = [
        m.group(0).rstrip(".,;:!'\")")
        for m in _RE_URL.finditer(window)
        if _url_host(m.group(0)) not in _HOST_NOISE
    ]
    iocs.urls = _dedup(u[:2000] for u in urls)

    hosts: list[str] = []
    for url in iocs.urls:
        host = _url_host(url)
        if host and not _valid_ip(host):
            hosts.append(host)
    hosts.extend(
        m.group(0).lower() for m in _RE_DOMAIN.finditer(window)
        if _valid_domain(m.group(0))
    )
    iocs.domains = _dedup(h for h in hosts if _valid_domain(h))
    iocs.ips = _dedup(m.group(0) for m in _RE_IP.finditer(window) if _valid_ip(m.group(0)))
    iocs.file_paths = _dedup(m.group(0)[:240] for m in _RE_UNC.finditer(window))
    return iocs


# --- OOXML structural checks (zip) --------------------------------------------

def _ooxml_relationships_and_body(path: str) -> tuple[list[dict[str, str]], str, list[str]]:
    """Walk the OOXML zip WITHOUT extracting to disk.

    Returns (external_relationship_targets, concatenated_body_text, embedded_names).
    A .rels Relationship with TargetMode="External" is the remote-template /
    remote-OLE vector — no macro required. Body text feeds IOC extraction.
    """
    external: list[dict[str, str]] = []
    body_parts: list[str] = []
    embedded: list[str] = []

    # Match a whole <Relationship .../> element, then read its attributes. Single
    # negated-class quantifier — no nested repetition, so no catastrophic case.
    rel_re = re.compile(rb"<Relationship\b[^>]{0,2000}?/?>", re.IGNORECASE)
    attr_re = re.compile(rb'(\w+)\s*=\s*"([^"]{0,2000})"')

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()[:MAX_ZIP_ENTRIES]
            for name in names:
                lower = name.lower()
                if "/embeddings/" in lower or lower.startswith("word/embeddings") \
                        or "oleobject" in lower or lower.endswith(".bin") and "embed" in lower:
                    embedded.append(_clip(name, 160))
                is_rels = lower.endswith(".rels")
                is_body = lower.endswith(".xml") and not is_rels
                if not (is_rels or is_body):
                    continue
                try:
                    with zf.open(name) as fh:
                        raw = fh.read(MAX_ENTRY_BYTES)
                except Exception:
                    continue
                if is_rels:
                    for match in rel_re.finditer(raw):
                        attrs = {
                            k.decode("latin-1").lower(): v.decode("utf-8", "replace")
                            for k, v in attr_re.findall(match.group(0))
                        }
                        if attrs.get("targetmode", "").lower() == "external":
                            rtype = attrs.get("type", "")
                            # Hyperlinks are external too, but Office does not
                            # auto-fetch them on open — they need a user click —
                            # so they are not a remote-template / remote-object
                            # vector. Nearly every real document has hyperlinks;
                            # firing "high" on them would be a mass false
                            # positive. Keep the URL as an IOC, don't fire.
                            if rtype.rsplit("/", 1)[-1].lower() == "hyperlink":
                                body_parts.append(attrs.get("target", ""))
                                continue
                            external.append({
                                "source": _clip(name, 160),
                                "type": _clip(rtype, 160),
                                "target": _clip(attrs.get("target", ""), STR_LIMIT),
                            })
                            if len(external) >= MAX_REL_TARGETS:
                                break
                elif is_body:
                    body_parts.append(raw.decode("utf-8", "replace"))
    except Exception:
        return external, "", embedded

    return external, "\n".join(body_parts)[:MAX_SCAN_CHARS], embedded


def _ole_embedded_and_body(path: str, raw: bytes) -> tuple[list[str], bool]:
    """Legacy OLE2 embedded-object check via storage names; body IOCs from raw
    bytes (ASCII + UTF-16LE), which needs no stream interpretation."""
    embedded: list[str] = []
    try:
        import olefile

        if olefile.isOleFile(path):
            ole = olefile.OleFileIO(path)
            try:
                for entry in ole.listdir(streams=True, storages=True):
                    joined = "/".join(entry)
                    low = joined.lower()
                    if "objectpool" in low or "ole10native" in low \
                            or low.endswith("\x01ole") or "\x01compobj" in low and "objectpool" in low:
                        embedded.append(_clip(joined, 160))
            finally:
                ole.close()
    except Exception:
        pass
    return _dedup(embedded, 32), bool(embedded)


def _ole_body_text(raw: bytes) -> str:
    """ASCII + UTF-16LE view of an OLE2 file for IOC extraction. Cheap slicing,
    not a full stream decode — it finds the same URLs a decode would."""
    blob = raw[:MAX_OLE_BODY_BYTES]
    ascii_text = blob.decode("latin-1", "replace")
    wide = blob[0::2].decode("latin-1", "replace") + "\n" + blob[1::2].decode("latin-1", "replace")
    return (ascii_text + "\n" + wide)[: MAX_SCAN_CHARS * 2]


# --- entry point --------------------------------------------------------------

def applies_to(sample: Sample) -> bool:
    if sample.mime in _OFFICE_MIMES:
        return True
    if sample.claimed_extension in _OFFICE_EXTENSIONS:
        return True
    try:
        head = sample.read(8)
    except OSError:
        return False
    return head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") or head.startswith(b"PK\x03\x04")


def analyze(sample: Sample) -> AnalyzerResult:
    started = time.perf_counter()

    try:
        from oletools import olevba
    except Exception as exc:  # pragma: no cover - dependency is pinned
        return AnalyzerResult.unavailable(NAME, f"oletools is not importable: {exc!r}")

    if not applies_to(sample):
        return AnalyzerResult.not_applicable(NAME, sample.mime or "unknown")

    if sample.size_bytes == 0:
        return AnalyzerResult.unavailable(NAME, "sample is empty")

    signals: list[Signal] = []
    facts: dict[str, Any] = {"claimed_extension": sample.claimed_extension}
    iocs = IOCs()

    # --- open with olevba (parsing only) -------------------------------------
    vba_parser = None
    try:
        vba_parser = olevba.VBA_Parser(sample.path)
    except Exception as exc:
        signals.append(Signal(
            id="office.parse_failed",
            title="Document structure could not be parsed",
            severity="high",
            detail=(
                "The file is claimed to be an Office document but its OLE/OOXML "
                "structure is malformed. Corruption is possible; deliberate "
                "damage to defeat static analysis is common."
            ),
            evidence={"error": _clip(f"{exc.__class__.__name__}: {exc}")},
        ))
        return AnalyzerResult(
            analyzer=NAME, ran=True, signals=signals,
            facts={**facts, "parsed": False}, iocs=iocs,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    try:
        _TYPE_NAMES = {
            olevba.TYPE_OLE: "OLE2 (legacy)",
            olevba.TYPE_OpenXML: "OOXML (zip)",
            olevba.TYPE_Word2003_XML: "Word 2003 XML",
            olevba.TYPE_MHTML: "MHTML / Single File Web Page",
            olevba.TYPE_TEXT: "text",
            olevba.TYPE_PPT: "PowerPoint 97-2003",
            olevba.TYPE_SLK: "SYLK",
        }
        container = _TYPE_NAMES.get(getattr(vba_parser, "type", None), "unknown")
        facts["container"] = container
        facts["parsed"] = True

        # olevba falls back to TYPE_TEXT when it finds no OLE/OOXML structure and
        # is just scanning raw text for VBA. A genuine Office document is never
        # TYPE_TEXT — that content is the script analyzer's job, and claiming
        # "VBA present" on an arbitrary text file would be a false positive.
        if getattr(vba_parser, "type", None) == olevba.TYPE_TEXT:
            return AnalyzerResult.not_applicable(
                NAME, "plain text (no OLE/OOXML structure; handled by the script analyzer)"
            )

        is_ooxml = getattr(vba_parser, "type", None) == olevba.TYPE_OpenXML

        # --- encrypted? report, never crack ----------------------------------
        encrypted = False
        try:
            encrypted = bool(vba_parser.detect_is_encrypted())
        except Exception:
            encrypted = False
        facts["encrypted"] = encrypted
        if encrypted:
            signals.append(Signal(
                id="office.encrypted",
                title="Document is encrypted / password-protected",
                severity="medium",
                detail=(
                    "The document is encrypted. This analyzer does not and will "
                    "not attempt to crack it — a password supplied by an analyst "
                    "is a deliberate, audited act. Encryption on a delivered "
                    "document also defeats content inspection, which is itself "
                    "why phishing kits use it."
                ),
                evidence={},
            ))

        # --- VBA extraction (decompress source; never execute) ---------------
        modules: list[dict[str, Any]] = []
        all_code_parts: list[str] = []
        vba_present = False
        try:
            vba_present = bool(vba_parser.detect_vba_macros())
        except Exception:
            vba_present = False

        if vba_present and not encrypted:
            try:
                for (subfile, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    if vba_code is None:
                        continue
                    code = vba_code if isinstance(vba_code, str) else str(vba_code)
                    all_code_parts.append(code)
                    if len(modules) < MAX_MODULES:
                        modules.append({
                            "ole_subfile": _clip(subfile, 160),
                            "stream_path": _clip(stream_path, 160),
                            "vba_filename": _clip(vba_filename, 160),
                            "code_chars": len(code),
                            "code_excerpt": code[:MAX_MODULE_FACT_CHARS],
                            "code_truncated": len(code) > MAX_MODULE_FACT_CHARS,
                        })
            except Exception as exc:
                signals.append(Signal(
                    id="office.parse_failed",
                    title="VBA project present but source extraction failed",
                    severity="medium",
                    detail=(
                        "A VBA project was detected but its module source could "
                        "not be decompressed. This can indicate VBA stomping "
                        "(source stripped, only P-code left) or a corrupted "
                        "project."
                    ),
                    evidence={"error": _clip(f"{exc.__class__.__name__}: {exc}")},
                ))

        all_code = "\n".join(all_code_parts)
        scan_code = all_code[:MAX_SCAN_CHARS]
        facts["vba_present"] = vba_present
        facts["module_count"] = len(all_code_parts)
        facts["modules"] = modules
        facts["vba_scan_truncated"] = len(all_code) > MAX_SCAN_CHARS

        if vba_present:
            signals.append(Signal(
                id="office.vba_present",
                title="Document contains VBA macros",
                severity="low",
                detail=(
                    f"{len(all_code_parts)} VBA module(s) present. Macros are not "
                    "malicious in themselves; the value is in what they do and "
                    "whether they run automatically — see the other office.* "
                    "signals."
                ),
                evidence={"module_count": len(all_code_parts),
                          "modules": [m["vba_filename"] for m in modules][:24]},
            ))

        # --- olevba keyword analysis (corroboration + XLM/stomping) ----------
        olevba_keywords: dict[str, list[str]] = {}
        stomping = False
        xlm = False
        try:
            for (kw_type, keyword, description) in vba_parser.analyze_macros():
                olevba_keywords.setdefault(_clip(kw_type, 40), []).append(_clip(keyword, 120))
            stomping = bool(getattr(vba_parser, "vba_stomping_detected", False))
            xlm = bool(getattr(vba_parser, "contains_xlm_macros", False))
        except Exception:
            pass
        # cap the recorded keyword lists
        facts["olevba_keywords"] = {k: _dedup(v, 40) for k, v in olevba_keywords.items()}

        # --- auto-execution triggers -----------------------------------------
        triggers: list[str] = []
        seen_trig: set[str] = set()
        for name, pattern in _AUTOEXEC_TRIGGERS:
            if pattern.search(scan_code) and name not in seen_trig:
                seen_trig.add(name)
                triggers.append(name)
        # fold in olevba's AutoExec findings (it catches forms we do not)
        for keyword in olevba_keywords.get("AutoExec", []):
            if keyword not in seen_trig:
                seen_trig.add(keyword)
                triggers.append(keyword)
        facts["autoexec_triggers"] = triggers[:24]
        if triggers:
            signals.append(Signal(
                id="office.autoexec_macro",
                title="Macro runs automatically on open/close",
                severity="high",
                detail=(
                    "The document has an auto-execution trigger, so its macro "
                    "runs the moment the document is opened (or closed) with "
                    "macros enabled — no user action beyond opening is needed. "
                    f"Trigger(s): {', '.join(triggers[:8])}."
                ),
                evidence={"triggers": triggers[:24]},
            ))

        # --- obfuscation -----------------------------------------------------
        techniques = _obfuscation_techniques(scan_code) if scan_code else []
        for kw_type in ("VBA obfuscated Strings", "Hex String", "Base64 String", "Dridex String"):
            if olevba_keywords.get(kw_type):
                techniques.append(f"olevba: {kw_type} ({len(olevba_keywords[kw_type])})")
        if techniques:
            signals.append(Signal(
                id="office.macro_obfuscation",
                title="Macro source is obfuscated",
                severity="high" if len(techniques) >= 2 else "medium",
                detail=(
                    "The VBA source uses obfuscation to hide its behaviour from "
                    "static inspection. Obfuscation in a document macro has no "
                    "legitimate purpose. Techniques: " + "; ".join(techniques[:10]) + "."
                ),
                evidence={"techniques": techniques[:12]},
            ))

        # --- suspicious capabilities (one signal per capability) -------------
        if scan_code:
            for cap in _CAPABILITIES:
                matched = [label for label, pat in cap.patterns if pat.search(scan_code)]
                if matched:
                    signals.append(Signal(
                        id=f"office.macro_suspicious_call.{cap.suffix}",
                        title=cap.title,
                        severity=cap.severity,
                        detail=(
                            f"The macro reaches the '{cap.suffix}' capability. "
                            "Capability, not intent — the matched constructs are "
                            "listed. Combined with an auto-execution trigger this "
                            "is a self-launching payload."
                        ),
                        evidence={"capability": cap.suffix, "matched": matched[:12]},
                    ))

        # --- VBA stomping / XLM macros ---------------------------------------
        if stomping:
            signals.append(Signal(
                id="office.vba_stomping",
                title="VBA stomping detected",
                severity="high",
                detail=(
                    "The compiled P-code and the VBA source do not match. The "
                    "source shown here is not what Office will actually run — the "
                    "real logic is in the P-code, stripped of readable source to "
                    "defeat exactly this kind of analysis."
                ),
                evidence={},
            ))
        if xlm:
            signals.append(Signal(
                id="office.xlm_macro",
                title="Excel 4.0 (XLM) macro sheet present",
                severity="high",
                detail=(
                    "Excel 4.0 macros predate VBA and run from hidden macro "
                    "sheets. They are a favourite of modern maldocs precisely "
                    "because many tools only inspect VBA."
                ),
                evidence={},
            ))

        # --- OOXML external relationships + body, or OLE2 embedded + body ----
        external_rels: list[dict[str, str]] = []
        embedded: list[str] = []
        body_text = ""
        if is_ooxml:
            external_rels, body_text, embedded = _ooxml_relationships_and_body(sample.path)
        else:
            try:
                raw = sample.read(MAX_OLE_BODY_BYTES)
            except OSError:
                raw = b""
            embedded, _ = _ole_embedded_and_body(sample.path, raw)
            body_text = _ole_body_text(raw)

        facts["external_relationships"] = external_rels
        facts["embedded_objects"] = embedded

        if external_rels:
            signals.append(Signal(
                id="office.remote_template",
                title="External relationship target (remote template / remote object)",
                severity="high",
                detail=(
                    "The document references an external target with "
                    'TargetMode="External". This is the remote-template-injection '
                    "vector: opening the document fetches a template (or OLE "
                    "object) from a remote server, which can carry the actual "
                    "payload. No macro is required for this to fire."
                ),
                evidence={"targets": external_rels[:16]},
            ))
            # the target URLs are indicators in their own right
            iocs = iocs.merge(_extract_iocs(
                "\n".join(r["target"] for r in external_rels)
            ))

        if embedded:
            signals.append(Signal(
                id="office.embedded_object",
                title="Embedded / OLE object present",
                severity="medium",
                detail=(
                    "The document embeds an OLE object or package. Embedded "
                    "objects are a delivery mechanism: a packaged executable or "
                    "script the user is lured into double-clicking, or an object "
                    "that triggers an exploit on load."
                ),
                evidence={"objects": embedded[:16]},
            ))

        # --- DDE fields (code execution, no macro) ---------------------------
        try:
            from oletools import msodde

            dde_out = msodde.process_file(sample.path)
        except Exception:
            dde_out = ""
        dde_commands = [
            _clip(line, STR_LIMIT)
            for line in (dde_out or "").splitlines()
            if line.strip()
        ][:32]
        facts["dde_fields"] = dde_commands
        if dde_commands:
            signals.append(Signal(
                id="office.dde_field",
                title="DDE field present",
                severity="high",
                detail=(
                    "The document contains a DDE (Dynamic Data Exchange) field. "
                    "DDE fields execute external commands when the document is "
                    "opened and the user accepts the update prompt — code "
                    "execution with no macro at all."
                ),
                evidence={"commands": dde_commands[:12]},
            ))

        # --- IOCs from macro source and document body ------------------------
        if all_code:
            iocs = iocs.merge(_extract_iocs(all_code))
        if body_text:
            iocs = iocs.merge(_extract_iocs(body_text))
        iocs = iocs.merge(_extract_iocs(dde_out or ""))

        return AnalyzerResult(
            analyzer=NAME,
            ran=True,
            signals=signals,
            facts=facts,
            iocs=iocs,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    except Exception as exc:  # noqa: BLE001 — a hostile document fought back mid-parse
        signals.append(Signal(
            id="office.parse_failed",
            title="Document analysis aborted part-way",
            severity="medium",
            detail="The document opened but a later structure could not be walked.",
            evidence={"error": _clip(f"{exc.__class__.__name__}: {exc}")},
        ))
        return AnalyzerResult(
            analyzer=NAME, ran=True, signals=signals,
            facts={**facts, "parsed": "partial"}, iocs=iocs,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
    finally:
        try:
            vba_parser.close()
        except Exception:
            pass
