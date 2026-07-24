"""Disk-image static analysis for ISO9660 and raw disk/USB images.

Optical images (.iso) and raw block images (.img) are containers: what matters
is not the image itself but the files a victim would see once it is mounted or
burned. So this analyzer opens the container by reading its on-disk structures
and reports what is inside — an autorun entry, a bundled executable, a document
that is really a program — without ever mounting, loading or running anything.

For ISO9660 the Primary Volume Descriptor and the directory records are parsed
by hand, from the bytes. The layout is small and well documented, and hand
parsing buys the property a sandbox needs: a truncated or contradictory image
degrades into fewer findings, never into an exception from a library written to
read well-formed media rather than hostile ones.

For a raw image with no filesystem this analyzer cannot enumerate files, so it
falls back to scanning bounded chunks for embedded signatures (a PE at a sector
boundary, an ELF, a PDF, a Zip) and for readable strings.

Nothing here mounts, maps or runs the sample. It reads bytes and reports what
they say. Strings that look like URLs are extracted and never fetched.

References: ECMA-119 / ISO 9660 (Volume Descriptors, Directory Records).
"""
from __future__ import annotations

import re
import struct
import time
from typing import Any

from ..contracts import AnalyzerResult, IOCs, Sample, Signal

NAME = "diskimage"
#: identify.py family this analyzer claims.
FAMILY = "diskimage"

# --- bounds -------------------------------------------------------------------
# Every number below exists because the sample chose its own: a directory extent
# can claim a 4 GB size, a record can name a 255-byte file, a raw image can be a
# gigabyte of the same byte. The input is hostile; nothing is unbounded.

MAX_READ_BYTES = 64 * 1024 * 1024      # raw scan / string cap
MAX_DIR_BYTES = 2 * 1024 * 1024        # bytes read from a single directory extent
MAX_ENTRIES = 2000                     # total directory entries walked
MAX_DEPTH = 8                          # directory recursion depth
MAX_FILES_REPORTED = 250               # entries carried into facts
MAX_STRINGS = 20000
MIN_STRING_LEN = 6
MAX_STRING_LEN = 512
MAX_IOCS_PER_KIND = 50
MAX_SIG_HITS = 64                      # embedded-signature hits kept per scan
MAX_EVIDENCE_ITEMS = 16
EVIDENCE_TRUNCATE = 200
LARGE_FILE_BYTES = 10 * 1024 * 1024    # a "notable" large file
DEFAULT_BLOCK_SIZE = 2048

# --- ISO9660 constants --------------------------------------------------------

_ISO_MAGIC = b"CD001"
_ISO_MAGIC_OFFSET = 0x8001             # sector 16, byte 1
_PVD_OFFSET = 0x8000                   # Primary Volume Descriptor
_PVD_BLOCK_SIZE_OFFSET = 128           # u2 both-endian, logical block size
_PVD_ROOT_RECORD_OFFSET = 156          # root Directory Record, 34 bytes

_DR_FLAG_DIRECTORY = 0x02
_VALID_BLOCK_SIZES = (512, 1024, 2048, 4096, 8192)

# --- content sniffing ---------------------------------------------------------
# The first bytes of a file are enough to say what kind of thing it is. These are
# compared, never run.

_SNIFF_PE = b"MZ"
_SNIFF_ELF = b"\x7fELF"
_SNIFF_SCRIPT = b"#!"
_SNIFF_PDF = b"%PDF"
_SNIFF_ZIP = b"PK\x03\x04"

_EXECUTABLE_TYPES = ("pe", "elf")

# Extensions that carry code on a double-click.
_EXEC_EXTS = frozenset(
    "exe scr com bat cmd pif dll msi jar vbs vbe js jse ps1 psm1 hta cpl "
    "wsf wsh lnk gadget application reg".split()
)
# Extensions a victim reads as harmless data.
_DOC_EXTS = frozenset(
    "pdf doc docx xls xlsx ppt pptx txt rtf csv jpg jpeg png gif bmp tif tiff "
    "odt ods mp3 mp4 avi html htm".split()
)
# Extensions whose content is a script.
_SCRIPT_EXTS = frozenset(
    "bat cmd ps1 psm1 vbs vbe js jse wsf wsh sh py pl rb php hta".split()
)

# --- IOC extraction -----------------------------------------------------------
# Linear regexes over already length-bounded strings: no nested quantifiers.

_RE_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^\s\"'<>\\]{1,300}")
_RE_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_RE_STRINGS = re.compile(rb"[\x20-\x7e]{%d,%d}" % (MIN_STRING_LEN, MAX_STRING_LEN))


def _clip(text: str, limit: int = EVIDENCE_TRUNCATE) -> str:
    text = text.replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "..."


def _u32le(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(blob):
        return 0
    return struct.unpack_from("<I", blob, offset)[0]


def _u16le(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(blob):
        return 0
    return struct.unpack_from("<H", blob, offset)[0]


def _valid_ip(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o > 255 for o in octets):
        return False
    if any(len(p) > 1 and p[0] == "0" for p in parts):  # version strings, not IPs
        return False
    if octets[0] in (0, 127) or octets == [255, 255, 255, 255]:
        return False
    return True


def _harvest_iocs(data: bytes) -> IOCs:
    urls: dict[str, None] = {}
    ips: dict[str, None] = {}
    seen = 0
    for m in _RE_STRINGS.finditer(data):
        if seen >= MAX_STRINGS:
            break
        seen += 1
        text = m.group().decode("ascii", "replace")
        if len(urls) < MAX_IOCS_PER_KIND:
            for um in _RE_URL.finditer(text):
                urls.setdefault(_clip(um.group(), 300), None)
                if len(urls) >= MAX_IOCS_PER_KIND:
                    break
        if len(ips) < MAX_IOCS_PER_KIND:
            for im in _RE_IP.finditer(text):
                value = im.group()
                if _valid_ip(value):
                    ips.setdefault(value, None)
                if len(ips) >= MAX_IOCS_PER_KIND:
                    break
        if len(urls) >= MAX_IOCS_PER_KIND and len(ips) >= MAX_IOCS_PER_KIND:
            break
    return IOCs(urls=list(urls), ips=list(ips))


# --- filename reasoning -------------------------------------------------------


def _clean_name(raw: bytes) -> str:
    """A displayable name out of an ISO file identifier, version stripped."""
    text = raw.decode("ascii", "replace")
    semi = text.find(";")            # ISO version suffix, e.g. ";1"
    if semi != -1:
        text = text[:semi]
    if text.endswith("."):
        text = text[:-1]
    return text


def _extensions(name: str) -> list[str]:
    parts = name.lower().split(".")
    return parts[1:] if len(parts) > 1 else []


def _double_extension(name: str) -> bool:
    exts = _extensions(name)
    return len(exts) >= 2 and exts[-1] in _EXEC_EXTS and exts[-2] in _DOC_EXTS


def _looks_like_document(name: str) -> bool:
    exts = _extensions(name)
    return bool(exts) and exts[-1] in _DOC_EXTS


def _is_script_name(name: str) -> bool:
    exts = _extensions(name)
    return bool(exts) and exts[-1] in _SCRIPT_EXTS


# --- ISO9660 parsing ----------------------------------------------------------


def _sniff(data: bytes, offset: int) -> str | None:
    if offset < 0 or offset >= len(data):
        return None
    head = data[offset:offset + 16]
    if head.startswith(_SNIFF_PE):
        return "pe"
    if head.startswith(_SNIFF_ELF):
        return "elf"
    if head.startswith(_SNIFF_SCRIPT):
        return "script"
    if head.startswith(_SNIFF_PDF):
        return "pdf"
    if head.startswith(_SNIFF_ZIP):
        return "zip"
    return None


def _walk_iso(data: bytes, lba: int, size: int, block_size: int) -> list[dict[str, Any]]:
    """Bounded, depth-limited walk of the ISO directory tree."""
    entries: list[dict[str, Any]] = []

    def recurse(lba: int, size: int, depth: int) -> None:
        if depth > MAX_DEPTH or len(entries) >= MAX_ENTRIES:
            return
        start = lba * block_size
        if start < 0 or start >= len(data) or size <= 0:
            return
        block = data[start:start + min(size, MAX_DIR_BYTES)]
        pos = 0
        while pos < len(block):
            if len(entries) >= MAX_ENTRIES:
                return
            rec_len = block[pos]
            if rec_len == 0:
                # A zero length is padding to the next logical block; records
                # never straddle a block boundary.
                nxt = ((pos // block_size) + 1) * block_size
                if nxt <= pos:
                    break
                pos = nxt
                continue
            if rec_len < 34 or pos + rec_len > len(block):
                break
            ext_attr_len = block[pos + 1]
            child_lba = _u32le(block, pos + 2)
            data_len = _u32le(block, pos + 10)
            flags = block[pos + 25]
            name_len = block[pos + 32]
            name_bytes = block[pos + 33:pos + 33 + name_len]
            rec_start = pos
            pos += rec_len

            # "." (0x00) and ".." (0x01) self/parent records.
            if name_len == 1 and name_bytes in (b"\x00", b"\x01"):
                continue
            if not name_bytes:
                continue

            is_dir = bool(flags & _DR_FLAG_DIRECTORY)
            name = _clean_name(name_bytes)
            content_lba = child_lba + ext_attr_len
            sniff = None if is_dir else _sniff(data, content_lba * block_size)
            entries.append(
                {
                    "name": name,
                    "size": int(data_len),
                    "is_dir": is_dir,
                    "sniff": sniff,
                }
            )
            if is_dir and child_lba != lba and rec_start != 0:
                recurse(content_lba, data_len, depth + 1)

    recurse(lba, size, 0)
    return entries


def _analyze_iso(data: bytes, facts: dict[str, Any]) -> tuple[list[Signal], IOCs]:
    signals: list[Signal] = []

    block_size = _u16le(data, _PVD_OFFSET + _PVD_BLOCK_SIZE_OFFSET)
    if block_size not in _VALID_BLOCK_SIZES:
        block_size = DEFAULT_BLOCK_SIZE
    facts["block_size"] = block_size

    root = _PVD_OFFSET + _PVD_ROOT_RECORD_OFFSET
    root_lba = _u32le(data, root + 2)
    root_size = _u32le(data, root + 10)

    entries = _walk_iso(data, root_lba, root_size, block_size)

    files = [e for e in entries if not e["is_dir"]]
    facts["file_count"] = len(files)
    facts["entry_count"] = len(entries)
    facts["files"] = [
        {"name": _clip(e["name"], 120), "size": e["size"]}
        for e in entries[:MAX_FILES_REPORTED]
    ]

    embedded_types = sorted({e["sniff"] for e in files if e["sniff"]})
    facts["embedded_types"] = embedded_types

    # --- embedded executable --------------------------------------------------
    exec_files = [e for e in files if e["sniff"] in _EXECUTABLE_TYPES]
    if exec_files:
        signals.append(
            Signal(
                id="diskimage.embedded_executable",
                title="Executable bundled inside the image",
                severity="high",
                detail=(
                    f"{len(exec_files)} file(s) inside the image begin with an "
                    "executable header (PE or ELF). An image is a delivery wrapper; "
                    "the payload is whatever runs once it is mounted or burned."
                ),
                evidence={
                    "files": [
                        {"name": _clip(e["name"], 120), "type": e["sniff"], "size": e["size"]}
                        for e in exec_files[:MAX_EVIDENCE_ITEMS]
                    ]
                },
            )
        )

    # --- autorun --------------------------------------------------------------
    autorun = [e for e in entries if e["name"].lower() == "autorun.inf"]
    if autorun:
        signals.append(
            Signal(
                id="diskimage.autorun",
                title="autorun.inf present",
                severity="high",
                detail=(
                    "The image carries an autorun.inf. On a burned disc or a mounted "
                    "image this file tells Windows which program to launch, which is "
                    "the classic mechanism for making inserted media run code by "
                    "itself."
                ),
                evidence={"names": [_clip(e["name"], 120) for e in autorun[:MAX_EVIDENCE_ITEMS]]},
            )
        )

    # --- scripts --------------------------------------------------------------
    scripts = [e for e in files if e["sniff"] == "script" or _is_script_name(e["name"])]
    if scripts:
        signals.append(
            Signal(
                id="diskimage.script_present",
                title="Script files inside the image",
                severity="medium",
                detail=(
                    f"{len(scripts)} script file(s) are present. Scripts on removable "
                    "media are commonly the launcher that an autorun entry or a lured "
                    "double-click hands control to."
                ),
                evidence={
                    "files": [_clip(e["name"], 120) for e in scripts[:MAX_EVIDENCE_ITEMS]]
                },
            )
        )

    # --- disguised filenames --------------------------------------------------
    disguised: list[dict[str, str]] = []
    for e in files:
        if _double_extension(e["name"]):
            disguised.append({"name": _clip(e["name"], 120), "reason": "double extension"})
        elif e["sniff"] in _EXECUTABLE_TYPES and _looks_like_document(e["name"]):
            disguised.append(
                {"name": _clip(e["name"], 120), "reason": "executable named like a document"}
            )
    if disguised:
        signals.append(
            Signal(
                id="diskimage.suspicious_filename",
                title="Files disguised as documents",
                severity="medium",
                detail=(
                    "Filenames use a trailing executable extension behind a document "
                    "one, or an executable is named like a document. This is a social "
                    "trick: the victim reads the first extension and double-clicks a "
                    "program."
                ),
                evidence={"files": disguised[:MAX_EVIDENCE_ITEMS]},
            )
        )

    # --- notable large files --------------------------------------------------
    large = sorted(
        (e for e in files if e["size"] >= LARGE_FILE_BYTES),
        key=lambda e: -e["size"],
    )
    if large:
        signals.append(
            Signal(
                id="diskimage.large_binary",
                title="Notably large files inside the image",
                severity="info",
                detail=(
                    "Large files can be padding to defeat size-limited scanners or the "
                    "bulk payload itself. Noted as context, not as a verdict."
                ),
                evidence={
                    "files": [
                        {"name": _clip(e["name"], 120), "size": e["size"]}
                        for e in large[:MAX_EVIDENCE_ITEMS]
                    ]
                },
            )
        )

    iocs = _harvest_iocs(data)
    _emit_url_signal(signals, iocs)
    return signals, iocs


# --- raw image parsing --------------------------------------------------------


def _is_pe_at(data: bytes, offset: int) -> bool:
    if offset < 0 or offset + 0x40 > len(data):
        return False
    if data[offset:offset + 2] != _SNIFF_PE:
        return False
    e_lfanew = _u32le(data, offset + 0x3C)
    if e_lfanew <= 0 or e_lfanew > 0x10000:
        return False
    pe = offset + e_lfanew
    if pe + 4 > len(data):
        return False
    return data[pe:pe + 4] == b"PE\x00\x00"


def _scan_raw(data: bytes, facts: dict[str, Any]) -> tuple[list[Signal], IOCs]:
    signals: list[Signal] = []
    found: dict[str, list[int]] = {}

    def note(kind: str, offset: int) -> None:
        bucket = found.setdefault(kind, [])
        if len(bucket) < MAX_SIG_HITS:
            bucket.append(offset)

    # PE at a 512-byte (sector) boundary, header-validated to keep false
    # positives down — "MZ" alone is two common bytes.
    for offset in range(0, len(data), 512):
        if len(found.get("pe", [])) >= MAX_SIG_HITS:
            break
        if data[offset:offset + 2] == _SNIFF_PE and _is_pe_at(data, offset):
            note("pe", offset)

    for kind, magic in (("elf", _SNIFF_ELF), ("pdf", _SNIFF_PDF), ("zip", _SNIFF_ZIP)):
        pos = data.find(magic)
        while pos != -1 and len(found.get(kind, [])) < MAX_SIG_HITS:
            note(kind, pos)
            pos = data.find(magic, pos + len(magic))

    embedded_types = sorted(found)
    facts["file_count"] = 0
    facts["files"] = []
    facts["embedded_types"] = embedded_types
    facts["signature_offsets"] = {
        kind: offsets[:MAX_EVIDENCE_ITEMS] for kind, offsets in found.items()
    }

    exec_kinds = [k for k in ("pe", "elf") if found.get(k)]
    if exec_kinds:
        signals.append(
            Signal(
                id="diskimage.embedded_executable",
                title="Executable embedded in the raw image",
                severity="high",
                detail=(
                    "The raw image contains "
                    + ", ".join(
                        f"{len(found[k])} {k.upper()} header(s)" for k in exec_kinds
                    )
                    + ". A raw disk or USB image with a bundled executable is a way to "
                    "carry a payload onto a machine as innocuous-looking media."
                ),
                evidence={
                    k: found[k][:MAX_EVIDENCE_ITEMS] for k in exec_kinds
                },
            )
        )

    iocs = _harvest_iocs(data)
    _emit_url_signal(signals, iocs)
    return signals, iocs


# --- shared -------------------------------------------------------------------


def _emit_url_signal(signals: list[Signal], iocs: IOCs) -> None:
    if not iocs.urls and not iocs.ips:
        return
    signals.append(
        Signal(
            id="diskimage.embedded_url",
            title="URLs or IPs in the image",
            severity="info",
            detail=(
                "Network indicators were recovered from readable strings inside the "
                "image. They are extracted for triage and were never contacted."
            ),
            evidence={
                "urls": iocs.urls[:MAX_EVIDENCE_ITEMS],
                "ips": iocs.ips[:MAX_EVIDENCE_ITEMS],
            },
        )
    )


# --- entry point --------------------------------------------------------------


def analyze(sample: Sample) -> AnalyzerResult:
    started = time.monotonic()

    def finish(result: AnalyzerResult) -> AnalyzerResult:
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    try:
        data = sample.read(MAX_READ_BYTES)
    except OSError as exc:
        return finish(
            AnalyzerResult.unavailable(NAME, f"sample unreadable: {type(exc).__name__}")
        )

    try:
        is_iso = data[_ISO_MAGIC_OFFSET:_ISO_MAGIC_OFFSET + len(_ISO_MAGIC)] == _ISO_MAGIC
        facts: dict[str, Any] = {
            "format": "iso9660" if is_iso else "raw",
            "truncated_read": sample.size_bytes > MAX_READ_BYTES,
            "bytes_examined": len(data),
        }
        if is_iso:
            signals, iocs = _analyze_iso(data, facts)
        else:
            signals, iocs = _scan_raw(data, facts)
    except Exception as exc:  # noqa: BLE001 — a hostile image must not raise
        return finish(
            AnalyzerResult.unavailable(
                NAME, f"parse failed: {type(exc).__name__}: {_clip(str(exc), 120)}"
            )
        )

    return finish(
        AnalyzerResult(analyzer=NAME, ran=True, signals=signals, facts=facts, iocs=iocs)
    )
