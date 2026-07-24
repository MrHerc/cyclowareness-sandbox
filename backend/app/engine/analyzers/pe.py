"""Static analysis of Windows PE images (.exe / .dll / .sys).

The sample is never executed, never loaded, never imported. `pefile` parses the
headers as data and that is the whole of the interaction with it.

What this module claims and does not claim:

* It reports *structure*: what the header says, what the section table looks
  like, which capabilities the import table makes available. Structure is
  evidence, not a verdict — a packed binary with injection imports is a
  description, and the score is somebody else's job (see contracts.Signal).
* It never validates a signature chain. `pe.signature_present` means the
  security directory is non-empty, nothing more. An invalid or stolen
  certificate is still "present", and pretending otherwise would be the exact
  kind of confident-and-wrong a security tool must not be.
* Every limit here is a denial-of-service limit. A malformed PE is a sample that
  wants the analyzer to allocate 4 GB or recurse forever; bounds are not
  politeness, they are the defence.
"""
from __future__ import annotations

import math
import re
import time
from datetime import datetime, timezone
from typing import Any, Iterable

from ..contracts import AnalyzerResult, IOCs, Sample, Signal

NAME = "pe"

#: Mimes identify.py assigns to the PE family.
_PE_MIMES = frozenset({"application/x-dosexec"})

# --- bounds -------------------------------------------------------------------
#: Entropy is measured on at most this much of a section. A packer fills the
#: whole section, so a 1 MiB window is representative, and a 300 MiB virtual
#: section cannot make us walk 300 MiB.
MAX_ENTROPY_BYTES = 1 * 1024 * 1024
#: How much of the file the string/IOC scan reads.
MAX_IOC_SCAN_BYTES = 8 * 1024 * 1024
MAX_SECTIONS_RECORDED = 96
MAX_IMPORT_FUNCS_RECORDED = 400
MAX_IMPORT_FUNCS_SCANNED = 8000
MAX_EXPORTS_RECORDED = 200
MAX_RESOURCE_TYPES = 32
MAX_IOCS_PER_KIND = 64
#: Any sample-derived string that reaches a Signal is cut to this.
STR_LIMIT = 200

#: Entropy above which an *executable* section is treated as packed/encrypted.
ENTROPY_PACKED = 7.2
#: Below ~10 imported functions on a native binary the import table has been
#: packed away — a real Win32 program cannot do anything with fewer.
FEW_IMPORTS_THRESHOLD = 10

#: PE section characteristics.
_SCN_CNT_CODE = 0x00000020
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000

_FILE_DLL = 0x2000

#: Timestamps outside this window are a tampered or absurd header. The lower
#: bound predates Win95; the upper is "the future", allowing a day of clock skew.
_TS_FLOOR = datetime(1995, 1, 1, tzinfo=timezone.utc).timestamp()

#: Section names that only ever come from a packer or a protector.
_PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx0": "UPX", ".upx1": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", "aspack": "ASPack",
    ".themida": "Themida", ".winlice": "WinLicense", ".vmp0": "VMProtect",
    ".vmp1": "VMProtect", ".vmp2": "VMProtect", ".enigma1": "Enigma",
    ".enigma2": "Enigma", ".petite": "Petite", ".mpress1": "MPRESS",
    ".mpress2": "MPRESS", ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".packed": "generic packer", ".pelock": "PELock", "pebundle": "PEBundle",
    ".mew": "MEW", ".fsg": "FSG", ".boom": "BoomBinder", ".taz": "PESpin",
    ".rlp": "RLPack", "kkrunchy": "kkrunchy",
}

#: Capability groups. Matching is prefix-based on the lowercased API name, so
#: one entry covers the A/W/Ex variants. `min_hits` is what stops a single
#: ubiquitous API from claiming a capability on its own.
_CAPABILITIES: tuple[tuple[str, str, str, int, tuple[str, ...]], ...] = (
    (
        "process_injection", "Process injection primitives imported", "high", 2,
        ("virtualallocex", "writeprocessmemory", "createremotethread",
         "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc",
         "ntqueueapcthread", "setthreadcontext", "getthreadcontext",
         "ntunmapviewofsection", "ntmapviewofsection", "ntwritevirtualmemory",
         "ntallocatevirtualmemory", "virtualprotectex", "openprocess",
         "resumethread", "createprocessinternal"),
    ),
    (
        "dynamic_resolution", "Resolves its own API addresses at runtime", "medium", 2,
        ("loadlibrary", "getprocaddress", "ldrloaddll",
         "ldrgetprocedureaddress", "ldrgetdllhandle", "getmodulehandle"),
    ),
    (
        "anti_debug", "Anti-debugging / anti-analysis checks", "medium", 1,
        ("isdebuggerpresent", "checkremotedebuggerpresent",
         "ntqueryinformationprocess", "outputdebugstring",
         "ntsetinformationthread", "debugactiveprocess",
         "zwqueryinformationprocess", "ntqueryobject"),
    ),
    (
        "persistence", "Writes persistence (registry / service)", "medium", 1,
        ("regsetvalue", "ntsetvaluekey", "zwsetvaluekey", "regcreatekey",
         "createservice", "startservice", "openscmanager",
         "changeserviceconfig"),
    ),
    (
        "keylogging", "Keyboard / input capture", "high", 1,
        # GetForegroundWindow / AttachThreadInput are the classic companions but
        # they are also ordinary UI code, so they are not in here: a keylogging
        # finding at "high" has to rest on an API with no innocent reading.
        ("setwindowshookex", "getasynckeystate", "getkeyboardstate",
         "getkeynametext", "getrawinputdata", "registerrawinputdevices"),
    ),
    (
        "crypto", "Cryptographic API use", "medium", 1,
        ("cryptencrypt", "cryptdecrypt", "cryptacquirecontext", "cryptgenkey",
         "cryptderivekey", "cryptimportkey", "cryptcreatehash",
         "bcrypt", "ncrypt"),
    ),
    (
        "network", "Network / download capability", "low", 1,
        ("winhttp", "internetopen", "internetconnect", "internetreadfile",
         "httpopenrequest", "httpsendrequest", "urldownloadtofile",
         "wsastartup", "wsasocket", "wsaconnect", "gethostbyname",
         "getaddrinfo", "inet_addr", "ftpputfile", "ftpgetfile",
         "dnsquery", "socket", "connect", "send", "recv"),
    ),
)

# `persistence` deliberately keeps RegCreateKey, which is common in benign
# software; it never fires alone at high severity, and the matched APIs travel
# with the signal so an analyst can dismiss it in one glance.

_URL_RE = re.compile(rb"(?i)\b(?:https?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{3,512}")
#: Candidate host tokens, validated in Python afterwards — a single flat
#: character class cannot backtrack, unlike a nested-quantifier domain regex.
_HOST_RE = re.compile(rb"(?i)\b[A-Za-z0-9][A-Za-z0-9.\-]{2,252}\.[A-Za-z]{2,18}\b")
_IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

#: Restricting host extraction to real TLDs is what keeps `kernel32.dll` and
#: `msvcrt.dll` out of the domain list.
_TLDS = frozenset("""
com net org info biz io co ru cn de uk eu fr nl br in ir jp it pl us ca au ch se
no fi dk es cz gr be at pt hu ro tr ua kz by az ge tv cc me ws su xyz top club
online site shop live app dev cloud space website tech store fun icu pro link
vip work life world today one asia mobi name gov edu mil int ly gg to sh st cf
ga ml tk pw cx nu is ee lv lt sk si hr rs bg md am uz kg tj tm mn kr tw hk sg my
th vn id ph nz za ng ke eg sa ae qa kw il pk bd lk np mm kh la
""".split())

#: Never emitted as IOCs — they are what a PE contains by construction.
_HOST_NOISE = frozenset({
    "schemas.microsoft.com", "www.w3.org", "schemas.xmlsoap.org",
    "schemas.openxmlformats.org", "crl.microsoft.com", "www.microsoft.com",
    "go.microsoft.com", "ocsp.digicert.com", "crl3.digicert.com",
    "crl4.digicert.com", "www.digicert.com", "sectigo.com",
})


# --- small helpers ------------------------------------------------------------

def _clean(value: Any, limit: int = STR_LIMIT) -> str:
    """Sample-derived text, made safe to put in a Signal or a JSON fact."""
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    else:
        text = str(value)
    text = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    return text[:limit]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    result = 0.0
    for count in counts:
        if count:
            p = count / total
            result -= p * math.log2(p)
    return round(result, 3)


def _take(items: Iterable[str], limit: int) -> list[str]:
    out: list[str] = []
    for item in items:
        if len(out) >= limit:
            break
        out.append(item)
    return out


def _dedup(values: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return list(seen)


# --- IOC extraction -----------------------------------------------------------

def _valid_host(host: str) -> bool:
    if len(host) > 253 or host.count(".") < 1:
        return False
    labels = host.split(".")
    if labels[-1].lower() not in _TLDS:
        return False
    if any(not label or len(label) > 63 for label in labels):
        return False
    if host.lower() in _HOST_NOISE:
        return False
    # "1.2.3.4" style tokens are handled by the IP extractor.
    return not labels[0].isdigit()


def _valid_ip(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o > 255 for o in octets) or any(len(p) > 3 for p in parts):
        return False
    if octets[0] in (0, 127, 255) or octets == [255, 255, 255, 255]:
        return False
    # Version strings ("6.1.7601.0") are the dominant false positive in a PE;
    # a leading octet under 10 with a zero somewhere is almost always one.
    if octets[0] < 10 and 0 in octets[1:]:
        return False
    return True


def _extract_iocs(data: bytes) -> IOCs:
    """URLs / hosts / IPs from the raw image, ASCII and UTF-16LE.

    Extraction only. Nothing here is resolved, fetched or contacted.
    """
    blobs = [data]
    if b"\x00" in data[:4096]:
        # Wide strings, read on both alignments — far cheaper than a real
        # UTF-16 decode and it finds the same indicators.
        blobs.append(data[0::2])
        blobs.append(data[1::2])

    urls: list[str] = []
    hosts: list[str] = []
    ips: list[str] = []

    for blob in blobs:
        for match in _URL_RE.finditer(blob):
            url = match.group(0).decode("latin-1").rstrip(".,);'\"")
            if len(url) > 8:
                urls.append(url[:512])
            if len(urls) > MAX_IOCS_PER_KIND * 4:
                break
        for match in _HOST_RE.finditer(blob):
            host = match.group(0).decode("latin-1").strip(".")
            if _valid_host(host):
                hosts.append(host.lower())
            if len(hosts) > MAX_IOCS_PER_KIND * 8:
                break
        for match in _IPV4_RE.finditer(blob):
            ip = match.group(0).decode("latin-1")
            if _valid_ip(ip):
                ips.append(ip)
            if len(ips) > MAX_IOCS_PER_KIND * 8:
                break

    # A host that only ever appeared inside a URL we already have is not a
    # second indicator, but we still list it — the domain field is what
    # blocklists are keyed on.
    for url in urls:
        rest = url.split("://", 1)[-1]
        host = rest.split("/", 1)[0].split(":", 1)[0].split("@")[-1]
        if _valid_host(host):
            hosts.append(host.lower())

    return IOCs(
        urls=_take(_dedup(urls), MAX_IOCS_PER_KIND),
        domains=_take(_dedup(hosts), MAX_IOCS_PER_KIND),
        ips=_take(_dedup(ips), MAX_IOCS_PER_KIND),
    )


# --- header facts -------------------------------------------------------------

def _lookup(table: Any, value: int, prefix: str) -> str:
    try:
        name = table.get(value)
    except Exception:
        name = None
    if not isinstance(name, str):
        return f"{prefix}_UNKNOWN_0x{value:04x}"
    return name


def _section_facts(pe_obj: Any) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for section in (pe_obj.sections or [])[:MAX_SECTIONS_RECORDED]:
        try:
            raw = section.get_data(length=MAX_ENTROPY_BYTES) or b""
        except Exception:
            raw = b""
        flags = int(getattr(section, "Characteristics", 0) or 0)
        sections.append({
            "name": _clean(getattr(section, "Name", b"").rstrip(b"\x00"), 32),
            "virtual_address": int(getattr(section, "VirtualAddress", 0) or 0),
            "virtual_size": int(getattr(section, "Misc_VirtualSize", 0) or 0),
            "raw_size": int(getattr(section, "SizeOfRawData", 0) or 0),
            "raw_offset": int(getattr(section, "PointerToRawData", 0) or 0),
            "entropy": _entropy(raw),
            "entropy_sampled_bytes": len(raw),
            "characteristics": flags,
            "executable": bool(flags & (_SCN_MEM_EXECUTE | _SCN_CNT_CODE)),
            "writable": bool(flags & _SCN_MEM_WRITE),
            "readable": bool(flags & _SCN_MEM_READ),
        })
    return sections


def _import_facts(pe_obj: Any) -> tuple[list[str], list[str], int]:
    """(dll names, "dll!func" strings, total functions seen)."""
    dlls: list[str] = []
    funcs: list[str] = []
    total = 0
    for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in getattr(pe_obj, attr, None) or []:
            try:
                dll = _clean(getattr(entry, "dll", b"") or b"", 64)
                dlls.append(dll)
                for imp in getattr(entry, "imports", None) or []:
                    if total >= MAX_IMPORT_FUNCS_SCANNED:
                        return _dedup(dlls), funcs, total
                    total += 1
                    name = getattr(imp, "name", None)
                    label = _clean(name, 96) if name else f"ordinal_{getattr(imp, 'ordinal', 0)}"
                    if len(funcs) < MAX_IMPORT_FUNCS_RECORDED:
                        funcs.append(f"{dll}!{label}")
            except Exception:
                continue
    return _dedup(dlls), funcs, total


def _imported_names(pe_obj: Any) -> list[str]:
    names: list[str] = []
    for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in getattr(pe_obj, attr, None) or []:
            for imp in getattr(entry, "imports", None) or []:
                if len(names) >= MAX_IMPORT_FUNCS_SCANNED:
                    return names
                raw = getattr(imp, "name", None)
                if raw:
                    names.append(_clean(raw, 96))
    return names


def _resource_facts(pe_obj: Any) -> dict[str, Any]:
    root = getattr(pe_obj, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return {"present": False, "types": [], "count": 0}
    types: list[str] = []
    count = 0
    try:
        import pefile

        for entry in (root.entries or [])[:MAX_RESOURCE_TYPES]:
            count += 1
            if getattr(entry, "name", None) is not None:
                types.append(_clean(str(entry.name), 48))
            else:
                rid = int(getattr(entry, "id", 0) or 0)
                types.append(pefile.RESOURCE_TYPE.get(rid) or f"RT_UNKNOWN_{rid}")
    except Exception:
        pass
    return {"present": True, "types": _dedup(types), "count": count}


# --- the analyzer -------------------------------------------------------------

def handles(sample: Sample) -> bool:
    if sample.mime in _PE_MIMES:
        return True
    try:
        return sample.read(2) == b"MZ"
    except OSError:
        return False


def analyze(sample: Sample) -> AnalyzerResult:
    started = time.monotonic()

    try:
        import pefile
    except Exception as exc:  # pragma: no cover - dependency is pinned
        return AnalyzerResult.unavailable(NAME, f"pefile is not importable: {exc!r}")

    if not handles(sample):
        return AnalyzerResult.not_applicable(NAME, sample.mime or "unknown")

    try:
        data = sample.read(MAX_IOC_SCAN_BYTES)
    except OSError as exc:
        return AnalyzerResult.unavailable(NAME, f"sample unreadable: {exc.__class__.__name__}")

    signals: list[Signal] = []
    facts: dict[str, Any] = {"file_size": sample.size_bytes}

    pe_obj = None
    try:
        # fast_load: parse the headers now, and only the data directories we
        # actually use, each behind its own try. A crafted resource tree is a
        # classic pefile resource exhaustion, so it is opt-in and bounded.
        pe_obj = pefile.PE(sample.path, fast_load=True)
    except Exception as exc:
        signals.append(Signal(
            id="pe.parse_failed",
            title="PE header could not be parsed",
            severity="high",
            detail=(
                "The file begins with MZ but its PE structure is malformed. "
                "Corruption is possible; deliberate header damage to defeat "
                "static analysis is more common."
            ),
            evidence={"error": _clean(f"{exc.__class__.__name__}: {exc}", STR_LIMIT)},
        ))
        iocs = _extract_iocs(data)
        return AnalyzerResult(
            analyzer=NAME, ran=True, signals=signals,
            facts={**facts, "parsed": False},
            iocs=iocs,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    try:
        return _analyze_parsed(sample, data, pe_obj, pefile, signals, facts, started)
    except Exception as exc:
        # We got a header but something below it fought back. That is still an
        # observation, not a clean result.
        signals.append(Signal(
            id="pe.parse_failed",
            title="PE parsing aborted part-way",
            severity="medium",
            detail="Headers parsed but a later structure could not be walked.",
            evidence={"error": _clean(f"{exc.__class__.__name__}: {exc}", STR_LIMIT)},
        ))
        return AnalyzerResult(
            analyzer=NAME, ran=True, signals=signals,
            facts={**facts, "parsed": "partial"},
            iocs=_extract_iocs(data),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    finally:
        try:
            pe_obj.close()
        except Exception:
            pass


def _analyze_parsed(
    sample: Sample,
    data: bytes,
    pe_obj: Any,
    pefile: Any,
    signals: list[Signal],
    facts: dict[str, Any],
    started: float,
) -> AnalyzerResult:
    for directory in (
        "IMAGE_DIRECTORY_ENTRY_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_EXPORT",
        "IMAGE_DIRECTORY_ENTRY_RESOURCE",
        "IMAGE_DIRECTORY_ENTRY_TLS",
        "IMAGE_DIRECTORY_ENTRY_SECURITY",
        "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
    ):
        try:
            pe_obj.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY[directory]]
            )
        except Exception:
            continue

    file_header = pe_obj.FILE_HEADER
    opt = pe_obj.OPTIONAL_HEADER
    characteristics = int(getattr(file_header, "Characteristics", 0) or 0)
    is_dll = bool(characteristics & _FILE_DLL)

    facts["parsed"] = True
    facts["machine"] = _lookup(pefile.MACHINE_TYPE, int(file_header.Machine), "MACHINE")
    facts["subsystem"] = _lookup(pefile.SUBSYSTEM_TYPE, int(opt.Subsystem), "SUBSYSTEM")
    facts["is_dll"] = is_dll
    facts["is_driver"] = facts["subsystem"] == "IMAGE_SUBSYSTEM_NATIVE"
    facts["is_64bit"] = int(opt.Magic) == 0x20B
    facts["entry_point_rva"] = int(opt.AddressOfEntryPoint)
    facts["image_base"] = int(opt.ImageBase)
    facts["characteristics"] = characteristics

    # --- timestamp ------------------------------------------------------------
    timestamp = int(getattr(file_header, "TimeDateStamp", 0) or 0)
    facts["timestamp_raw"] = timestamp
    compiled_at = None
    try:
        compiled_at = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        compiled_at = None
    facts["compiled_at"] = compiled_at

    now = time.time()
    if timestamp == 0:
        _ts_signal(signals, "zeroed", timestamp, compiled_at)
    elif timestamp > now + 86400:
        _ts_signal(signals, "in the future", timestamp, compiled_at)
    elif timestamp < _TS_FLOOR:
        _ts_signal(signals, "implausibly old", timestamp, compiled_at)

    # --- sections -------------------------------------------------------------
    sections = _section_facts(pe_obj)
    facts["sections"] = sections
    facts["section_count"] = len(pe_obj.sections or [])

    packed = [s for s in sections if s["executable"] and s["entropy"] > ENTROPY_PACKED]
    if packed:
        signals.append(Signal(
            id="pe.high_entropy_section",
            title="Executable section is packed or encrypted",
            severity="high",
            detail=(
                f"{len(packed)} executable section(s) measure above {ENTROPY_PACKED} "
                "bits/byte, which compiled code does not. The real code is "
                "unpacked in memory at runtime and is not visible here."
            ),
            evidence={"sections": [
                {"name": s["name"], "entropy": s["entropy"], "raw_size": s["raw_size"]}
                for s in packed[:16]
            ]},
        ))

    stubs = [
        s for s in sections
        if s["raw_size"] == 0 and s["virtual_size"] >= 0x1000
    ]
    if stubs:
        signals.append(Signal(
            id="pe.section_size_anomaly",
            title="Section reserves memory but carries no data on disk",
            severity="high",
            detail=(
                "A section with zero raw size and a large virtual size is space "
                "reserved for content that only exists after unpacking. It is the "
                "standard shape of a packer stub."
            ),
            evidence={"sections": [
                {"name": s["name"], "raw_size": 0, "virtual_size": s["virtual_size"]}
                for s in stubs[:16]
            ]},
        ))

    wx = [s for s in sections if s["writable"] and s["executable"]]
    if wx:
        signals.append(Signal(
            id="pe.writable_executable_section",
            title="Section is both writable and executable",
            severity="medium",
            detail=(
                "W+X sections let a program rewrite its own code. Compilers do "
                "not emit this; unpackers and self-modifying stubs need it."
            ),
            evidence={"sections": [s["name"] for s in wx[:16]]},
        ))

    packers = {
        s["name"]: _PACKER_SECTIONS[s["name"].lower()]
        for s in sections if s["name"].lower() in _PACKER_SECTIONS
    }
    if packers:
        signals.append(Signal(
            id="pe.packer_section_name",
            title="Section names belong to a known packer",
            severity="medium",
            detail="Section naming matches a commodity packer or protector.",
            evidence={"matches": packers},
        ))

    # --- entry point ----------------------------------------------------------
    entry = facts["entry_point_rva"]
    host_section = None
    for s in sections:
        span = max(s["virtual_size"], s["raw_size"])
        if s["virtual_address"] <= entry < s["virtual_address"] + max(span, 1):
            host_section = s
            break
    facts["entry_point_section"] = host_section["name"] if host_section else None

    if entry == 0 and not is_dll and not facts["is_driver"]:
        signals.append(Signal(
            id="pe.entrypoint_anomaly",
            title="Executable declares no entry point",
            severity="medium",
            detail="A non-DLL image with a zero entry point cannot start normally.",
            evidence={"entry_point_rva": 0},
        ))
    elif entry and host_section is None:
        signals.append(Signal(
            id="pe.entrypoint_anomaly",
            title="Entry point lies outside every section",
            severity="high",
            detail="Execution would begin at an address the section table does not map.",
            evidence={"entry_point_rva": entry},
        ))
    elif host_section is not None and not host_section["executable"]:
        signals.append(Signal(
            id="pe.entrypoint_anomaly",
            title="Entry point is in a non-executable section",
            severity="medium",
            detail="The section containing the entry point is not marked executable.",
            evidence={"entry_point_rva": entry, "section": host_section["name"]},
        ))

    # --- .NET, signature, rich header ----------------------------------------
    is_dotnet = False
    try:
        com = opt.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
        is_dotnet = bool(com.VirtualAddress and com.Size)
    except Exception:
        is_dotnet = False
    facts["is_dotnet"] = is_dotnet
    if is_dotnet:
        signals.append(Signal(
            id="pe.dotnet_assembly",
            title="Managed (.NET) assembly",
            severity="info",
            detail=(
                "The image is .NET. Its real logic is IL in the metadata, not in "
                "the import table, so import-based capability findings are "
                "expected to be sparse and are not evidence of packing."
            ),
            evidence={},
        ))

    signature_size = 0
    try:
        sec_dir = opt.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        signature_size = int(sec_dir.Size or 0) if sec_dir.VirtualAddress else 0
    except Exception:
        signature_size = 0
    facts["signature_present"] = signature_size > 0
    facts["signature_size"] = signature_size
    if signature_size > 0:
        signals.append(Signal(
            id="pe.signature_present",
            title="An Authenticode signature is present",
            severity="info",
            detail=(
                "Presence only — this analyzer does not validate the certificate "
                "chain, revocation, or whether the signature covers the file. A "
                "stolen or expired certificate looks identical here."
            ),
            evidence={"security_directory_bytes": signature_size},
        ))

    rich = None
    try:
        rich = pe_obj.parse_rich_header()
    except Exception:
        rich = None
    facts["rich_header_present"] = bool(rich)
    if rich:
        try:
            facts["rich_header_entries"] = len(rich.get("values", [])) // 2
        except Exception:
            facts["rich_header_entries"] = None

    try:
        facts["tls_callbacks_present"] = bool(
            getattr(getattr(pe_obj, "DIRECTORY_ENTRY_TLS", None), "struct", None)
            and pe_obj.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        )
    except Exception:
        facts["tls_callbacks_present"] = False
    if facts["tls_callbacks_present"]:
        signals.append(Signal(
            id="pe.tls_callbacks",
            title="TLS callbacks registered",
            severity="medium",
            detail=(
                "TLS callbacks run before the entry point. They are a standard "
                "place to hide initialisation and anti-debug checks that a "
                "debugger breaking on the entry point will already have missed."
            ),
            evidence={},
        ))

    # --- imports / exports ----------------------------------------------------
    dlls, funcs, total_imports = _import_facts(pe_obj)
    facts["imported_dlls"] = dlls
    facts["imported_functions"] = funcs
    facts["imported_function_count"] = total_imports

    imphash = ""
    try:
        imphash = pe_obj.get_imphash() or ""
    except Exception:
        imphash = ""
    facts["imphash"] = imphash or None

    exports: list[str] = []
    export_dir = getattr(pe_obj, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir is not None:
        try:
            for exp in (export_dir.symbols or [])[:MAX_EXPORTS_RECORDED]:
                name = getattr(exp, "name", None)
                exports.append(_clean(name, 96) if name else f"ordinal_{getattr(exp, 'ordinal', 0)}")
        except Exception:
            pass
    facts["exports"] = exports
    facts["export_count"] = len(exports)

    facts["resources"] = _resource_facts(pe_obj)

    if total_imports == 0:
        signals.append(Signal(
            id="pe.no_imports",
            title="No import table",
            severity="high",
            detail=(
                "A Windows binary with no imports cannot call the OS through the "
                "loader. Either the imports are resolved by hand at runtime "
                "(shellcode-style) or the table was packed away."
            ),
            evidence={"imported_dlls": dlls[:16]},
        ))
    elif total_imports < FEW_IMPORTS_THRESHOLD and not is_dotnet:
        signals.append(Signal(
            id="pe.few_imports",
            title=f"Only {total_imports} imported function(s)",
            severity="medium",
            detail=(
                "A native Windows program needs far more than this to do "
                "anything useful. The usual explanation is a packed import table "
                "rebuilt at runtime."
            ),
            evidence={"count": total_imports, "functions": funcs[:20]},
        ))

    normalized = [n.lower() for n in _imported_names(pe_obj)]
    for group, title, severity, min_hits, patterns in _CAPABILITIES:
        matched = _dedup(
            name for name in normalized
            if any(name.startswith(p) for p in patterns)
        )
        if len(matched) >= min_hits:
            signals.append(Signal(
                id=f"pe.suspicious_imports.{group}",
                title=title,
                severity=severity,
                detail=(
                    f"The import table exposes {len(matched)} API(s) in the "
                    f"'{group}' capability group. Capability, not intent — read "
                    "the matched APIs."
                ),
                evidence={"capability": group, "apis": _take(sorted(matched), 24)},
            ))

    # --- overlay --------------------------------------------------------------
    overlay_offset = None
    try:
        overlay_offset = pe_obj.get_overlay_data_start_offset()
    except Exception:
        overlay_offset = None
    if overlay_offset is not None and sample.size_bytes > overlay_offset:
        overlay_size = sample.size_bytes - overlay_offset
        facts["overlay_offset"] = int(overlay_offset)
        facts["overlay_size"] = int(overlay_size)
        # A few bytes of alignment padding is not a payload.
        if overlay_size >= 1024:
            overlay_slice = data[overlay_offset:overlay_offset + MAX_ENTROPY_BYTES]
            signals.append(Signal(
                id="pe.overlay_present",
                title=f"{overlay_size} bytes appended past the last section",
                severity="medium",
                detail=(
                    "Data after the final section is not loaded into memory by "
                    "the loader, so it is invisible to a naive scan. Installers "
                    "and signed binaries use it legitimately; droppers use it to "
                    "carry a second stage."
                ),
                evidence={
                    "offset": int(overlay_offset),
                    "size": int(overlay_size),
                    "entropy": _entropy(overlay_slice),
                    "signed": facts["signature_present"],
                },
            ))
    else:
        facts["overlay_size"] = 0

    iocs = _extract_iocs(data)
    if imphash:
        iocs.hashes = _dedup([f"imphash:{imphash}", *iocs.hashes])

    return AnalyzerResult(
        analyzer=NAME,
        ran=True,
        signals=signals,
        facts=facts,
        iocs=iocs,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def _ts_signal(signals: list[Signal], kind: str, raw: int, iso: str | None) -> None:
    signals.append(Signal(
        id="pe.timestamp_anomaly",
        title=f"Compile timestamp is {kind}",
        severity="medium",
        detail=(
            "The PE compile timestamp is a plain header field and is trivially "
            "edited, which is why altered ones are worth reporting. Note the "
            "benign case: reproducible/deterministic builds put a content hash "
            "in this field, which reads as a nonsense date."
        ),
        evidence={"timestamp_raw": raw, "interpreted": iso},
    ))
