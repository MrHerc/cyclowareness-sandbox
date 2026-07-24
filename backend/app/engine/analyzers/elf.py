"""ELF static analysis.

The ELF header is parsed here by hand, from the bytes, on purpose. It is about
sixty bytes of well-documented layout, and hand-parsing buys the one property a
sandbox actually needs: a truncated, contradictory or deliberately corrupted ELF
degrades into a *signal* (``elf.parse_failed``) instead of an exception from a
third-party parser that was written to read compilers' output, not attackers'.

Nothing in this module executes, loads, links, maps or resolves anything. It
reads bytes and reports what they say. Strings that look like URLs are extracted
and never fetched.

References: System V gABI, ELF32/ELF64 header, section header and program header
layouts.
"""
from __future__ import annotations

import math
import re
import struct
import time
from collections import Counter
from typing import Any

from ..contracts import AnalyzerResult, IOCs, Sample, Severity, Signal

NAME = "elf"
#: identify.py families this analyzer claims.
HANDLES = ("elf",)

# --- bounds -------------------------------------------------------------------
# Every one of these exists because the sample chose its own numbers. e_shnum is
# a 16-bit field an attacker fills in; a section can claim a 4 GB size at an
# offset past EOF; a .rodata full of 'A' is a string extractor's worst day.

MAX_READ_BYTES = 32 * 1024 * 1024      # matches storage.MAX_SAMPLE_BYTES
MAX_SECTIONS = 256                     # headers parsed
MAX_SEGMENTS = 128
MAX_SECTION_NAMES_REPORTED = 64
MAX_ENTROPY_SECTIONS = 48
ENTROPY_SAMPLE_BYTES = 1024 * 1024     # per section
MIN_ENTROPY_BYTES = 2048               # below this, entropy is noise
HIGH_ENTROPY = 7.2
MAX_STRINGS = 20000
MIN_STRING_LEN = 6
MAX_STRING_LEN = 512
MAX_IOCS_PER_KIND = 50
MAX_EVIDENCE_ITEMS = 12
EVIDENCE_TRUNCATE = 200

# --- ELF constants ------------------------------------------------------------

_ELF_MAGIC = b"\x7fELF"

_CLASSES = {1: "ELF32", 2: "ELF64"}
_ENDIAN = {1: "little", 2: "big"}
_OSABI = {
    0: "SYSV", 1: "HPUX", 2: "NetBSD", 3: "Linux", 6: "Solaris", 7: "AIX",
    8: "IRIX", 9: "FreeBSD", 10: "Tru64", 12: "OpenBSD", 13: "OpenVMS",
    64: "ARM_AEABI", 97: "ARM", 255: "Standalone",
}
_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
_MACHINES = {
    0: "None", 2: "SPARC", 3: "x86", 4: "m68k", 8: "MIPS", 18: "SPARC32PLUS",
    20: "PowerPC", 21: "PowerPC64", 22: "S390", 40: "ARM", 42: "SuperH",
    43: "SPARCv9", 50: "IA-64", 62: "x86-64", 183: "AArch64", 220: "Z80",
    243: "RISC-V", 258: "LoongArch",
}

_PT_LOAD = 1
_PT_DYNAMIC = 2
_PT_INTERP = 3

_SHT_SYMTAB = 2
_SHT_NOBITS = 8
_SHT_DYNSYM = 11

_SHF_EXECINSTR = 0x4

_SHN_XINDEX = 0xFFFF

# --- interpreter allowlist ----------------------------------------------------
# A real dynamic loader lives in a system library directory and is called
# something ld-ish. Anything else is the sample telling you where it wants you
# to look.

_INTERP_DIRS = (
    "/lib/", "/lib64/", "/lib32/", "/libx32/",
    "/usr/lib/", "/usr/lib64/", "/usr/lib32/",
    "/libexec/", "/usr/libexec/",
    "/system/bin/", "/system/lib/", "/system/lib64/",  # Android linker
    "/apex/",
)
_INTERP_NAME = re.compile(r"^(?:ld[-.].*|ld\.so.*|linker(?:64)?|ld)$")
_INTERP_HOT_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/root/", "./")

# --- suspicious string catalogue ----------------------------------------------
# Plain substring matching on already-extracted, length-bounded strings. No
# regex here, so no backtracking to worry about. Matching is case-insensitive
# except where the token is genuinely case-carrying (LD_PRELOAD).

_SUSPICIOUS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "shell_invocation", "medium",
        ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/busybox", "sh -c ", "bash -c ",
         "/bin/zsh", "execve"),
    ),
    (
        "reverse_shell", "high",
        ("/dev/tcp/", "/dev/udp/", "nc -e", "ncat -e", "bash -i >&", "sh -i >&",
         "0<&196", "mkfifo /tmp/", "socat tcp", "telnet ", "/dev/tcp"),
    ),
    (
        "persistence_cron", "medium",
        ("crontab", "/etc/cron", "/var/spool/cron", "@reboot", "/etc/rc.local",
         "systemctl enable", "/etc/init.d/", "/etc/systemd/system/"),
    ),
    (
        "ld_preload", "medium",
        ("ld_preload", "/etc/ld.so.preload", "ld_library_path"),
    ),
    (
        "anti_debug", "medium",
        ("ptrace", "ptrace_traceme", "tracerpid", "/proc/self/status",
         "/proc/self/exe", "isdebuggerpresent"),
    ),
    (
        "miner_pool", "high",
        ("stratum+tcp", "stratum+ssl", "stratum1+tcp", "xmrig", "randomx",
         "cryptonight", "minergate", "nicehash", "pool.minexmr", "supportxmr",
         "nanopool", "--donate-level", "hashrate"),
    ),
    (
        "host_recon", "medium",
        ("/proc/cpuinfo", "iptables -f", "history -c", "chattr -i",
         "/etc/shadow", "authorized_keys", "wget http", "curl http"),
    ),
)

_HIGH_CATEGORIES = {name for name, sev, _ in _SUSPICIOUS if sev == "high"}

# --- IOC extraction -----------------------------------------------------------
# All three run against a single already-bounded string (<= MAX_STRING_LEN), and
# all three are linear: no nested quantifiers, no alternation that can overlap.

_RE_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^\s\"'<>\\]{1,300}")
_RE_DOMAIN = re.compile(
    r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,30})\.){1,6}[a-zA-Z]{2,24}(?![\w-])"
)
_RE_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_RE_STRINGS = re.compile(rb"[\x20-\x7e]{%d,%d}" % (MIN_STRING_LEN, MAX_STRING_LEN))

#: Domains are accepted by TLD allowlist rather than rejected by extension
#: blocklist. A blocklist loses twice here: ELF binaries are full of filenames
#: that look like domains (``libc.so``, ``crtstuff.c``, ``gate.php``), and a
#: high-entropy packed section produces plausible-looking garbage
#: (``yl9z.zj``) by chance. An analyst drowning in invented indicators stops
#: reading them, so the bias is deliberately toward missing an exotic TLD.
_TLDS = frozenset(
    # ISO 3166-1 alpha-2 ccTLDs
    """ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh
    bi bj bm bn bo br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu
    cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga
    gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie
    il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb
    lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt
    mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk
    pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm
    sn sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw
    tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw
    """.split()
    # gTLDs that actually turn up in samples, plus RFC 2606 reserved names.
    + """com net org edu gov mil int info biz name pro app dev io ai co cloud
    online site shop store xyz top club live life world web space fun icu cyou
    tech link click download stream press host website digital network systems
    services solutions company center email pw cc tv me ru su onion i2p bit
    example test invalid localhost local lan internal onion
    """.split()
)
# NB: ".so" (Somalia) is intentionally absent from _TLDS — in an ELF binary
# "libc.so" is a shared object every time, and Somali C2 is the rarer event.


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _clip(text: str, limit: int = EVIDENCE_TRUNCATE) -> str:
    text = text.replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "..."


def _cstr(blob: bytes, offset: int, limit: int = 4096) -> str:
    """NUL-terminated string out of a blob, bounded and never trusted."""
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset, offset + limit)
    if end == -1:
        end = min(offset + limit, len(blob))
    return blob[offset:end].decode("utf-8", "replace")


class _Truncated(Exception):
    """A header ran off the end of the file."""


def _unpack(fmt: str, data: bytes, offset: int) -> tuple[Any, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise _Truncated(f"structure at offset {offset} extends past end of file")
    return struct.unpack_from(fmt, data, offset)


# --- header parsing -----------------------------------------------------------


def _parse_header(data: bytes) -> dict[str, Any]:
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in _CLASSES:
        raise _Truncated(f"invalid EI_CLASS {ei_class}")
    if ei_data not in _ENDIAN:
        raise _Truncated(f"invalid EI_DATA {ei_data}")

    end = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    fmt = (end + "HHIQQQIHHHHHH") if is64 else (end + "HHIIIIIHHHHHH")
    (
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
        e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
    ) = _unpack(fmt, data, 16)

    return {
        "is64": is64,
        "endian": end,
        "ei_class": ei_class,
        "ei_data": ei_data,
        "ei_osabi": data[7],
        "ei_abiversion": data[8],
        "e_type": e_type,
        "e_machine": e_machine,
        "e_version": e_version,
        "e_entry": e_entry,
        "e_phoff": e_phoff,
        "e_shoff": e_shoff,
        "e_flags": e_flags,
        "e_ehsize": e_ehsize,
        "e_phentsize": e_phentsize,
        "e_phnum": e_phnum,
        "e_shentsize": e_shentsize,
        "e_shnum": e_shnum,
        "e_shstrndx": e_shstrndx,
    }


def _parse_segments(data: bytes, h: dict[str, Any]) -> list[dict[str, Any]]:
    if not h["e_phoff"] or not h["e_phnum"]:
        return []
    end, is64 = h["endian"], h["is64"]
    entsize = h["e_phentsize"] or (56 if is64 else 32)
    count = min(h["e_phnum"], MAX_SEGMENTS)

    out: list[dict[str, Any]] = []
    for i in range(count):
        off = h["e_phoff"] + i * entsize
        try:
            if is64:
                p_type, p_flags, p_offset, _va, _pa, p_filesz, p_memsz, _al = _unpack(
                    end + "IIQQQQQQ", data, off
                )
            else:
                p_type, p_offset, _va, _pa, p_filesz, p_memsz, p_flags, _al = _unpack(
                    end + "IIIIIIII", data, off
                )
        except _Truncated:
            break
        out.append(
            {
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "filesz": p_filesz,
                "memsz": p_memsz,
            }
        )
    return out


def _parse_sections(data: bytes, h: dict[str, Any]) -> list[dict[str, Any]]:
    if not h["e_shoff"]:
        return []
    end, is64 = h["endian"], h["is64"]
    entsize = h["e_shentsize"] or (64 if is64 else 40)
    fmt = (end + "IIQQQQIIQQ") if is64 else (end + "IIIIIIIIII")

    def read(index: int) -> dict[str, Any]:
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         sh_link, _info, _align, _entsize) = _unpack(
            fmt, data, h["e_shoff"] + index * entsize
        )
        return {
            "name_off": sh_name, "type": sh_type, "flags": sh_flags,
            "addr": sh_addr, "offset": sh_offset, "size": sh_size, "link": sh_link,
        }

    # e_shnum == 0 with a non-zero e_shoff means the real count lives in
    # shdr[0].sh_size (gABI extended numbering). Same trick for e_shstrndx.
    shnum = h["e_shnum"]
    shstrndx = h["e_shstrndx"]
    zero = read(0)
    if shnum == 0:
        shnum = zero["size"]
    if shstrndx == _SHN_XINDEX:
        shstrndx = zero["link"]
    if shnum <= 0:
        return []

    sections: list[dict[str, Any]] = []
    for i in range(min(shnum, MAX_SECTIONS)):
        try:
            sections.append(read(i))
        except _Truncated:
            break

    # Section-name string table. Unreadable is survivable: sh_type carries the
    # facts that matter (symtab present, executable, NOBITS).
    strtab = b""
    if 0 < shstrndx < len(sections):
        st = sections[shstrndx]
        start, size = st["offset"], min(st["size"], 4 * 1024 * 1024)
        if st["type"] != _SHT_NOBITS and 0 <= start < len(data):
            strtab = data[start:start + size]
    for s in sections:
        s["name"] = _cstr(strtab, s["name_off"]) if strtab else ""
    return sections


def _section_bytes(data: bytes, s: dict[str, Any]) -> bytes:
    if s["type"] == _SHT_NOBITS:
        return b""
    start = s["offset"]
    if start < 0 or start >= len(data):
        return b""
    size = min(s["size"], ENTROPY_SAMPLE_BYTES, len(data) - start)
    if size <= 0:
        return b""
    return data[start:start + size]


# --- strings and IOCs ---------------------------------------------------------


def _extract_strings(data: bytes) -> list[str]:
    out: list[str] = []
    for m in _RE_STRINGS.finditer(data):
        out.append(m.group().decode("ascii", "replace"))
        if len(out) >= MAX_STRINGS:
            break
    return out


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


def _harvest_iocs(strings: list[str]) -> IOCs:
    urls: dict[str, None] = {}
    domains: dict[str, None] = {}
    ips: dict[str, None] = {}

    for text in strings:
        if len(urls) >= MAX_IOCS_PER_KIND and len(domains) >= MAX_IOCS_PER_KIND \
                and len(ips) >= MAX_IOCS_PER_KIND:
            break
        for m in _RE_URL.finditer(text):
            if len(urls) < MAX_IOCS_PER_KIND:
                urls.setdefault(_clip(m.group(), 300), None)
        for m in _RE_IP.finditer(text):
            value = m.group()
            if _valid_ip(value) and len(ips) < MAX_IOCS_PER_KIND:
                ips.setdefault(value, None)
        for m in _RE_DOMAIN.finditer(text):
            value = m.group().lower().rstrip(".")
            labels = value.split(".")
            if labels[-1] not in _TLDS or len(value) > 253:
                continue
            # Every label two characters or shorter is chance, not a hostname:
            # random bytes produce "af.qa" far more often than anyone registers it.
            if all(len(label) <= 2 for label in labels):
                continue
            if len(domains) < MAX_IOCS_PER_KIND:
                domains.setdefault(value, None)

    return IOCs(urls=list(urls), domains=list(domains), ips=list(ips))


def _scan_suspicious(strings: list[str]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for text in strings:
        low = text.lower()
        for category, _sev, needles in _SUSPICIOUS:
            bucket = hits.get(category)
            if bucket is not None and len(bucket) >= MAX_EVIDENCE_ITEMS:
                continue
            for needle in needles:
                if needle in low:
                    hits.setdefault(category, []).append(_clip(text))
                    break
    return hits


def _interpreter_is_unusual(interp: str) -> tuple[bool, str]:
    low = interp.lower()
    for hot in _INTERP_HOT_DIRS:
        if hot in low:
            return True, "loader path is in a user-writable directory"
    if not interp.startswith("/"):
        return True, "loader path is not absolute"
    directory, _, base = interp.rpartition("/")
    directory += "/"
    if not any(directory.startswith(d) for d in _INTERP_DIRS):
        return True, "loader is outside the system library directories"
    if not _INTERP_NAME.match(base):
        return True, "loader filename does not look like a dynamic linker"
    return False, ""


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

    if not data.startswith(_ELF_MAGIC):
        return finish(AnalyzerResult.not_applicable(NAME, sample.mime or "non-ELF"))

    signals: list[Signal] = []
    facts: dict[str, Any] = {
        "truncated_read": sample.size_bytes > MAX_READ_BYTES,
        "bytes_examined": len(data),
    }

    try:
        header = _parse_header(data)
    except (_Truncated, IndexError, struct.error, ValueError) as exc:
        # An ELF magic with an unparseable header is not an error condition, it
        # is a finding: real toolchains do not emit these.
        facts["header_parsed"] = False
        signals.append(
            Signal(
                id="elf.parse_failed",
                title="ELF header is malformed or truncated",
                severity="medium",
                detail=(
                    "The file begins with the ELF magic but its header could not "
                    f"be parsed: {_clip(str(exc))}. Corrupt headers are a common "
                    "anti-analysis technique — the Linux loader is more forgiving "
                    "than most parsers."
                ),
                evidence={"error": _clip(str(exc)), "size_bytes": sample.size_bytes},
            )
        )
        strings = _extract_strings(data)
        return finish(
            AnalyzerResult(
                analyzer=NAME, ran=True, signals=signals, facts=facts,
                iocs=_harvest_iocs(strings),
            )
        )

    facts["header_parsed"] = True
    facts["elf_class"] = _CLASSES[header["ei_class"]]
    facts["endianness"] = _ENDIAN[header["ei_data"]]
    facts["os_abi"] = _OSABI.get(header["ei_osabi"], f"unknown({header['ei_osabi']})")
    facts["abi_version"] = header["ei_abiversion"]
    facts["type"] = _TYPES.get(header["e_type"], f"unknown({header['e_type']})")
    facts["machine"] = _MACHINES.get(
        header["e_machine"], f"unknown({header['e_machine']})"
    )
    facts["entry_point"] = f"0x{header['e_entry']:x}"
    facts["flags"] = f"0x{header['e_flags']:x}"

    # --- program headers ------------------------------------------------------
    parse_notes: list[str] = []
    try:
        segments = _parse_segments(data, header)
    except (_Truncated, struct.error, ValueError) as exc:
        segments = []
        parse_notes.append(f"program headers: {_clip(str(exc), 120)}")

    try:
        sections = _parse_sections(data, header)
    except (_Truncated, struct.error, ValueError) as exc:
        sections = []
        parse_notes.append(f"section headers: {_clip(str(exc), 120)}")

    facts["program_header_count"] = len(segments)
    facts["declared_program_headers"] = header["e_phnum"]
    facts["section_count"] = len(sections)
    facts["declared_sections"] = header["e_shnum"]
    facts["section_names"] = [
        s["name"] for s in sections[:MAX_SECTION_NAMES_REPORTED] if s["name"]
    ]

    if parse_notes:
        signals.append(
            Signal(
                id="elf.parse_failed",
                title="ELF header table could not be fully parsed",
                severity="medium",
                detail=(
                    "The ELF header parsed, but a header table did not: "
                    + "; ".join(parse_notes)
                    + ". Offsets or counts point outside the file."
                ),
                evidence={"problems": parse_notes[:MAX_EVIDENCE_ITEMS]},
            )
        )

    # --- interpreter ----------------------------------------------------------
    interp = ""
    for seg in segments:
        if seg["type"] == _PT_INTERP:
            start, size = seg["offset"], min(seg["filesz"], 4096)
            if 0 <= start < len(data) and size > 0:
                interp = _cstr(data[start:start + size], 0)
            break
    facts["interpreter"] = interp or None

    if interp:
        unusual, why = _interpreter_is_unusual(interp)
        if unusual:
            signals.append(
                Signal(
                    id="elf.unusual_interpreter",
                    title="Non-standard ELF interpreter",
                    severity="high" if "user-writable" in why else "medium",
                    detail=(
                        f"PT_INTERP names {_clip(interp)!r} as the dynamic loader — "
                        f"{why}. A binary that supplies its own loader controls what "
                        "runs before main()."
                    ),
                    evidence={"interpreter": _clip(interp), "reason": why},
                )
            )

    # --- static linking -------------------------------------------------------
    has_interp = any(s["type"] == _PT_INTERP for s in segments)
    has_dynamic = any(s["type"] == _PT_DYNAMIC for s in segments) or any(
        s["type"] == _SHT_DYNSYM for s in sections
    )
    statically_linked = (
        header["e_type"] in (2, 3)  # EXEC or DYN
        and bool(segments)
        and not has_interp
        and not has_dynamic
    )
    facts["statically_linked"] = statically_linked

    if statically_linked:
        signals.append(
            Signal(
                id="elf.statically_linked",
                title="Statically linked binary",
                severity="low",
                detail=(
                    "No PT_INTERP and no dynamic linking information: every library "
                    "the binary uses is baked in. Distro packages are almost never "
                    "built this way; dropped Linux implants usually are, because a "
                    "static binary runs on a host whose libc it has never met."
                ),
                evidence={
                    "type": facts["type"],
                    "machine": facts["machine"],
                    "program_headers": len(segments),
                },
            )
        )

    # --- sections stripped / removed -----------------------------------------
    if not sections:
        facts["stripped"] = True
        signals.append(
            Signal(
                id="elf.no_sections",
                title="Section headers removed",
                severity="medium",
                detail=(
                    "The section header table is absent or empty (e_shoff="
                    f"{header['e_shoff']}, e_shnum={header['e_shnum']}). Linux will "
                    "still load the file from its program headers, but every "
                    "section-based tool — objdump, readelf, most YARA rules — is "
                    "blinded. Compilers do not produce this; strippers and packers do."
                ),
                evidence={
                    "e_shoff": header["e_shoff"],
                    "e_shnum": header["e_shnum"],
                    "program_headers": len(segments),
                },
            )
        )
    else:
        stripped = not any(s["type"] == _SHT_SYMTAB for s in sections)
        facts["stripped"] = stripped
        if stripped:
            signals.append(
                Signal(
                    id="elf.stripped",
                    title="Symbol table stripped",
                    severity="low",
                    detail=(
                        "No SHT_SYMTAB section: local and function symbol names have "
                        "been removed. Common in release builds, and universal in "
                        "malware — it costs the author nothing and costs the analyst "
                        "the function names."
                    ),
                    evidence={"section_count": len(sections)},
                )
            )

    # --- packing --------------------------------------------------------------
    packing_reasons: list[str] = []
    packing_evidence: dict[str, Any] = {}

    upx_at = data.find(b"UPX!")
    if upx_at != -1:
        packing_reasons.append("UPX! marker present")
        packing_evidence["upx_marker_offset"] = upx_at
    upx_sections = [
        s["name"] for s in sections if s["name"].upper().startswith("UPX")
    ]
    if upx_sections:
        packing_reasons.append("UPX section names")
        packing_evidence["upx_sections"] = upx_sections[:MAX_EVIDENCE_ITEMS]

    entropies: list[tuple[str, float, int]] = []
    if sections:
        candidates = [
            s for s in sections
            if s["type"] != _SHT_NOBITS and s["size"] >= MIN_ENTROPY_BYTES
        ][:MAX_ENTROPY_SECTIONS]
        for s in candidates:
            blob = _section_bytes(data, s)
            if len(blob) >= MIN_ENTROPY_BYTES:
                entropies.append(
                    (s["name"] or f"<sh_offset 0x{s['offset']:x}>", _entropy(blob), len(blob))
                )
    else:
        # No sections: fall back to PT_LOAD segments, which is what the loader
        # itself would read.
        for seg in segments[:MAX_ENTROPY_SECTIONS]:
            if seg["type"] != _PT_LOAD or seg["filesz"] < MIN_ENTROPY_BYTES:
                continue
            start = seg["offset"]
            if start >= len(data):
                continue
            size = min(seg["filesz"], ENTROPY_SAMPLE_BYTES, len(data) - start)
            if size >= MIN_ENTROPY_BYTES:
                entropies.append(
                    (f"<PT_LOAD 0x{start:x}>", _entropy(data[start:start + size]), size)
                )

    facts["entropy"] = [
        {"name": _clip(name, 64), "entropy": round(value, 3), "bytes": size}
        for name, value, size in sorted(entropies, key=lambda e: -e[1])[:16]
    ]
    high = [e for e in entropies if e[1] >= HIGH_ENTROPY]
    if high:
        packing_reasons.append("high-entropy region")
        packing_evidence["high_entropy"] = [
            {"name": _clip(n, 64), "entropy": round(v, 3), "bytes": b}
            for n, v, b in sorted(high, key=lambda e: -e[1])[:MAX_EVIDENCE_ITEMS]
        ]

    facts["packed"] = bool(packing_reasons)
    if packing_reasons:
        packing_evidence["reasons"] = packing_reasons
        signals.append(
            Signal(
                id="elf.packed",
                title="Binary appears packed or compressed",
                severity="high",
                detail=(
                    "Packing detected via " + ", ".join(packing_reasons) + ". Packed "
                    "code is unreadable until it unpacks itself at runtime, which is "
                    "the point: the on-disk bytes are not the bytes that execute. "
                    f"(entropy threshold {HIGH_ENTROPY} of a possible 8.0)"
                ),
                evidence=packing_evidence,
            )
        )

    # --- strings --------------------------------------------------------------
    strings = _extract_strings(data)
    facts["strings_examined"] = len(strings)
    facts["strings_truncated"] = len(strings) >= MAX_STRINGS

    hits = _scan_suspicious(strings)
    facts["suspicious_categories"] = sorted(hits)
    if hits:
        severity: Severity = "high" if _HIGH_CATEGORIES & set(hits) else "medium"
        signals.append(
            Signal(
                id="elf.suspicious_strings",
                title="Suspicious strings in binary",
                severity=severity,
                detail=(
                    "Plain-text strings matching "
                    + ", ".join(sorted(hits))
                    + ". Strings are intent, not proof — a string is present because "
                    "somebody typed it, but only execution would show it being used."
                ),
                evidence={
                    category: matches[:MAX_EVIDENCE_ITEMS]
                    for category, matches in sorted(hits.items())
                },
            )
        )

    iocs = _harvest_iocs(strings)

    return finish(
        AnalyzerResult(
            analyzer=NAME, ran=True, signals=signals, facts=facts, iocs=iocs
        )
    )
