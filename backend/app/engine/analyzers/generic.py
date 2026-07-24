"""The analyzer that runs on every sample, whatever it turns out to be.

Two jobs, and they are deliberately the boring ones:

1. **Shape.** Entropy, size, strings, and whether the bytes agree with the name
   the submitter put on them. None of this needs to know the file format, which
   is exactly why it is the one analyzer that can never be skipped.
2. **Indicators.** This module owns the *canonical* IOC extractor. Every other
   analyzer imports :func:`extract_iocs` rather than growing its own regexes,
   because an engine with four URL patterns has four different opinions about
   what a URL is, and the report is where those disagreements surface.

Nothing here executes, decodes-and-runs, resolves, or fetches anything. URLs,
domains and paths are lifted out as *text* and left as text.
"""
from __future__ import annotations

import ipaddress
import math
import re
import time
from urllib.parse import urlsplit

from ..contracts import AnalyzerResult, IOCs, Sample, Signal

NAME = "generic"
#: This analyzer claims every family; the registry dispatches "*" to everything.
FAMILY = "*"

# --- bounds -------------------------------------------------------------------
# The sample is hostile and so is its size. Every loop below terminates on a
# constant, never on something the sample gets to choose.

#: Most bytes we will ever pull into memory for one sample.
MAX_READ = 16 * 1024 * 1024
#: Most characters of extracted text we will run indicator regexes over.
MAX_IOC_TEXT = 2_000_000
#: Most indicators of any one kind we will report. Beyond this the list has
#: stopped being evidence and started being a payload of its own.
MAX_PER_KIND = 500
#: Any sample-derived string that reaches a Signal or a fact is cut to this.
MAX_EVIDENCE_CHARS = 200
#: Header candidates we will validate when hunting for an embedded executable.
MAX_EMBED_CANDIDATES = 4096

#: Whole-file entropy above this is "packed or encrypted" territory.
ENTROPY_THRESHOLD = 7.5
#: Below this a file is too small for its entropy to mean anything.
ENTROPY_MIN_BYTES = 1024
#: A file smaller than this has essentially no content to analyse.
TINY_FILE_BYTES = 64
#: More distinct URLs than this in one sample is worth saying out loud.
MANY_URLS_THRESHOLD = 12


# --- entropy and strings ------------------------------------------------------


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, 0.0 for empty input.

    8.0 is the ceiling. Compressed and encrypted data both sit near it, which is
    why a high value is a question ("why is this .doc incompressible?") and not
    an answer.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


_ASCII_RUN_CACHE: dict[int, re.Pattern[bytes]] = {}
_UTF16_RUN_CACHE: dict[int, re.Pattern[bytes]] = {}


def _ascii_run(min_len: int) -> re.Pattern[bytes]:
    pattern = _ASCII_RUN_CACHE.get(min_len)
    if pattern is None:
        pattern = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
        _ASCII_RUN_CACHE[min_len] = pattern
    return pattern


def _utf16_run(min_len: int) -> re.Pattern[bytes]:
    pattern = _UTF16_RUN_CACHE.get(min_len)
    if pattern is None:
        pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
        _UTF16_RUN_CACHE[min_len] = pattern
    return pattern


#: Longest single string we will keep. Past this it is a blob, not a string.
_MAX_STRING_CHARS = 1024


def printable_strings(data: bytes, min_len: int = 6, limit: int = 5000) -> list[str]:
    """ASCII and UTF-16LE printable runs, in that order, capped at ``limit``.

    UTF-16LE is not an optional extra: Windows API strings, PowerShell
    ``-EncodedCommand`` payloads and .NET literals are all wide, and an
    extractor that only reads ASCII sees a suspiciously quiet binary.
    """
    if not data or min_len < 1 or limit < 1:
        return []
    min_len = min(min_len, 256)

    def collect(pattern: re.Pattern[bytes], encoding: str, cap: int) -> list[str]:
        out: list[str] = []
        for match in pattern.finditer(data):
            if len(out) >= cap:
                break
            try:
                text = match.group().decode(encoding, "replace")
            except Exception:
                continue
            out.append(text[:_MAX_STRING_CHARS])
        return out

    wide = collect(_utf16_run(min_len), "utf-16-le", limit)
    # Reserve a slice of the budget for wide strings so a chatty ASCII blob
    # cannot starve them out entirely.
    reserved = min(len(wide), max(1, limit // 4))
    narrow = collect(_ascii_run(min_len), "ascii", limit - reserved)
    return (narrow + wide[:reserved])[:limit]


# --- indicator extraction -----------------------------------------------------

_URL_RE = re.compile(
    r"""(?:https?|ftp)://[^\s<>"'`\\\]\}\|\x00-\x1f]{1,2048}""",
    re.IGNORECASE,
)

# Loose token, validated in Python. A single bounded character class cannot
# backtrack, which matters more here than regex elegance.
_DOMAIN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9._/\\@:-])[A-Za-z0-9][A-Za-z0-9.-]{2,252}(?![A-Za-z0-9-])"
)

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

# Candidate only: anything hex-and-colon that has enough colons to be worth
# handing to ipaddress. Validation is what decides, not the pattern.
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")

_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,250}\.[A-Za-z]{2,24}"
    r"(?![A-Za-z0-9-])"
)

_WIN_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]{1,255}\\){0,16}"
    r"[^\\/:*?\"<>|\r\n\t ]{0,255}"
)

_ENV_PATH_RE = re.compile(
    r"%[A-Za-z_][A-Za-z0-9_()]{0,32}%\\(?:[^\\/:*?\"<>|\r\n]{1,255}\\){0,16}"
    r"[^\\/:*?\"<>|\r\n\t ]{0,255}"
)

_UNC_PATH_RE = re.compile(
    r"\\\\[A-Za-z0-9._-]{1,63}\\(?:[^\\/:*?\"<>|\r\n]{1,255}\\){0,16}"
    r"[^\\/:*?\"<>|\r\n\t ]{0,255}"
)

_REGISTRY_RE = re.compile(
    r"(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)"
    r"|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\r\n\"'<>|\x00]{1,512}"
)

#: Trailing characters that are punctuation in prose far more often than they
#: are part of the indicator.
_TRAILING_JUNK = ".,;:!?)]}'\"<>*"

#: Generic top-level domains we accept for a *bare* domain. Every two-letter
#: TLD is accepted separately as a ccTLD.
_GTLDS = {
    "com", "net", "org", "info", "biz", "pro", "name", "mobi", "asia", "int",
    "edu", "gov", "mil", "arpa", "travel", "jobs", "museum", "aero", "coop",
    "xyz", "top", "online", "site", "shop", "store", "club", "live", "life",
    "world", "today", "space", "website", "tech", "cloud", "app", "dev",
    "page", "link", "click", "download", "zip", "mov", "work", "agency",
    "digital", "email", "support", "services", "solutions", "systems",
    "network", "host", "icu", "cyou", "monster", "quest", "buzz", "fun",
    "bar", "rest", "wiki", "blog", "news", "media", "group", "ltd", "vip",
    "center", "company", "tools", "zone", "plus", "one", "run", "sbs", "cfd",
    "bond", "autos", "best", "cam", "cheap", "gdn", "help", "homes", "lol",
    "ninja", "party", "pics", "racing", "review", "rocks", "science",
    "stream", "study", "trade", "uno", "webcam", "win", "wtf", "xin",
}

#: TLDs that are also everyday file extensions. A bare two-label token ending
#: in one of these ("README.md", "payload.zip", "libc.so") is a filename far
#: more often than a domain, so we demand a subdomain before believing it.
#: A host parsed out of a real URL bypasses this entirely — that is the case
#: that actually matters for ".zip" phishing.
_EXTENSION_LIKE_TLDS = {
    "zip", "mov", "md", "sh", "pl", "py", "so", "ps", "cs", "vb", "rb", "ml",
    "gs", "ai", "cc", "in", "is", "it", "as", "do", "cd", "bz", "la", "im",
    "dm", "st", "ws", "me", "tm",
}

#: Boilerplate that appears in essentially every Office document, signed PE and
#: PDF. Suppressed from IOCs — but recorded as a fact, never silently dropped.
_BOILERPLATE_DOMAINS = {
    "w3.org", "schema.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
    "openxmlformats.org", "purl.org", "purl.oclc.org", "dublincore.org",
    "xmlsoap.org", "oasis-open.org", "iana.org", "ietf.org", "adobe.com",
    "ns.adobe.com", "openoffice.org", "libreoffice.org", "sun.com",
    "microsoft.com", "windows.com", "msn.com", "live.com", "office.com",
    "apache.org", "mozilla.org", "gnu.org", "python.org", "unicode.org",
    "verisign.com", "symantec.com", "digicert.com", "globalsign.com",
    "globalsign.net", "thawte.com", "entrust.net", "sectigo.com",
    "comodoca.com", "usertrust.com", "godaddy.com", "letsencrypt.org",
    "amazontrust.com", "certum.pl", "quovadisglobal.com", "swisssign.com",
}

#: Registrars of choice for throwaway phishing infrastructure. Low severity on
#: its own — this is a nudge, not a verdict.
_SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "tk", "cf", "gq", "ru"}

#: Brands worth impersonating, for the lookalike check.
_LOOKALIKE_BRANDS = {
    "paypal", "microsoft", "office365", "outlook", "apple", "icloud",
    "amazon", "google", "netflix", "facebook", "instagram", "whatsapp",
    "linkedin", "dropbox", "docusign", "dhl", "fedex", "binance", "coinbase",
    "metamask", "steamcommunity", "telegram", "sharepoint", "onedrive",
}

#: Digit/letter swaps that survive a glance at a browser address bar.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def _looks_like_tld(tld: str) -> bool:
    return tld in _GTLDS or (len(tld) == 2 and tld.isalpha())


def _valid_domain(candidate: str, *, allow_extension_like: bool) -> str | None:
    """Return the normalised domain, or None if this is not one."""
    host = candidate.strip(".").lower()
    if not host or len(host) > 253 or ".." in host:
        return None
    labels = host.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not 1 <= len(label) <= 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
    tld = labels[-1]
    if not tld.isalpha() or not _looks_like_tld(tld):
        return None
    if tld in _EXTENSION_LIKE_TLDS and not allow_extension_like and len(labels) < 3:
        return None
    # A domain made only of digits and dots is a mangled IP, not a name.
    if all(label.isdigit() for label in labels[:-1]):
        return None
    return host


#: Precomputed once so the hot per-token check is a set lookup plus a single
#: C-level ``str.endswith`` over a tuple, not 44 string concatenations per call.
_BOILERPLATE_SUFFIXES = tuple("." + b for b in _BOILERPLATE_DOMAINS)


def _is_boilerplate(host: str) -> bool:
    return host in _BOILERPLATE_DOMAINS or host.endswith(_BOILERPLATE_SUFFIXES)


def _classify_ip(text: str) -> tuple[str, bool] | None:
    """(normalised address, is_public). None when it is not an IP at all."""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    public = not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )
    return str(addr), public


class _Bag:
    """Order-preserving, de-duplicating, hard-capped accumulator."""

    def __init__(self, cap: int = MAX_PER_KIND) -> None:
        self._seen: dict[str, None] = {}
        self._cap = cap

    def add(self, value: str) -> None:
        if len(self._seen) < self._cap:
            self._seen.setdefault(value, None)

    def list(self) -> list[str]:
        return list(self._seen)


def _clean_path(raw: str) -> str | None:
    path = raw.rstrip(" \t").rstrip(_TRAILING_JUNK)
    if len(path) < 4 or path.endswith(":"):
        return None
    # "C:\" on its own is not an indicator of anything.
    if re.fullmatch(r"[A-Za-z]:\\?", path):
        return None
    return path[:512]


def extract_iocs(text: str, *, max_len: int = MAX_IOC_TEXT) -> IOCs:
    """The one indicator extractor in the engine. Extraction only.

    Nothing found here is resolved, requested, or expanded. Private and
    reserved IP literals, and the XML/CA boilerplate that lives in every Office
    document and signed binary, are deliberately *not* returned — see
    :func:`split_noise` for the same pass with the discarded material kept.
    """
    return _extract(text, max_len=max_len)[0]


def split_noise(text: str, *, max_len: int = MAX_IOC_TEXT) -> tuple[IOCs, dict[str, list[str]]]:
    """:func:`extract_iocs`, plus what it filtered out.

    The generic analyzer records the filtered material as a fact. Suppressing
    noise from the indicator list is a reporting decision; deleting it would be
    a claim we did not look.
    """
    return _extract(text, max_len=max_len)


def _extract(text: str, *, max_len: int) -> tuple[IOCs, dict[str, list[str]]]:
    iocs = IOCs()
    noise: dict[str, list[str]] = {}
    if not text:
        return iocs, noise
    if max_len > 0:
        text = text[:max_len]

    urls = _Bag()
    domains = _Bag()
    ips = _Bag()
    emails = _Bag()
    paths = _Bag()
    registry = _Bag()
    private_ips = _Bag(cap=200)
    filtered_domains = _Bag(cap=200)
    filtered_urls = _Bag(cap=200)

    url_hosts: set[str] = set()

    # --- URLs, and the hosts inside them
    for match in _URL_RE.finditer(text):
        url = match.group().rstrip(_TRAILING_JUNK)
        if len(url) < 8:
            continue
        host = ""
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
        except ValueError:
            host = ""
        if host and _is_boilerplate(host):
            filtered_urls.add(url[:512])
            filtered_domains.add(host)
            continue
        urls.add(url[:512])
        if not host:
            continue
        ip = _classify_ip(host.strip("[]"))
        if ip is not None:
            address, public = ip
            (ips if public else private_ips).add(address)
            url_hosts.add(host)
            continue
        # A URL host is a host by construction, so the filename ambiguity that
        # makes bare ".zip" tokens unreliable does not apply here.
        normalised = _valid_domain(host, allow_extension_like=True)
        if normalised:
            domains.add(normalised)
            url_hosts.add(normalised)

    # --- emails (before bare domains, so mail hosts are not double-counted)
    email_hosts: set[str] = set()
    for match in _EMAIL_RE.finditer(text):
        address = match.group().rstrip(_TRAILING_JUNK).lower()
        local, _, host = address.rpartition("@")
        normalised = _valid_domain(host, allow_extension_like=True)
        if not local or not normalised:
            continue
        if _is_boilerplate(normalised):
            filtered_domains.add(normalised)
            continue
        emails.add(address[:320])
        email_hosts.add(normalised)

    # --- IPv4 / IPv6 literals
    for match in _IPV4_RE.finditer(text):
        ip = _classify_ip(match.group())
        if ip is None:
            continue
        address, public = ip
        (ips if public else private_ips).add(address)

    for match in _IPV6_RE.finditer(text):
        candidate = match.group()
        if candidate.count(":") < 2 or len(candidate) < 3:
            continue
        ip = _classify_ip(candidate)
        if ip is None:
            continue
        address, public = ip
        (ips if public else private_ips).add(address)

    # --- paths and registry keys
    for pattern in (_WIN_PATH_RE, _ENV_PATH_RE, _UNC_PATH_RE):
        for match in pattern.finditer(text):
            path = _clean_path(match.group())
            if path:
                paths.add(path)

    for match in _REGISTRY_RE.finditer(text):
        key = match.group().rstrip().rstrip(_TRAILING_JUNK)
        if len(key) > 6:
            registry.add(key[:512])

    # --- bare domains, last, and with the strictest rules
    path_tails = {p.rsplit("\\", 1)[-1].lower() for p in paths.list()}
    for match in _DOMAIN_TOKEN_RE.finditer(text):
        normalised = _valid_domain(match.group(), allow_extension_like=False)
        if not normalised:
            continue
        if normalised in url_hosts or normalised in email_hosts:
            continue
        if normalised in path_tails:
            continue
        if _is_boilerplate(normalised):
            filtered_domains.add(normalised)
            continue
        domains.add(normalised)

    iocs.urls = urls.list()
    iocs.domains = domains.list()
    iocs.ips = ips.list()
    iocs.emails = emails.list()
    iocs.file_paths = paths.list()
    iocs.registry_keys = registry.list()

    noise["private_ips"] = private_ips.list()
    noise["boilerplate_domains"] = filtered_domains.list()
    noise["boilerplate_urls"] = filtered_urls.list()
    return iocs, noise


# --- lookalike / suspicious-name checks ---------------------------------------


def _registrable(host: str) -> str:
    labels = host.split(".")
    return labels[-2] if len(labels) >= 2 else host


def _edit_distance_le_1(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    if a == b:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = 0
    edits = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            edits += 1
            if edits > 1:
                return False
            if len(a) == len(b):
                i += 1
            j += 1
        else:
            i += 1
            j += 1
    return edits + (len(b) - j) <= 1


def _lookalike_reason(host: str) -> str | None:
    if any(label.startswith("xn--") for label in host.split(".")):
        return "punycode label (internationalised name shown differently in a browser)"
    sld = _registrable(host)
    if len(sld) < 4 or sld in _LOOKALIKE_BRANDS:
        return None
    folded = sld.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    folded = folded.replace("-", "")
    for brand in _LOOKALIKE_BRANDS:
        if folded == brand:
            return f"character-substitution lookalike of {brand}"
        if _edit_distance_le_1(folded, brand):
            return f"one edit away from {brand}"
    return None


# --- embedded executable ------------------------------------------------------

#: Families whose contents legitimately look like anything at all.
_EMBED_EXEMPT_FAMILIES = {"pe", "elf", "archive"}
_EMBED_EXEMPT_MIMES = {
    "application/zip",
    "application/java-archive",
    "application/vnd.android.package-archive",
    "application/x-dosexec",
    "application/x-elf",
}


def _pe_at(data: bytes, offset: int) -> bool:
    if offset + 0x40 > len(data):
        return False
    e_lfanew = int.from_bytes(data[offset + 0x3C: offset + 0x40], "little")
    start = offset + e_lfanew
    if not (0x40 <= e_lfanew <= 0x10000) or start + 4 > len(data):
        return False
    return data[start: start + 4] == b"PE\x00\x00"


def _elf_at(data: bytes, offset: int) -> bool:
    if offset + 7 > len(data):
        return False
    return data[offset + 4] in (1, 2) and data[offset + 5] in (1, 2) and data[offset + 6] == 1


def _find_embedded_executables(data: bytes) -> list[dict[str, object]]:
    """MZ/PE and ELF headers at a non-zero offset, validated, not just matched.

    A bare ``MZ`` occurs by chance roughly every 64 KB of random data, so the
    two bytes alone are worthless; only a header whose ``e_lfanew`` lands on a
    real ``PE\\0\\0`` counts. This deliberately misses *compressed* embedded
    binaries — those are the archive and packer analyzers' problem.
    """
    found: list[dict[str, object]] = []
    for marker, kind, validate in (
        (b"MZ", "pe", _pe_at),
        (b"\x7fELF", "elf", _elf_at),
    ):
        pos = 1
        checked = 0
        while checked < MAX_EMBED_CANDIDATES and len(found) < 32:
            pos = data.find(marker, pos)
            if pos == -1:
                break
            checked += 1
            if validate(data, pos):
                found.append({"offset": pos, "kind": kind})
            pos += 1
    return found


# --- the analyzer -------------------------------------------------------------


def _truncate(value: str) -> str:
    return value[:MAX_EVIDENCE_CHARS]


#: Types whose whole-file entropy is near 8.0 by design. Reporting "high
#: entropy" for a JPEG or a .docx is not a finding, it is a bug that trains
#: analysts to ignore the signal.
_ALREADY_COMPRESSED_MIMES = {
    "application/zip",
    "application/java-archive",
    "application/vnd.android.package-archive",
    "application/gzip",
    "application/x-bzip2",
    "application/x-xz",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
}


def _entropy_is_meaningful(sample: Sample, family: str) -> bool:
    if family == "archive":
        return False
    mime = (sample.mime or "").lower()
    if mime.startswith(("image/", "audio/", "video/")):
        return False
    # OOXML documents are ZIP containers; their whole-file entropy is always
    # near 8 and says nothing about the document.
    if mime.startswith("application/vnd.openxmlformats"):
        return False
    return mime not in _ALREADY_COMPRESSED_MIMES


def analyze(sample: Sample, *, family: str = "") -> AnalyzerResult:
    """Run the type-independent pass over one quarantined sample.

    ``family`` is what :mod:`..identify` decided; it is only used to suppress
    checks that are meaningless for that shape (entropy on an archive). It is
    optional so this analyzer still runs when identification itself failed.
    """
    started = time.perf_counter()
    result = AnalyzerResult(analyzer=NAME)

    try:
        data = sample.read(MAX_READ)
    except OSError as exc:
        return AnalyzerResult.unavailable(
            NAME, f"could not read the quarantined sample ({type(exc).__name__})"
        )

    size = sample.size_bytes if sample.size_bytes >= 0 else len(data)
    truncated = size > len(data)

    signals: list[Signal] = result.signals
    facts: dict[str, object] = result.facts
    facts.update(
        {
            "size_bytes": size,
            "bytes_examined": len(data),
            "truncated": truncated,
            "mime": sample.mime,
            "magic": sample.magic,
        }
    )

    # --- size
    if size == 0 or not data:
        signals.append(
            Signal(
                id="generic.zero_bytes",
                title="Sample is empty",
                severity="low",
                detail="The submitted file contains no bytes, so nothing can be analysed.",
                evidence={"size_bytes": size},
            )
        )
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    if size < TINY_FILE_BYTES:
        signals.append(
            Signal(
                id="generic.tiny_file",
                title=f"Sample is only {size} bytes",
                severity="info",
                detail=(
                    "Too small to carry a real payload on its own. Usually a "
                    "stub, a truncated upload, or a downloader one-liner."
                ),
                evidence={"size_bytes": size},
            )
        )

    # --- the name versus the bytes
    if sample.extension_mismatch:
        signals.append(
            Signal(
                id="generic.extension_mismatch",
                title="File content contradicts its extension",
                severity="high",
                detail=(
                    f"The submitter named this {sample.claimed_extension or '(no extension)'} "
                    f"but the bytes are {sample.magic}. Renaming an executable to look like a "
                    "document is one of the oldest and most effective delivery tricks."
                ),
                evidence={
                    "claimed_extension": _truncate(sample.claimed_extension or ""),
                    "original_name": _truncate(sample.original_name or ""),
                    "detected_mime": _truncate(sample.mime or ""),
                    "detected_magic": _truncate(sample.magic or ""),
                },
            )
        )

    # --- entropy
    entropy = shannon_entropy(data)
    facts["entropy_overall"] = round(entropy, 4)
    if (
        entropy > ENTROPY_THRESHOLD
        and len(data) >= ENTROPY_MIN_BYTES
        and _entropy_is_meaningful(sample, family)
    ):
        signals.append(
            Signal(
                id="generic.high_entropy_overall",
                title=f"Whole-file entropy {entropy:.2f}/8.00",
                severity="medium",
                detail=(
                    "The file is close to incompressible across its whole length, which "
                    "means packed, encrypted, or otherwise obfuscated content. Legitimate "
                    "files of this type are normally well below this."
                ),
                evidence={
                    "entropy": round(entropy, 4),
                    "threshold": ENTROPY_THRESHOLD,
                    "mime": _truncate(sample.mime or ""),
                },
            )
        )

    # --- an executable hiding inside something that is not one
    if family not in _EMBED_EXEMPT_FAMILIES and (sample.mime or "") not in _EMBED_EXEMPT_MIMES:
        embedded = _find_embedded_executables(data)
        if embedded:
            facts["embedded_executables"] = embedded
            signals.append(
                Signal(
                    id="generic.embedded_executable",
                    title=f"Executable header found inside a {sample.magic}",
                    severity="high",
                    detail=(
                        "A valid PE or ELF header sits at a non-zero offset in a file that "
                        "is not itself an executable or an archive. That is a dropper "
                        "layout: the carrier is opened, the payload is carved out."
                    ),
                    evidence={
                        "count": len(embedded),
                        "offsets": [e["offset"] for e in embedded[:16]],
                        "kinds": sorted({str(e["kind"]) for e in embedded}),
                        "carrier": _truncate(sample.magic or sample.mime or ""),
                    },
                )
            )

    # --- strings and indicators
    strings = printable_strings(data)
    facts["string_count"] = len(strings)
    facts["top_strings"] = _top_strings(strings)

    iocs, noise = split_noise("\n".join(strings))
    result.iocs = iocs
    facts["ioc_counts"] = {k: len(v) for k, v in iocs.to_dict().items() if v}
    for key, values in noise.items():
        if values:
            facts[key] = values

    signals.extend(_indicator_signals(iocs))

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    return result


#: How many strings survive into the report's technical annex.
_TOP_STRINGS = 60


def _top_strings(strings: list[str]) -> list[str]:
    """Longest distinct strings, truncated. Bounded on both axes."""
    seen: dict[str, None] = {}
    for text in strings:
        stripped = text.strip()
        if len(stripped) >= 6:
            seen.setdefault(stripped, None)
        if len(seen) >= 4000:
            break
    ranked = sorted(seen, key=len, reverse=True)[:_TOP_STRINGS]
    return [_truncate(s) for s in ranked]


def _indicator_signals(iocs: IOCs) -> list[Signal]:
    signals: list[Signal] = []

    if len(iocs.urls) > MANY_URLS_THRESHOLD:
        signals.append(
            Signal(
                id="generic.many_urls",
                title=f"{len(iocs.urls)} distinct URLs embedded in the sample",
                severity="low",
                detail=(
                    "A large number of embedded links. Normal for a newsletter or a "
                    "web page, unusual for a document or a binary."
                ),
                evidence={
                    "count": len(iocs.urls),
                    "threshold": MANY_URLS_THRESHOLD,
                    "sample": [_truncate(u) for u in iocs.urls[:10]],
                },
            )
        )

    ip_urls: list[str] = []
    for url in iocs.urls:
        try:
            host = (urlsplit(url).hostname or "").strip("[]")
        except ValueError:
            continue
        if host and _classify_ip(host) is not None:
            ip_urls.append(url)
    if ip_urls:
        signals.append(
            Signal(
                id="generic.ip_literal_url",
                title="URL points at a bare IP address",
                severity="medium",
                detail=(
                    "The link addresses a host by IP rather than by name. Legitimate "
                    "services use names; hard-coded IPs are typical of throwaway "
                    "command-and-control and staging hosts."
                ),
                evidence={"count": len(ip_urls), "urls": [_truncate(u) for u in ip_urls[:10]]},
            )
        )

    lookalikes: list[dict[str, str]] = []
    for domain in iocs.domains:
        reason = _lookalike_reason(domain)
        if reason:
            lookalikes.append({"domain": _truncate(domain), "reason": reason})
        if len(lookalikes) >= 20:
            break
    if lookalikes:
        signals.append(
            Signal(
                id="generic.punycode_or_lookalike_domain",
                title="Domain designed to be misread as a known brand",
                severity="medium",
                detail=(
                    "A punycode label or a near-miss spelling of a well-known service. "
                    "Both exist to survive a glance at the address bar."
                ),
                evidence={"count": len(lookalikes), "domains": lookalikes},
            )
        )

    flagged: list[dict[str, str]] = []
    for domain in iocs.domains:
        tld = domain.rsplit(".", 1)[-1]
        if tld in _SUSPICIOUS_TLDS:
            flagged.append({"domain": _truncate(domain), "tld": "." + tld})
        if len(flagged) >= 20:
            break
    if flagged:
        signals.append(
            Signal(
                id="generic.suspicious_tld",
                title="Domain in a top-level domain favoured by abuse",
                severity="low",
                detail=(
                    "These registries are cheap, fast, and lightly policed, so a large "
                    "share of short-lived phishing infrastructure lives there. On its "
                    "own this is context, not a verdict."
                ),
                evidence={
                    "count": len(flagged),
                    "domains": flagged,
                    "watched_tlds": sorted("." + t for t in _SUSPICIOUS_TLDS),
                },
            )
        )

    return signals


__all__ = [
    "NAME",
    "FAMILY",
    "analyze",
    "extract_iocs",
    "split_noise",
    "shannon_entropy",
    "printable_strings",
]
