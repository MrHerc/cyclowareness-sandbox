"""Static analysis of script samples — the "decode but never run" analyzer.

Handles the ``script`` family: ``.ps1 .js .jse .vbs .vbe .bat .cmd .py .sh .hta
.wsf``. Everything here is text processing. Nothing in this module executes,
imports, compiles or hands the sample to anything that would: the input is live
malware by definition, and a script is the one file type where "just run it to
see" is most tempting and most fatal.

The most valuable thing this analyzer produces is the **decoded layer**. Script
droppers hide their real intent in base64 (PowerShell ``-EncodedCommand`` is
UTF-16LE base64), so we decode candidate blobs, recursively to a depth of 2, and
run the exact same detectors over the decoded text. A signal that fired only
inside layer 2 says so in its evidence.

Two deliberate defences against a hostile sample:

* every regex is linear — single quantifiers over negated character classes, no
  nested quantifiers — and every regex runs against a *bounded* prefix of the
  text, because a catastrophic-backtracking pattern and a 30 MB one-liner are
  the same outage;
* every string lifted out of the sample is truncated before it reaches a Signal,
  a fact, or the caller.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
import time
import zlib
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable

from ..contracts import AnalyzerResult, IOCs, Sample, Severity, Signal

ANALYZER = "script"
#: Registry dispatch attributes (see analyzers/__init__.py).
NAME = "script"
FAMILY = "script"

#: Extensions this analyzer claims. Identification decides the family; this is
#: the belt to that braces.
SUPPORTED_EXTENSIONS = frozenset(
    {".ps1", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".py", ".sh", ".hta", ".wsf"}
)

#: Mimes identify.py hands us for textual content.
_TEXT_MIMES = frozenset(
    {
        "text/x-powershell",
        "text/javascript",
        "text/vbscript",
        "text/x-msdos-batch",
        "text/x-python",
        "text/x-shellscript",
        "text/x-script",
        "text/plain",
        "text/xml",
        "text/html",
        "application/hta",
        "application/javascript",
    }
)

# --- bounds -------------------------------------------------------------------
#: Bytes read off disk. Larger scripts are analysed truncated, and say so.
MAX_READ_BYTES = 4 * 1024 * 1024
#: Characters kept after decoding to text.
MAX_TEXT_CHARS = 2_000_000
#: Characters any regex is allowed to see. Everything past this is unexamined
#: and reported as such.
MAX_SCAN_CHARS = 1_000_000
#: How deep the base64 unwrapping goes. Depth 2 = the encoded command inside the
#: encoded command, and no further.
MAX_DECODE_DEPTH = 2
#: Total decoded layers kept, across the whole recursion.
MAX_LAYERS = 8
#: Base64 candidates inspected per text. Decoding is cheap; unbounded is not.
MAX_B64_CANDIDATES = 80
#: Longest base64 blob we will decode, in encoded characters.
MAX_B64_CHARS = 400_000
#: Ceiling on a single decompressed stream.
MAX_INFLATE_BYTES = 4 * 1024 * 1024
#: Sample-derived text never reaches a Signal longer than this.
SNIPPET_CHARS = 200
#: Per-category IOC cap.
MAX_IOCS_PER_KIND = 100
#: Entropy above which text stops looking like source code.
ENTROPY_THRESHOLD = 5.2
#: A line this long is not something a human typed.
LONG_LINE_CHARS = 800


def _clip(text: str, limit: int = SNIPPET_CHARS) -> str:
    """Truncate sample-derived text and normalise it to one printable line."""
    flat = re.sub(r"\s+", " ", text[: limit * 4]).strip()
    return flat[:limit] + ("…" if len(flat) > limit else "")


# --- pattern detectors --------------------------------------------------------


@dataclass(frozen=True)
class _Detector:
    signal_id: str
    title: str
    severity: Severity
    #: (human label named in the signal detail, pattern)
    patterns: tuple[tuple[str, re.Pattern[str]], ...]
    #: Extra patterns that only run when the sample IS the named language.
    #:
    #: `exec(` and `compile(` are Python builtins and were matched in every
    #: file. In JavaScript `.exec(` is `RegExp.prototype.exec` — every script
    #: that uses a regular expression has it — so jQuery was `malicious` at 48.8
    #: on sixteen matches of `L.exec(t)`, and Vue at 40.5 partly on its own
    #: template compiler being a function named `compile`. Neither has anything
    #: to do with running code from a string.
    python_only: tuple[tuple[str, re.Pattern[str]], ...] = ()


def _p(*pairs: tuple[str, str]) -> tuple[tuple[str, re.Pattern[str]], ...]:
    return tuple((label, re.compile(rx, re.IGNORECASE)) for label, rx in pairs)


_DETECTORS: tuple[_Detector, ...] = (
    _Detector(
        "script.encoded_command",
        "Base64-encoded command",
        "high",
        _p(
            # `-e` really is PowerShell shorthand for -EncodedCommand, so it
            # stays -- but it has to be POWERSHELL's -e. The bare flag plus 20
            # characters from a class containing / and = matched
            # `grep -e abcdefghij0123456789xy`, and `sed -e`, and `docker run -e`.
            ("Base64 -EncodedCommand", r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}"),
            ("powershell -e <base64>",
             r"(?:powershell|pwsh)(?:\.exe)?[^\n]{0,200}?\s-e\s+[A-Za-z0-9+/=]{40,}"),
            ("[Convert]::FromBase64String", r"frombase64string"),
            ("JavaScript atob()", r"\batob\s*\("),
            ("base64 --decode", r"\bbase64(?:\.exe)?\s+(?:-d|-D|--decode)\b"),
            ("python base64.b64decode", r"\bb(?:64|32)decode\s*\("),
            ("VBScript Base64 MSXML decode", r"bin\.base64"),
        ),
    ),
    _Detector(
        "script.download_and_execute",
        "Remote payload retrieval",
        "high",
        _p(
            ("Invoke-WebRequest/iwr", r"\b(?:invoke-webrequest|iwr)\b"),
            ("Invoke-RestMethod/irm", r"\b(?:invoke-restmethod|irm)\b"),
            ("WebClient.DownloadString", r"\bdownloadstring\s*\("),
            ("WebClient.DownloadFile", r"\bdownloadfile\s*\("),
            ("WebClient.DownloadData", r"\bdownloaddata\s*\("),
            ("Net.WebClient", r"net\.webclient"),
            ("curl", r"\bcurl(?:\.exe)?\b"),
            ("wget", r"\bwget(?:\.exe)?\b"),
            ("certutil -urlcache", r"certutil(?:\.exe)?[^\n]{0,80}-urlcache"),
            ("bitsadmin", r"\bbitsadmin(?:\.exe)?\b"),
            ("Start-BitsTransfer", r"\bstart-bitstransfer\b"),
            ("MSXML2.XMLHTTP", r"msxml2\.(?:xmlhttp|serverxmlhttp)"),
            ("WinHttp.WinHttpRequest", r"winhttp\.winhttprequest"),
            ("ADODB.Stream write-to-disk", r"adodb\.stream"),
            ("python urllib/requests", r"urllib\.request|\brequests\.get\s*\(|\burlretrieve\s*\("),
            # `Start-Process` was here. It starts a LOCAL program, and this
            # detector is titled "Remote payload retrieval" and asserts both
            # `network` and `execution`. It moved to script.dynamic_execution,
            # which asserts execution alone and is the true statement.
        ),
    ),
    _Detector(
        "script.dynamic_execution",
        "Runtime code evaluation",
        "high",
        _p(
            ("IEX / Invoke-Expression", r"\b(?:iex|invoke-expression)\b"),
            ("eval()", r"\beval\s*\("),
            ("new Function()", r"\bnew\s+function\s*\(|\bfunction\s*\(\s*['\"]"),
            ("VBScript ExecuteGlobal", r"\bexecuteglobal\b"),
            # `(?<![.\w])` for the reason spelled out eleven lines below:
            # without it every `db.execute(...)`, `cursor.execute(...)` and
            # `session.execute(...)` on earth is "Runtime code evaluation".
            ("VBScript Execute", r"(?<![.\w])execute\s*\("),
            ("Start-Process", r"\bstart-process\b"),
            ("[ScriptBlock]::Create", r"\[scriptblock\]\s*::\s*create"),
            ("WScript.Shell Run", r"wscript\.shell"),
        ),
        python_only=_p(
            # `(?<![.\w])` so a METHOD call is not a builtin call. Without it
            # `re.compile(...)` and JavaScript's `RegExp.prototype.exec` both
            # counted as running code from a string.
            ("python exec()", r"(?<![.\w])exec\s*\("),
            ("python compile()", r"(?<![.\w])compile\s*\("),
        ),
    ),
    _Detector(
        "script.amsi_or_etw_tamper",
        "AMSI / ETW tampering",
        "critical",
        _p(
            # A bare `amsi` mention was here at `critical`. It matched any
            # document that DISCUSSES AMSI -- a security note, a detection
            # rule, a blog post saved as .ps1. The specific patterns below
            # are the tamper evidence and they are unchanged.
            ("amsiInitFailed patch", r"amsiinitfailed"),
            ("AmsiScanBuffer patch", r"amsiscanbuffer"),
            ("EtwEventWrite patch", r"etweventwrite"),
            ("PSEtwLogProvider", r"psetwlogprovider"),
            ("NtTraceEvent", r"nttraceevent"),
            ("ScriptBlock logging disable", r"scriptblocklogging|logpipelineexecutiondetails"),
        ),
    ),
    _Detector(
        "script.execution_policy_bypass",
        "Execution policy bypass",
        "medium",
        _p(
            ("-ExecutionPolicy Bypass", r"-ex[ecutionpoly]{0,14}\s+(?:bypass|unrestricted)"),
            ("Set-ExecutionPolicy", r"set-executionpolicy\s+(?:bypass|unrestricted)"),
            ("ExecutionPolicy Bypass", r"executionpolicy\s+(?:bypass|unrestricted)"),
        ),
    ),
    _Detector(
        "script.hidden_window",
        "Hidden window execution",
        "medium",
        _p(
            ("-WindowStyle Hidden", r"-w(?:indowstyle)?\s+h(?:idden)?\b"),
            ("WindowStyle=Hidden", r"windowstyle\s*=\s*['\"]?hidden"),
            ("vbHide", r"\bvbhide\b"),
            ("WScript Run(..., 0)", r"\.run\s*\([^)\n]{0,200},\s*0\s*[,)]"),
            ("CREATE_NO_WINDOW", r"create_?no_?window"),
            ("start /b", r"\bstart\s+/b\b"),
        ),
    ),
    _Detector(
        "script.persistence",
        "Persistence mechanism",
        "high",
        _p(
            ("schtasks", r"\bschtasks(?:\.exe)?\b"),
            ("Register-ScheduledTask", r"\b(?:register|new)-scheduledtask\b"),
            # NO PATTERN FOR THE RUN KEY ITSELF. `reg query HKCU\...\Run`
            # READS it, which is discovery; writing it is persistence, and
            # the same string appears either way. Measured on a harmless
            # .bat that only queried it and was accused of
            # `Batch.Downloader.Persistence`.
            #
            # A first attempt kept the key and demanded a nearby `/v`, and a
            # test caught that `reg query ... /v Foo` names a value on a read
            # too. Nothing about the key distinguishes the two, so the key
            # alone no longer fires. `reg add` and the `*-ItemProperty`
            # patterns below catch the ordinary writes; `reg import` is the
            # one they genuinely miss.
            ("reg import", r"\breg(?:\.exe)?\s+import\b"),
            ("reg add", r"\breg(?:\.exe)?\s+add\b"),
            ("New-ItemProperty registry write", r"\bnew-itemproperty\b|\bset-itemproperty\b"),
            ("WMI event subscription", r"__eventfilter|commandlineeventconsumer|__filtertoconsumerbinding|register-wmievent|set-wmiinstance"),
            ("crontab", r"\bcrontab\b|/etc/cron"),
            ("systemd unit", r"systemctl\s+enable|/etc/systemd/system"),
            ("macOS LaunchAgent", r"launchagents|launchdaemons"),
            ("Startup folder", r"shell:startup|\\programs\\startup"),
        ),
    ),
    _Detector(
        "script.credential_access",
        "Credential theft",
        "critical",
        _p(
            ("Mimikatz", r"\bmimikatz\b|sekurlsa|logonpasswords|lsadump|kerberos::"),
            ("LSASS access", r"\blsass(?:\.exe)?\b|minidumpwritedump|\bprocdump\b"),
            ("SAM/SECURITY hive export", r"reg(?:\.exe)?\s+save[^\n]{0,60}\b(?:sam|system|security)\b"),
            ("NTDS.dit", r"\bntds\.dit\b"),
            ("DPAPI", r"\bdpapi\b|cryptunprotectdata"),
            # `Login Data` is a Chrome profile FILE and is spelled with a
            # space. `\s?` made the space optional, so every `loginData`
            # identifier in every JavaScript file was "Credential theft" at
            # `critical`. The space is required now, and the Windows profile
            # path form is accepted beside it so the real artefact still hits.
            ("Browser credential store",
             r"\blogin data\b"
             r"|user data[\\/][^\\/\n]{0,40}[\\/]login data"
             r"|\bvaultcmd\b|\blazagne\b"),
        ),
    ),
    _Detector(
        "script.defense_evasion",
        "Defence tampering",
        "high",
        _p(
            ("Set-MpPreference / Defender", r"(?:set|add)-mppreference|disablerealtimemonitoring|disableioavprotection|disablescriptscanning|\bwindefend\b"),
            ("Defender exclusion", r"-exclusionpath|-exclusionextension"),
            ("Event log clearing", r"wevtutil(?:\.exe)?\s+cl\b|clear-eventlog|remove-eventlog"),
            ("Shadow copy deletion", r"vssadmin[^\n]{0,40}delete\s+shadows|win32_shadowcopy"),
            ("Firewall disable", r"netsh\s+advfirewall\s+set[^\n]{0,60}\boff\b"),
            ("Recovery disable", r"bcdedit[^\n]{0,60}(?:recoveryenabled|bootstatuspolicy)"),
            ("Attribute hiding", r"attrib(?:\.exe)?\s+\+[hs]"),
        ),
    ),
)

# --- obfuscation techniques ---------------------------------------------------

#: PowerShell and cmd obfuscation splits an identifier with escape characters —
#: `` i`e`x ``, `p^o^w^e^r^s^h^e^l^l`` — so the escape sits BETWEEN two word
#: characters. That is the whole trick, and it is what these must match.
#:
#: Counting every backtick instead made Markdown obfuscated: a `` `code span` ``
#: is a backtick, and caddy's and hugo's CHANGELOG.md have 910 and 253 of them.
#: Both READMEs came out `Script.Suspicious.ObfuscationHigh`, which made caddy.zip
#: and hugo.zip suspicious with them. Counting every caret has the same problem
#: with regular expressions, diffs and mathematics.
#:
#: A fence (```` ``` ````) and a code span both put the backtick against
#: whitespace or another backtick, never inside a word, so neither can reach this.
#: The caret is LETTERS on both sides, not word characters: cmd escaping splits
#: an identifier (`p^o^w^e^r^s^h^e^l^l`), while `x^2`, `y^2`, `n^k` is how
#: exponentiation is written in any document that contains mathematics. A
#: symbolic exponent (`a^n`) is still letter-caret-letter and would trip if a
#: document repeated one hundreds of times; none of the 105 documentation files
#: in the benign corpus does.
_RE_BACKTICK = re.compile(r"(?<=\w)`(?=\w)")
_RE_CARET = re.compile(r"(?<=[A-Za-z])\^(?=[A-Za-z])")
_RE_CHARCODE = re.compile(r"\[char\]\s*\d{1,3}|\bchrw?\s*\(\s*\d{1,3}\s*\)|fromcharcode", re.I)
#: STRING reversal, which is a way to hide a literal. A bare `.reverse()` is
#: `Array.prototype.reverse` — jQuery calls it to order DOM nodes, and that was
#: counted as an obfuscation technique. The JavaScript idiom for reversing a
#: STRING is `split('').reverse().join('')`, which is what this now matches.
_RE_REVERSE = re.compile(
    r"\[array\]\s*::\s*reverse"
    r"|\bstrreverse\s*\("
    r"|\[::-1\]"
    r"|\bsplit\s*\(\s*(['\"])\1\s*\)\s*\.\s*reverse\s*\(\s*\)",
    re.I,
)
_RE_CONCAT = re.compile(r"['\"]\s*\+\s*['\"]")
_RE_FORMAT_SLOT = re.compile(r"\{\d{1,2}\}")
_RE_FORMAT_OP = re.compile(r"\s-f\s|\.format\s*\(", re.I)

# --- IOC patterns -------------------------------------------------------------
# Every one of these is a single quantifier over a negated class or a literal
# class: linear time, no nested repetition.

_RE_URL = re.compile(r"\b(?:https?|ftps?)://[^\s\"'<>)\]}\\^`|]{1,2000}", re.I)
_RE_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_RE_WIN_PATH = re.compile(r"[A-Za-z]:\\[^\s\"'<>|*?\n\r;,()]{1,240}")
_RE_ENV_PATH = re.compile(r"%[A-Za-z_]{1,24}%\\[^\s\"'<>|*?\n\r;,()]{1,240}")
_RE_UNC_PATH = re.compile(r"\\\\[A-Za-z0-9._-]{1,64}\\[^\s\"'<>|*?\n\r;,()]{1,240}")
_RE_NIX_PATH = re.compile(r"/(?:etc|tmp|var|usr|home|opt|bin|sbin|dev|proc|root)/[^\s\"'<>|*?\n\r;,()]{0,240}")
_RE_REGKEY = re.compile(
    r"(?:HKEY_[A-Z_]{1,30}|HKLM|HKCU|HKCR|HKU|HKCC):?\\[A-Za-z0-9 _.\\{}-]{1,200}", re.I
)

_TLDS = (
    "com|net|org|edu|gov|mil|int|info|biz|name|pro|io|co|me|tv|cc|ws|su|ru|cn|jp|kr|in|br|"
    "uk|de|fr|it|es|nl|pl|se|no|fi|dk|cz|ro|gr|pt|tr|ir|az|ge|ua|by|kz|il|sa|ae|eg|za|ng|"
    "au|nz|mx|ar|cl|ca|xyz|top|club|online|site|shop|store|live|link|fun|icu|dev|app|zip|"
    "mov|cloud|space|website|pw|tk|ml|ga|cf|gq|to|st|sh|is|am|fm|gg|vip|work|life|world"
)
#: A DENIAL OF SERVICE, MEASURED.
#:
#: The old pattern was `\b[a-zA-Z0-9][a-zA-Z0-9.-]{0,80}\.(?:<100 TLDs>)\b`, and
#: its label class INCLUDES the dot that the following `\.` must then match. So
#: every start position backtracks through up to 81 lengths and retries the
#: 100-branch alternation at every dot it lands on. One million characters of
#: "a.a.a.a…" took SECONDS and matched nothing — and `_extract_iocs` runs once on
#: the raw source and once per decoded layer up to `MAX_LAYERS`, so one upload of
#: a megabyte of dots wrapped in eight base64 layers costs minutes of CPU.
#:
#: Fixed the way `generic._DOMAIN_TOKEN_RE` already does it: the dot leaves the
#: label class, each label is bounded on its own, and lookarounds replace `\b` so
#: there is exactly one way to match at any position. Linear, and it still finds
#: every domain the old one found.
_RE_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9._-])"
    r"[A-Za-z0-9][A-Za-z0-9-]{0,62}"
    r"(?:\.[A-Za-z0-9][A-Za-z0-9-]{0,62})*"
    r"\.(?:" + _TLDS + r")"
    r"(?![A-Za-z0-9-])",
    re.IGNORECASE,
)

#: Base64 candidate. 20+ chars of the alphabet is 15 bytes — short enough to
#: catch ``FromBase64String('...')`` one-liners, long enough that ordinary
#: identifiers rarely qualify. Anything that decodes to non-text is discarded.
_RE_B64 = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

_PRINTABLE = frozenset(range(32, 127)) | {9, 10, 13}


# --- text recovery ------------------------------------------------------------


def _to_text(data: bytes) -> tuple[str, str] | None:
    """Best-effort decode of a script's bytes. Returns (text, encoding_used)."""
    if data.startswith(b"\xef\xbb\xbf"):
        try:
            return data.decode("utf-8-sig"), "utf-8-bom"
        except UnicodeDecodeError:
            pass
    if data.startswith(b"\xff\xfe"):
        try:
            return data[2:].decode("utf-16-le", "replace"), "utf-16le-bom"
        except Exception:
            pass
    if data.startswith(b"\xfe\xff"):
        try:
            return data[2:].decode("utf-16-be", "replace"), "utf-16be-bom"
        except Exception:
            pass

    head = data[:8192]
    if head:
        odd_nuls = head[1::2].count(0)
        if odd_nuls > len(head[1::2]) * 0.6:
            return data.decode("utf-16-le", "replace"), "utf-16le"
        even_nuls = head[0::2].count(0)
        if even_nuls > len(head[0::2]) * 0.6:
            return data.decode("utf-16-be", "replace"), "utf-16be"

    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass

    printable = sum(1 for b in head if b in _PRINTABLE)
    if head and printable / len(head) >= 0.85:
        return data.decode("latin-1", "replace"), "latin-1 (lossy)"
    return None


def _looks_textual(data: bytes) -> bool:
    if len(data) < 8:
        return False
    sample = data[:4096]
    return sum(1 for b in sample if b in _PRINTABLE) / len(sample) >= 0.85


def _entropy(text: str) -> float:
    window = text[:262_144]
    if not window:
        return 0.0
    counts = Counter(window)
    n = len(window)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --- base64 unwrapping --------------------------------------------------------


def _b64_decode(blob: str) -> bytes | None:
    trimmed = blob.rstrip("=")
    padding = "=" * (-len(trimmed) % 4)
    try:
        raw = base64.b64decode(trimmed + padding, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw or None


def _inflate(raw: bytes) -> bytes | None:
    """Bounded gzip/deflate expansion.

    Included because base64 + GZipStream is the standard PowerShell wrapper and
    without it the decoded layer — the whole point of this analyzer — comes back
    as noise. Decompression is pure parsing; nothing is executed.
    """
    for wbits in (31, -15, 15):
        try:
            out = zlib.decompressobj(wbits).decompress(raw, MAX_INFLATE_BYTES)
        except zlib.error:
            continue
        # Textuality is decided by _to_text downstream, which understands
        # UTF-16LE — the encoding a PowerShell GZipStream payload decompresses
        # to. Gating here on a byte-ratio would wrongly drop exactly that case.
        if out:
            return out
    return None


def _decoded_to_text(raw: bytes) -> tuple[str, str] | None:
    """Turn decoded bytes into text, or decide they are not text at all."""
    if raw[:2] == b"\x1f\x8b" or raw[:1] == b"x":
        inflated = _inflate(raw)
        if inflated is not None:
            got = _to_text(inflated)
            if got:
                return got[0], f"gzip/deflate + {got[1]}"

    if len(raw) >= 8 and raw[1::2].count(0) > len(raw[1::2]) * 0.8:
        text = raw.decode("utf-16-le", "replace")
        if text.strip():
            return text, "utf-16le"

    if not _looks_textual(raw):
        return None
    got = _to_text(raw)
    if not got or not got[0].strip():
        return None
    return got


def _collect_layers(text: str, depth: int, layers: list[dict[str, Any]], seen: set[str]) -> None:
    """Recursively decode base64 blobs. Depth-first, hard-capped everywhere."""
    if depth > MAX_DECODE_DEPTH or len(layers) >= MAX_LAYERS:
        return
    for index, match in enumerate(_RE_B64.finditer(text[:MAX_SCAN_CHARS])):
        if index >= MAX_B64_CANDIDATES or len(layers) >= MAX_LAYERS:
            return
        blob = match.group(0)
        if len(blob) > MAX_B64_CHARS:
            continue
        raw = _b64_decode(blob)
        if raw is None:
            continue
        got = _decoded_to_text(raw)
        if got is None:
            continue
        decoded, encoding = got
        decoded = decoded[:MAX_TEXT_CHARS]
        key = decoded[:512]
        if key in seen:
            continue
        seen.add(key)
        layers.append(
            {
                "depth": depth,
                "encoding": encoding,
                "encoded_chars": len(blob),
                "decoded_chars": len(decoded),
                "encoded_preview": _clip(blob, 80),
                "text": decoded,
            }
        )
        _collect_layers(decoded, depth + 1, layers, seen)


# --- per-text scanning --------------------------------------------------------


@dataclass
class _Hit:
    signal_id: str
    title: str
    severity: Severity
    labels: list[str]
    snippet: str
    layer: str


#: Extensions whose contents really are Python. A `.py` is Python; a decoded
#: base64 layer inside one could be anything, so the layer inherits the
#: submission's language rather than being guessed at.
_PYTHON_EXTENSIONS = frozenset({".py", ".pyw", ".pyi"})


def _scan_text(
    text: str, layer: str, *, is_python: bool = False, is_prose: bool = False
) -> list[_Hit]:
    window = text[:MAX_SCAN_CHARS]
    hits: list[_Hit] = []

    for det in _DETECTORS:
        labels: list[str] = []
        snippet = ""
        patterns = det.patterns + (det.python_only if is_python else ())
        for label, pattern in patterns:
            found = pattern.search(window)
            if found:
                labels.append(label)
                if not snippet:
                    start = max(0, found.start() - 30)
                    snippet = _clip(window[start : found.end() + 60])
        if labels:
            hits.append(_Hit(det.signal_id, det.title, det.severity, labels, snippet, layer))

    techniques = _obfuscation_techniques(window, is_prose=is_prose)
    if techniques:
        hits.append(
            _Hit(
                "script.obfuscation_high",
                "Obfuscated source",
                "high" if len(techniques) >= 2 else "medium",
                techniques,
                "",
                layer,
            )
        )

    # A minifier produces one enormous line by design; that is the whole job.
    # Every published library therefore trips this, so it is not evidence about
    # a file that says what it is.
    longest = max((len(line) for line in window.splitlines()), default=len(window))
    if longest >= LONG_LINE_CHARS and not _is_published_library(window):
        hits.append(
            _Hit(
                "script.long_one_liner",
                "Very long single line",
                "medium",
                [f"longest line is {longest} characters"],
                "",
                layer,
            )
        )
    return hits


#: A distributed library announces itself. Every one of them ships a banner
#: comment in the first few hundred characters carrying a name, a version and a
#: licence:
#:
#:     /*! jQuery v3.7.1 | (c) OpenJS Foundation … | jquery.org/license */
#:     /** vue v3.5.13 · (c) 2018-present Yuxi (Evan) You · @license MIT **/
#:
#: Obfuscated malware does the opposite by construction: its whole purpose is to
#: be unreadable, and it does not put its name, its version and its licence at
#: the top. This is not proof — a banner is three lines to forge — and it is not
#: used as one. It only decides whether MINIFICATION counts as obfuscation.
_RE_LIBRARY_BANNER = re.compile(
    r"/\*[!*].{0,400}?(?:\bv\d+\.\d+|@license|\bcopyright\b|\(c\)\s*\d{4})",
    re.IGNORECASE | re.DOTALL,
)


def _is_published_library(window: str) -> bool:
    return bool(_RE_LIBRARY_BANNER.match(window.lstrip()[:600] or ""))


def _obfuscation_techniques(window: str, *, is_prose: bool = False) -> list[str]:
    found: list[str] = []
    n = max(len(window), 1)

    # MINIFICATION IS NOT OBFUSCATION.
    #
    # Both produce one enormous line of dense text with short identifiers, so
    # entropy and line length cannot tell them apart — measured, jQuery 3.7.1
    # sits at 5.26 bits/char against a 5.2 threshold, and came out `malicious`
    # at 48.8 for being minified. What CAN tell them apart is that a published
    # library says who it is at the top.
    #
    # Only these two are waived. Character-code reconstruction, backtick and
    # caret escaping, and format-slot reordering are not things minifiers do,
    # so they still count against a file however it announces itself.
    published = _is_published_library(window)

    # ENTROPY IS NOT OBFUSCATION FOR A DOCUMENT EITHER.
    #
    # Prose is dense: mixed case, punctuation, URLs, badges, code samples in
    # several languages. Measured, hugo's README.md sits at 5.22 bits/char
    # against a 5.2 threshold and was `Script.Suspicious.ObfuscationHigh`, which
    # made hugo.zip suspicious for shipping a readme. jQuery was the same
    # argument at 5.26 from minification. The threshold cannot separate dense
    # text from hidden code, so it is not asked about files that are read rather
    # than run — `_is_prose` already decides which those are, and the capability
    # claims in such a file are already downgraded to `document.mentions_*`.
    ent = _entropy(window)
    if ent >= ENTROPY_THRESHOLD and not published and not is_prose:
        found.append(f"high character entropy ({ent:.2f} bits/char)")

    backticks = len(_RE_BACKTICK.findall(window))
    if backticks >= 15 and backticks / n >= 0.004:
        found.append(f"backtick escaping ({backticks} occurrences)")

    carets = len(_RE_CARET.findall(window))
    if carets >= 15 and carets / n >= 0.004:
        found.append(f"caret escaping ({carets} occurrences)")

    charcodes = len(_RE_CHARCODE.findall(window))
    if charcodes >= 5:
        found.append(f"character-code reconstruction ({charcodes} occurrences)")

    if _RE_REVERSE.search(window):
        found.append("string reversal")

    concats = len(_RE_CONCAT.findall(window))
    if concats >= 10:
        found.append(f"string concatenation splicing ({concats} joins)")

    slots = len(_RE_FORMAT_SLOT.findall(window))
    if slots >= 5 and _RE_FORMAT_OP.search(window):
        found.append(f"format-operator reordering ({slots} slots)")

    return found


# --- IOC extraction -----------------------------------------------------------


def _dedupe(values: Iterable[str], limit: int = MAX_IOCS_PER_KIND) -> list[str]:
    out: dict[str, None] = {}
    for value in values:
        if len(out) >= limit:
            break
        out.setdefault(value, None)
    return list(out)


def _valid_ip(candidate: str) -> bool:
    parts = candidate.split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts)


def _valid_domain(candidate: str) -> bool:
    if ".." in candidate or len(candidate) > 253:
        return False
    labels = candidate.split(".")
    return len(labels) >= 2 and all(
        1 <= len(lbl) <= 63 and not lbl.startswith("-") and not lbl.endswith("-") for lbl in labels
    )


def _extract_iocs(text: str) -> IOCs:
    window = text[:MAX_SCAN_CHARS]
    iocs = IOCs()

    urls = [m.group(0).rstrip(".,;:!'\"") for m in _RE_URL.finditer(window)]
    iocs.urls = _dedupe(u[:2000] for u in urls)

    hosts: list[str] = []
    for url in iocs.urls:
        authority = url.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
        host = authority.rsplit(":", 1)[0].strip("[]").lower()
        if host and not _valid_ip(host):
            hosts.append(host)
    hosts.extend(
        m.group(0).lower() for m in _RE_DOMAIN.finditer(window) if _valid_domain(m.group(0))
    )
    iocs.domains = _dedupe(h for h in hosts if _valid_domain(h))

    iocs.ips = _dedupe(m.group(0) for m in _RE_IP.finditer(window) if _valid_ip(m.group(0)))

    paths: list[str] = []
    for pattern in (_RE_UNC_PATH, _RE_WIN_PATH, _RE_ENV_PATH, _RE_NIX_PATH):
        paths.extend(m.group(0)[:260] for m in pattern.finditer(window))
    iocs.file_paths = _dedupe(paths)

    iocs.registry_keys = _dedupe(m.group(0)[:220] for m in _RE_REGKEY.finditer(window))
    return iocs


# --- signal assembly ----------------------------------------------------------

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _merge_hits(hits: list[_Hit]) -> list[Signal]:
    """One Signal per id. The same id firing in two layers is one observation
    with more support, and the evidence names every layer it came from."""
    grouped: dict[str, list[_Hit]] = {}
    for hit in hits:
        grouped.setdefault(hit.signal_id, []).append(hit)

    signals: list[Signal] = []
    for signal_id, group in grouped.items():
        best = max(group, key=lambda h: _SEV_RANK[h.severity])
        labels = _dedupe((label for h in group for label in h.labels), limit=24)
        layers = _dedupe([h.layer for h in group])
        snippet = next((h.snippet for h in group if h.snippet), "")
        where = "raw source" if layers == ["raw source"] else ", ".join(layers)
        signals.append(
            Signal(
                id=signal_id,
                title=best.title,
                severity=best.severity,
                detail=f"{'; '.join(labels)} (seen in: {where})",
                evidence={
                    "indicators": labels,
                    "layers": layers,
                    "context": snippet,
                },
            )
        )
    signals.sort(key=lambda s: -_SEV_RANK[s.severity])
    return signals


def _layer_signals(layers: list[dict[str, Any]]) -> list[Signal]:
    out: list[Signal] = []
    for index, layer in enumerate(layers, start=1):
        depth = layer["depth"]
        out.append(
            Signal(
                id="script.decoded_layer",
                title=f"Decoded hidden layer {index} (depth {depth}, {layer['encoding']})",
                # Nesting is deliberate work by the author; depth 2 is not an
                # accident and is graded higher than a single wrapper.
                severity="medium" if depth >= 2 else "low",
                detail=(
                    f"{layer['encoded_chars']} base64 chars decoded via {layer['encoding']} to "
                    f"{layer['decoded_chars']} chars: {_clip(layer['text'])}"
                ),
                evidence={
                    "depth": depth,
                    "encoding": layer["encoding"],
                    "encoded_chars": layer["encoded_chars"],
                    "decoded_chars": layer["decoded_chars"],
                    "encoded_preview": layer["encoded_preview"],
                    "decoded_snippet": _clip(layer["text"], 400),
                },
            )
        )
    return out


# --- prose -------------------------------------------------------------------

#: Extensions whose content is READ, never executed. Documentation, notes,
#: manuals, config, source in languages nothing here runs.
#:
#: The indicators this analyzer looks for do not change meaning between a script
#: and a document — but what they PROVE does. In a `.ps1`, `Invoke-Expression`
#: is the program: it will run. In a README it is a sentence about a program.
#: The engine's own rule is that a capability is something the sample can DO,
#: not something it mentions, and this analyzer was breaking it on every file.
#:
#: Measured on the corpus: of 59 prose files (all documentation extracted from
#: benign archives, ZERO malware), 24 were rated suspicious or malicious.
#: rclone's README.txt, README.html and its `rclone.1` man page were MALICIOUS at
#: CIR 8.8 — for explaining how to install rclone with curl.
PROSE_EXTENSIONS = frozenset({
    ".txt", ".md", ".rst", ".log", ".csv", ".tsv",
    ".html", ".htm", ".xhtml",
    ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".css", ".scss", ".less",
    ".c", ".h", ".cpp", ".hpp", ".cs", ".go", ".rs", ".java", ".kt", ".swift",
    ".sql", ".tex", ".po", ".pot", ".diff", ".patch", ".desktop", ".service", ".def",
    # man pages: roff sections 1-9, plus the compressed forms
    ".1", ".2", ".3", ".4", ".5", ".6", ".7", ".8", ".9", ".man", ".roff",
    # PEM-armoured material: certificates, keys, requests, signatures. Base64
    # between BEGIN/END markers with commentary around it. `curl-ca-bundle.crt`
    # came out MALICIOUS 67.2 because its header cites the URL the bundle is
    # extracted from, which the analyzer read as fetching a payload.
    ".crt", ".cer", ".pem", ".key", ".pub", ".csr", ".p7b", ".asc", ".sig",
})

#: Signal ids this analyzer emits that assert a capability, mapped to the id it
#: uses instead when the file is prose. The observation is kept — an analyst
#: should still see that a document contains a download-and-execute pattern,
#: because that is how a malicious "instructions" file works — but it no longer
#: claims the file can perform it.
_PROSE_REWRITE = {
    "script.download_and_execute": "document.mentions_remote_payload",
    "script.dynamic_execution": "document.mentions_dynamic_execution",
    "script.persistence": "document.mentions_persistence",
    "script.credential_access": "document.mentions_credential_access",
    "script.defense_evasion": "document.mentions_defense_evasion",
    "script.amsi_or_etw_tamper": "document.mentions_defence_tampering",
    "script.execution_policy_bypass": "document.mentions_policy_bypass",
    "script.encoded_command": "document.mentions_encoded_command",
    "script.hidden_window": "document.mentions_hidden_window",
}


def _is_prose(sample: Sample) -> bool:
    """Will the operating system execute this file, or only display it?

    Keyed on the CLAIMED extension, which is what decides whether anything runs
    it. A `.txt` full of PowerShell is inert until someone renames it — and the
    moment they do, it is submitted as `.ps1` and analysed as one.
    """
    return sample.claimed_extension in PROSE_EXTENSIONS


def _as_prose_findings(signals: list[Signal]) -> list[Signal]:
    """Downgrade capability claims to observations, keeping the evidence."""
    out: list[Signal] = []
    for signal in signals:
        replacement = _PROSE_REWRITE.get(signal.id)
        if replacement is None:
            out.append(signal)
            continue
        out.append(
            Signal(
                id=replacement,
                title=f"Document text describes: {signal.title[0].lower()}{signal.title[1:]}",
                # Never above low. This is a fact about wording, and the file is
                # not executable — a document cannot be the most severe thing in
                # a report on the strength of what it says.
                severity="low",
                detail=(
                    f"{signal.detail} This file's extension is not executed by the "
                    "operating system, so the pattern is text describing the "
                    "behaviour rather than code that performs it. Reported because "
                    "instructions can still be the malicious part of a delivery, "
                    "and suppressed to a note because reading is not running."
                ),
                evidence={**(signal.evidence or {}), "prose": True,
                          "original_signal": signal.id},
            )
        )
    return out


# --- entry point --------------------------------------------------------------


def applies_to(sample: Sample) -> bool:
    return sample.claimed_extension in SUPPORTED_EXTENSIONS or sample.mime in _TEXT_MIMES


def analyze(sample: Sample) -> AnalyzerResult:
    started = time.perf_counter()

    if not applies_to(sample):
        return AnalyzerResult.not_applicable(ANALYZER, sample.mime or "unknown")

    try:
        data = sample.read(MAX_READ_BYTES)
    except OSError as exc:
        return AnalyzerResult.unavailable(ANALYZER, f"could not read the sample: {type(exc).__name__}")

    if not data:
        return AnalyzerResult.unavailable(ANALYZER, "sample is empty")

    try:
        recovered = _to_text(data)
    except Exception as exc:  # noqa: BLE001 — a malformed sample must not crash the engine
        return AnalyzerResult.unavailable(ANALYZER, f"text decode failed: {type(exc).__name__}")

    if recovered is None:
        return AnalyzerResult.unavailable(
            ANALYZER,
            f"content is not text (identified as {sample.magic or sample.mime}); "
            "a binary claiming a script extension belongs to a binary analyzer",
        )

    text, encoding = recovered
    truncated = len(data) >= MAX_READ_BYTES or len(text) > MAX_TEXT_CHARS
    text = text[:MAX_TEXT_CHARS]

    layers: list[dict[str, Any]] = []
    try:
        _collect_layers(text, 1, layers, set())
    except Exception:  # noqa: BLE001 — decoding is best-effort, never fatal
        layers = layers[:MAX_LAYERS]

    # Language-specific detectors run only on the language they are about. The
    # Python builtins `exec()` and `compile()` were matched in every file, and
    # in JavaScript `.exec(` is `RegExp.prototype.exec` — which every script
    # using a regular expression has. jQuery came out `malicious` at 48.8 on
    # sixteen matches of `L.exec(t)`; it does not evaluate anything.
    is_python = (sample.claimed_extension or "").lower() in _PYTHON_EXTENSIONS or (
        sample.mime == "text/x-python"
    )
    prose = _is_prose(sample)
    hits = _scan_text(text, "raw source", is_python=is_python, is_prose=prose)
    iocs = _extract_iocs(text)
    for index, layer in enumerate(layers, start=1):
        label = f"decoded layer {index} (depth {layer['depth']})"
        hits.extend(
            _scan_text(layer["text"], label, is_python=is_python, is_prose=prose)
        )
        iocs = iocs.merge(_extract_iocs(layer["text"]))

    signals = _merge_hits(hits) + _layer_signals(layers)
    if prose:
        signals = _as_prose_findings(signals)

    lines = text.splitlines()
    facts: dict[str, Any] = {
        "encoding": encoding,
        "truncated": truncated,
        "scan_limited": len(text) > MAX_SCAN_CHARS,
        "chars": len(text),
        "lines": len(lines),
        "longest_line": max((len(line) for line in lines), default=0),
        "entropy": round(_entropy(text), 3),
        "claimed_extension": sample.claimed_extension,
        "extension_mismatch": sample.extension_mismatch,
        # Stated in the report, not just applied silently: a reader comparing two
        # files with the same content and different names deserves to see why one
        # carries findings and the other carries notes.
        "prose": prose,
        "decoded_layers": [
            {k: v for k, v in layer.items() if k != "text"} | {"snippet": _clip(layer["text"], 400)}
            for layer in layers
        ],
    }

    return AnalyzerResult(
        analyzer=ANALYZER,
        ran=True,
        signals=signals,
        facts=facts,
        iocs=iocs,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
