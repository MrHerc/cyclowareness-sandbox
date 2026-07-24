"""Static analysis of Android application packages (APK).

An APK is a ZIP with a fixed skeleton: a binary ``AndroidManifest.xml``, one or
more ``classes*.dex`` bytecode files, and optional native ``lib/**/*.so``
libraries. This analyzer reads all of them as data. It **never installs, loads,
links, or runs** any part of the sample — the manifest is parsed as a chunked
binary blob, the DEX files are scanned as bytes for readable strings, and the
native libraries are listed but never mapped. The input is live Android malware
by definition, so the one rule is: nothing here is ever handed to anything that
would execute it.

What this module observes:

* the declared package name and every requested permission, recovered from the
  binary ``AndroidManifest.xml`` (AXML) string pool — with a raw-bytes regex
  fallback when the chunked parse fails;
* dangerous permission groups (SMS, call log / contacts, boot persistence,
  silent install, screen overlay, microphone, camera, location);
* accessibility-service abuse — the single most abused Android permission, used
  by banking trojans to read the screen and click on the user's behalf;
* readable Android API descriptors in the DEX (Runtime.exec, SmsManager,
  DevicePolicyManager, DexClassLoader, device-identifier getters);
* the DEX and native-library inventory;
* URLs and IPs embedded in the DEX, lifted into IOCs and never contacted.

Every parse is wrapped, every read is bounded, and every sample-derived string
is truncated before it reaches a Signal — a malformed package is an
observation, not a crash, and a zip bomb or a 4 GB DEX is a denial of service.
"""
from __future__ import annotations

import re
import struct
import time
import zipfile
from typing import Any

from ..contracts import AnalyzerResult, IOCs, Sample, Severity, Signal

NAME = "apk"
FAMILY = "apk"

# --- bounds -------------------------------------------------------------------
# Every number here exists because the archive chose its own: a zip can claim a
# million entries, a manifest can declare a four-billion string pool, a DEX can
# decompress to gigabytes. The sample is hostile; nothing is read to the end.

MAX_ENTRIES = 4000                     # zip members enumerated
MAX_MANIFEST_BYTES = 8 * 1024 * 1024   # AndroidManifest.xml read cap
MAX_DEX_FILES = 12                     # classes*.dex actually scanned
MAX_DEX_BYTES = 4 * 1024 * 1024        # per-dex bytes scanned
MAX_NATIVE_LIBS = 200                  # .so entries recorded
MAX_STRINGS = 40000                    # AXML / dex strings kept
MIN_STRING_LEN = 4
MAX_STRING_LEN = 512
MAX_PERMISSIONS = 400                  # permissions recorded
MAX_IOCS_PER_KIND = 100
MAX_EVIDENCE_ITEMS = 20
STR_LIMIT = 200

EXCESSIVE_PERMISSION_COUNT = 24        # "this app wants everything"

# --- AXML constants -----------------------------------------------------------
# The binary XML format is a stream of typed chunks. We only need one of them —
# the string pool — because every readable token in the manifest (package name,
# permission names, component names) lives there.

_AXML_MAGIC = 0x00080003               # RES_XML_TYPE, headerSize 8
_RES_STRING_POOL_TYPE = 0x0001C        # note: 0x001C
_UTF8_FLAG = 0x00000100

# --- DEX API catalogue --------------------------------------------------------
# Plain substring matching on raw DEX bytes. DEX stores type descriptors and
# method names as MUTF-8, so the ASCII descriptors below appear verbatim in the
# byte stream. A match is *intent*, not proof — the string is present because a
# method reference to it was compiled in, which only execution would exercise.

# High-risk descriptors that, present, warrant apk.suspicious_api (high).
_DEX_SUSPICIOUS: tuple[tuple[bytes, str], ...] = (
    (b"Ljava/lang/Runtime;", "java.lang.Runtime (native command execution)"),
    (b"Ljava/lang/ProcessBuilder;", "java.lang.ProcessBuilder (native command execution)"),
    (b"Landroid/telephony/SmsManager;", "android.telephony.SmsManager (send/read SMS)"),
    (b"sendTextMessage", "SmsManager.sendTextMessage"),
    (b"getDeviceId", "TelephonyManager.getDeviceId (IMEI)"),
    (b"getSimSerialNumber", "TelephonyManager.getSimSerialNumber (ICCID)"),
    (b"Landroid/app/admin/DevicePolicyManager;", "DevicePolicyManager (device-admin control)"),
    (b"getInstalledPackages", "PackageManager.getInstalledPackages (app enumeration)"),
    (b"Landroid/accessibilityservice", "AccessibilityService (screen reading / auto-click)"),
)

# Dynamic-code loaders — their own signal, apk.dynamic_code (high).
_DEX_LOADERS: tuple[tuple[bytes, str], ...] = (
    (b"Ldalvik/system/DexClassLoader;", "DexClassLoader"),
    (b"Ldalvik/system/PathClassLoader;", "PathClassLoader"),
    (b"Ldalvik/system/InMemoryDexClassLoader;", "InMemoryDexClassLoader"),
)

# --- dangerous permission groups ----------------------------------------------
# Keyed on the trailing token of the permission name so both the android.* and
# any vendor-prefixed variant match. Each group present yields one
# apk.dangerous_permission (high) signal.

_DANGEROUS_GROUPS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("SMS", ("SEND_SMS", "RECEIVE_SMS", "READ_SMS", "WRITE_SMS", "RECEIVE_MMS"),
     "Read, send, or intercept text messages — used to steal 2FA codes and to "
     "subscribe the device to premium numbers."),
    ("Call log and contacts",
     ("READ_CALL_LOG", "WRITE_CALL_LOG", "READ_CONTACTS", "WRITE_CONTACTS",
      "PROCESS_OUTGOING_CALLS"),
     "Read the call history and address book — the raw material for spreading "
     "and for social-engineering the victim's contacts."),
    ("Boot persistence", ("RECEIVE_BOOT_COMPLETED",),
     "Start automatically on every reboot, so the payload survives a restart "
     "without the user ever launching it."),
    ("Silent install", ("REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES"),
     "Install further packages — the dropper capability, used to pull the real "
     "payload after the store-review-friendly stub is installed."),
    ("Screen overlay", ("SYSTEM_ALERT_WINDOW",),
     "Draw windows on top of every other app — the mechanism behind overlay "
     "phishing, where a fake login is painted over a real banking app."),
    ("Microphone", ("RECORD_AUDIO",),
     "Record audio from the microphone."),
    ("Camera", ("CAMERA",),
     "Capture photos and video from the camera."),
    ("Location", ("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION"),
     "Track the device's precise location."),
)
# Location alone is ordinary; it only becomes a finding alongside other
# dangerous capabilities (a flashlight app does not also need your SMS).
_LOCATION_GROUP = "Location"

# --- string / IOC extraction --------------------------------------------------

_RE_ASCII = re.compile(rb"[\x20-\x7e]{%d,%d}" % (MIN_STRING_LEN, MAX_STRING_LEN))
_RE_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,%d}" % (MIN_STRING_LEN, MAX_STRING_LEN))
_RE_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^\s\"'<>\\]{1,300}")
_RE_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_RE_DOMAIN = re.compile(
    r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,30})\.){1,6}[a-zA-Z]{2,24}(?![\w-])"
)
# A dotted token that looks like a Java/Android package identifier.
_RE_PACKAGE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){1,6}$")

# Package-name candidates whose leading segment names a framework namespace are
# not the app's own package.
_FRAMEWORK_PREFIXES = (
    "android.", "com.android.", "com.google.android.", "java.", "javax.",
    "org.xmlpull.", "org.w3c.", "org.json.", "kotlin.", "kotlinx.",
    "dalvik.", "org.apache.http.",
)


def _clip(text: str, limit: int = STR_LIMIT) -> str:
    text = text.replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "..."


# --- AXML string pool ---------------------------------------------------------


def _decode_len8(buf: bytes, off: int) -> tuple[int, int]:
    """UTF-8 length prefix: one byte, or two when the high bit is set."""
    v = buf[off]
    off += 1
    if v & 0x80:
        v = ((v & 0x7F) << 8) | buf[off]
        off += 1
    return v, off


def _decode_len16(buf: bytes, off: int) -> tuple[int, int]:
    """UTF-16 length prefix: one u16, or two when the high bit is set."""
    v = buf[off] | (buf[off + 1] << 8)
    off += 2
    if v & 0x8000:
        v = ((v & 0x7FFF) << 16) | (buf[off] | (buf[off + 1] << 8))
        off += 2
    return v, off


def _find_string_pool(data: bytes) -> int:
    """Offset of the RES_STRING_POOL chunk, or -1.

    In a well-formed AXML the pool follows the 8-byte file header, at offset 8.
    We check there first, then fall back to scanning for the chunk signature so
    a manifest with an unexpected preamble still parses.
    """
    if len(data) >= 10 and struct.unpack_from("<H", data, 8)[0] == _RES_STRING_POOL_TYPE:
        return 8
    # type (u16) 0x001C followed by headerSize (u16) 0x001C.
    sig = struct.pack("<HH", _RES_STRING_POOL_TYPE, 0x001C)
    idx = data.find(sig, 0, 1 << 20)
    return idx


def _parse_axml_strings(data: bytes) -> list[str]:
    """Recover the readable strings from a binary AndroidManifest string pool.

    Defensive throughout: any out-of-range offset or bad length aborts that one
    string (or the whole pool) rather than raising. Returns [] on total failure
    so the caller can fall back to a raw byte scan.
    """
    pool = _find_string_pool(data)
    if pool < 0 or pool + 28 > len(data):
        return []

    _type, _hsize, _size, string_count, _style_count, flags, strings_start, _styles_start = \
        struct.unpack_from("<HHIIIIII", data, pool)

    if string_count <= 0 or string_count > MAX_STRINGS:
        string_count = min(max(string_count, 0), MAX_STRINGS)
    is_utf8 = bool(flags & _UTF8_FLAG)

    offsets_at = pool + 28
    if offsets_at + string_count * 4 > len(data):
        string_count = max(0, (len(data) - offsets_at) // 4)
    data_base = pool + strings_start
    if data_base < 0 or data_base > len(data):
        return []

    out: list[str] = []
    for i in range(string_count):
        try:
            (rel,) = struct.unpack_from("<I", data, offsets_at + i * 4)
        except struct.error:
            break
        start = data_base + rel
        if start < 0 or start >= len(data):
            continue
        try:
            if is_utf8:
                # UTF-8: [u16 char count][u8 byte count][bytes][0x00]
                _chars, p = _decode_len8(data, start)
                nbytes, p = _decode_len8(data, p)
                if p + nbytes > len(data):
                    continue
                text = data[p:p + nbytes].decode("utf-8", "replace")
            else:
                # UTF-16LE: [u16 code-unit count][units][0x0000]
                nunits, p = _decode_len16(data, start)
                nbytes = nunits * 2
                if nbytes < 0 or p + nbytes > len(data):
                    continue
                text = data[p:p + nbytes].decode("utf-16-le", "replace")
        except (IndexError, struct.error):
            continue
        text = text.replace("\x00", "")
        if text:
            out.append(text[:MAX_STRING_LEN])
        if len(out) >= MAX_STRINGS:
            break
    return out


def _raw_string_scan(data: bytes) -> list[str]:
    """Fallback: readable ASCII and UTF-16LE runs from raw manifest bytes."""
    out: list[str] = []
    for m in _RE_ASCII.finditer(data):
        out.append(m.group().decode("ascii", "replace"))
        if len(out) >= MAX_STRINGS:
            return out
    for m in _RE_UTF16.finditer(data):
        out.append(m.group().decode("utf-16-le", "replace"))
        if len(out) >= MAX_STRINGS:
            break
    return out


# --- manifest interpretation --------------------------------------------------


def _permissions(strings: list[str]) -> list[str]:
    perms: dict[str, None] = {}
    for s in strings:
        if s.startswith("android.permission.") or s.startswith("com.android.") and ".permission." in s:
            perms.setdefault(s, None)
        elif ".permission." in s and s.count(" ") == 0 and len(s) < 128:
            perms.setdefault(s, None)
        if len(perms) >= MAX_PERMISSIONS:
            break
    return list(perms)


def _guess_package(strings: list[str], permissions: set[str]) -> str | None:
    """Best-effort package name: a dotted identifier that is not a framework
    namespace, not a permission, and not obviously a class path."""
    best: str | None = None
    for s in strings:
        if s in permissions or ".permission." in s:
            continue
        if not _RE_PACKAGE.match(s):
            continue
        if any(s.startswith(p) for p in _FRAMEWORK_PREFIXES):
            continue
        segments = s.split(".")
        if len(segments) < 2:
            continue
        # Prefer the shortest plausible package (2-4 segments); app packages are
        # rarely deep, class descriptors usually are.
        if best is None or len(segments) < len(best.split(".")):
            best = s
        if len(segments) in (2, 3):
            return s
    return best


def _permission_tail(perm: str) -> str:
    return perm.rsplit(".", 1)[-1].upper()


# --- DEX / IOC scanning -------------------------------------------------------


def _dex_strings(blob: bytes) -> list[str]:
    out: list[str] = []
    for m in _RE_ASCII.finditer(blob):
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
    if any(len(p) > 1 and p[0] == "0" for p in parts):
        return False
    if octets[0] in (0, 127) or octets == [255, 255, 255, 255]:
        return False
    return True


def _harvest_iocs(strings: list[str], tlds_ok: bool = False) -> IOCs:
    urls: dict[str, None] = {}
    ips: dict[str, None] = {}
    for text in strings:
        if len(urls) >= MAX_IOCS_PER_KIND and len(ips) >= MAX_IOCS_PER_KIND:
            break
        for m in _RE_URL.finditer(text):
            if len(urls) < MAX_IOCS_PER_KIND:
                urls.setdefault(_clip(m.group(), 300), None)
        for m in _RE_IP.finditer(text):
            value = m.group()
            if _valid_ip(value) and len(ips) < MAX_IOCS_PER_KIND:
                ips.setdefault(value, None)
    # Domains are taken from inside the URLs we already trust — extracting bare
    # domains from DEX byte soup produces too many invented indicators.
    domains: dict[str, None] = {}
    for url in urls:
        m = re.search(r"://([^/:?#\s]+)", url)
        if m:
            host = m.group(1).lower()
            if _RE_DOMAIN.match(host) and not _valid_ip(host):
                domains.setdefault(host, None)
    return IOCs(urls=list(urls), domains=list(domains), ips=list(ips))


# --- entry point --------------------------------------------------------------


def analyze(sample: Sample) -> AnalyzerResult:
    started = time.monotonic()

    def finish(result: AnalyzerResult) -> AnalyzerResult:
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    try:
        return finish(_analyze(sample))
    except zipfile.BadZipFile as exc:
        return finish(AnalyzerResult.unavailable(NAME, f"not a valid zip/APK: {_clip(str(exc), 120)}"))
    except Exception as exc:  # noqa: BLE001 — a hostile package must not crash the job
        return finish(AnalyzerResult.unavailable(NAME, f"{type(exc).__name__}: {_clip(str(exc), 120)}"))


def _analyze(sample: Sample) -> AnalyzerResult:
    signals: list[Signal] = []
    facts: dict[str, Any] = {}

    with zipfile.ZipFile(sample.path) as zf:
        infos = zf.infolist()[:MAX_ENTRIES]
        names = [i.filename for i in infos]

        dex_names = sorted(
            n for n in names
            if n.startswith("classes") and n.endswith(".dex") and "/" not in n
        )
        native_libs = sorted(
            n for n in names
            if n.startswith("lib/") and n.endswith(".so")
        )[:MAX_NATIVE_LIBS]

        facts["entry_count"] = len(infos)
        facts["dex_count"] = len(dex_names)
        facts["native_libs"] = native_libs
        facts["native_lib_count"] = len(native_libs)

        # --- manifest -> permissions, package ---------------------------------
        manifest_raw = b""
        if "AndroidManifest.xml" in names:
            try:
                with zf.open("AndroidManifest.xml") as fh:
                    manifest_raw = fh.read(MAX_MANIFEST_BYTES)
            except (zipfile.BadZipFile, OSError, RuntimeError):
                manifest_raw = b""

        manifest_strings: list[str] = []
        parse_mode = "none"
        if manifest_raw:
            if len(manifest_raw) >= 4 and struct.unpack_from("<I", manifest_raw, 0)[0] == _AXML_MAGIC:
                manifest_strings = _parse_axml_strings(manifest_raw)
                parse_mode = "axml"
            if not manifest_strings:
                manifest_strings = _raw_string_scan(manifest_raw)
                parse_mode = "raw-fallback" if parse_mode == "axml" else "raw"
        facts["manifest_present"] = bool(manifest_raw)
        facts["manifest_parse"] = parse_mode

        permissions = _permissions(manifest_strings)
        permission_set = set(permissions)
        package = _guess_package(manifest_strings, permission_set)

        facts["package"] = package
        facts["permissions"] = permissions[:MAX_EVIDENCE_ITEMS * 4]
        facts["permission_count"] = len(permissions)

        # --- dex scan ---------------------------------------------------------
        dex_apis: dict[str, None] = {}
        loaders: dict[str, None] = {}
        dex_ioc_strings: list[str] = []
        for dn in dex_names[:MAX_DEX_FILES]:
            try:
                with zf.open(dn) as fh:
                    blob = fh.read(MAX_DEX_BYTES)
            except (zipfile.BadZipFile, OSError, RuntimeError):
                continue
            for needle, label in _DEX_SUSPICIOUS:
                if needle in blob:
                    dex_apis.setdefault(label, None)
            for needle, label in _DEX_LOADERS:
                if needle in blob:
                    loaders.setdefault(label, None)
            if len(dex_ioc_strings) < MAX_STRINGS:
                dex_ioc_strings.extend(_dex_strings(blob))

        facts["dex_apis"] = list(dex_apis)
        iocs = _harvest_iocs(dex_ioc_strings)

    # --- signals: permissions -------------------------------------------------
    perm_tails = {_permission_tail(p) for p in permissions}
    matched_groups: list[str] = []
    for label, tails, _detail in _DANGEROUS_GROUPS:
        if any(t in perm_tails for t in tails):
            matched_groups.append(label)

    non_location = [g for g in matched_groups if g != _LOCATION_GROUP]
    for label, tails, detail in _DANGEROUS_GROUPS:
        if label not in matched_groups:
            continue
        if label == _LOCATION_GROUP and not non_location:
            continue  # location on its own is not a finding
        present = sorted(p for p in permissions if _permission_tail(p) in set(tails))
        signals.append(
            Signal(
                id="apk.dangerous_permission",
                title=f"Dangerous permission group requested: {label}",
                severity="high",
                detail=(
                    f"The app requests the {label} permission group. {detail} A "
                    "permission is a request, not proof of use — but it is the "
                    "ceiling on what the code is allowed to do."
                ),
                evidence={"group": label, "permissions": present[:MAX_EVIDENCE_ITEMS]},
            )
        )

    if "BIND_ACCESSIBILITY_SERVICE" in perm_tails:
        signals.append(
            Signal(
                id="apk.accessibility_abuse",
                title="Requests accessibility-service binding",
                severity="critical",
                detail=(
                    "The app requests BIND_ACCESSIBILITY_SERVICE. Accessibility "
                    "was built for users who need the screen read aloud and taps "
                    "performed for them — which is exactly what a banking trojan "
                    "needs to read on-screen credentials and click buttons on the "
                    "victim's behalf. It is the most abused permission on Android."
                ),
                evidence={
                    "permission": next(
                        (p for p in permissions if _permission_tail(p) == "BIND_ACCESSIBILITY_SERVICE"),
                        "BIND_ACCESSIBILITY_SERVICE",
                    )
                },
            )
        )

    if len(permissions) >= EXCESSIVE_PERMISSION_COUNT:
        signals.append(
            Signal(
                id="apk.excessive_permissions",
                title="Unusually large number of permissions",
                severity="medium",
                detail=(
                    f"The manifest declares {len(permissions)} permissions "
                    f"(threshold {EXCESSIVE_PERMISSION_COUNT}). A broad permission "
                    "surface is characteristic of spyware and of repackaged apps "
                    "that bolt capabilities onto a legitimate host."
                ),
                evidence={"permission_count": len(permissions),
                          "sample": permissions[:MAX_EVIDENCE_ITEMS]},
            )
        )

    # --- signals: dex APIs ----------------------------------------------------
    if dex_apis:
        signals.append(
            Signal(
                id="apk.suspicious_api",
                title="Sensitive Android APIs referenced in DEX",
                severity="high",
                detail=(
                    "The compiled bytecode references "
                    + ", ".join(sorted(dex_apis))
                    + ". These are the calls behind command execution, SMS "
                    "interception, device fingerprinting and device-admin "
                    "takeover. A reference is intent, not execution — but the "
                    "code was compiled to be able to reach them."
                ),
                evidence={"apis": sorted(dex_apis)[:MAX_EVIDENCE_ITEMS]},
            )
        )

    if loaders:
        signals.append(
            Signal(
                id="apk.dynamic_code",
                title="Loads code at runtime",
                severity="high",
                detail=(
                    "The bytecode references "
                    + ", ".join(sorted(loaders))
                    + ". Runtime class loading lets an app fetch and execute code "
                    "that is not in the scanned DEX at all — the standard way to "
                    "hide the real payload from static review and app-store "
                    "vetting."
                ),
                evidence={"loaders": sorted(loaders)},
            )
        )

    # --- signals: inventory ---------------------------------------------------
    if facts["dex_count"] > 1:
        signals.append(
            Signal(
                id="apk.multiple_dex",
                title="Multiple DEX files",
                severity="low",
                detail=(
                    f"The package contains {facts['dex_count']} DEX files. "
                    "Legitimate for large apps that exceed the 64K-method limit, "
                    "but also a common place to tuck a secondary payload apart "
                    "from the class that store review reads first."
                ),
                evidence={"dex_files": dex_names},
            )
        )

    if native_libs:
        signals.append(
            Signal(
                id="apk.native_libs",
                title="Bundled native libraries",
                severity="low",
                detail=(
                    f"The package ships {len(native_libs)} native "
                    ".so librar" + ("y" if len(native_libs) == 1 else "ies") +
                    ". Native code is normal for games and media apps, but it is "
                    "also where Android malware hides logic that DEX-level tools "
                    "do not read — packing, string decryption, and C2 addresses."
                ),
                evidence={"native_libs": native_libs[:MAX_EVIDENCE_ITEMS]},
            )
        )

    # --- signals: IOCs --------------------------------------------------------
    if iocs.total():
        signals.append(
            Signal(
                id="apk.embedded_url",
                title="Embedded URLs or IP addresses in DEX",
                severity="info",
                detail=(
                    f"Extracted {len(iocs.urls)} URL(s) and {len(iocs.ips)} IP "
                    "address(es) from the DEX strings. These are candidate "
                    "endpoints — extraction only; nothing here was contacted."
                ),
                evidence={
                    "urls": iocs.urls[:MAX_EVIDENCE_ITEMS],
                    "ips": iocs.ips[:MAX_EVIDENCE_ITEMS],
                },
            )
        )

    if not facts["manifest_present"]:
        signals.append(
            Signal(
                id="apk.no_manifest",
                title="No AndroidManifest.xml",
                severity="medium",
                detail=(
                    "The zip has no AndroidManifest.xml. A real APK cannot install "
                    "without one — this is either a malformed package or a zip "
                    "wearing an .apk extension."
                ),
                evidence={"entry_count": facts["entry_count"]},
            )
        )

    return AnalyzerResult(
        analyzer=NAME, ran=True, signals=signals, facts=facts, iocs=iocs
    )
