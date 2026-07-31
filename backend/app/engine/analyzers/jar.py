"""JAR (Java archive) static analysis.

A JAR is a ZIP with a manifest and a tree of ``.class`` files. This module reads
it exactly as data: it lists the archive with the standard library ``zipfile``,
reads ``META-INF/MANIFEST.MF`` as text, and hand-walks the constant pool of each
``.class`` to lift out the CONSTANT_Utf8 strings — the class names, method names
and string literals the bytecode refers to.

Nothing here loads a class, resolves a reference, or runs a byte of the sample.
The constant-pool walker is a bounds-checked byte reader, on purpose: a Java
class file is attacker-controlled input, and a malformed pool must degrade into a
short string list, never an exception or an unbounded read.

References: JVM specification, ClassFile structure and the constant_pool table
(CONSTANT_Utf8 tag 1; Long/Double each occupy two pool slots).
"""
from __future__ import annotations

import re
import struct
import time
import zipfile
from typing import Any

from ..contracts import AnalyzerResult, IOCs, Sample, Signal

NAME = "jar"
#: identify.py families this analyzer claims.
FAMILY = "jar"

# --- bounds -------------------------------------------------------------------
# Every limit here exists because the archive chose its own numbers: an entry can
# claim a 4 GB uncompressed size, a class can declare a constant_pool_count that
# runs off the end of the file, an obfuscated jar can hold a hundred thousand
# tiny classes.

MAX_ENTRIES_SCANNED = 5000             # namelist entries examined
MAX_CLASSES = 500                      # .class files parsed
MAX_CLASS_BYTES = 4 * 1024 * 1024      # per .class read cap
MAX_MANIFEST_BYTES = 256 * 1024
MAX_UTF8_PER_CLASS = 4000              # constant pool strings kept per class
MAX_TOTAL_STRINGS = 40000              # strings kept across all classes
MAX_HAYSTACK_BYTES = 8 * 1024 * 1024   # bound the detection text
MAX_STRING_LEN = 512
MAX_IOCS_PER_KIND = 50
MAX_EVIDENCE_ITEMS = 24
EVIDENCE_TRUNCATE = 200
MIN_CLASSES_FOR_OBFUSCATION = 8

_CLASS_MAGIC = b"\xca\xfe\xba\xbe"

# --- IOC extraction -----------------------------------------------------------
# Linear expressions run against already-bounded strings, mirroring elf.py.

_RE_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^\s\"'<>\\]{1,300}")
_RE_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

_NATIVE_SUFFIXES = (".so", ".dll", ".dylib")


def _clip(text: str, limit: int = EVIDENCE_TRUNCATE) -> str:
    text = text.replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "..."


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


# --- constant pool walker -----------------------------------------------------


def _constant_pool_utf8(blob: bytes) -> list[str]:
    """CONSTANT_Utf8 strings out of one class file's constant pool.

    Bounds-checked at every step. On the first malformed or out-of-range entry
    the walk stops and returns whatever was collected so far — a hostile class
    yields a short list, never an exception.
    """
    n = len(blob)
    if n < 10 or blob[:4] != _CLASS_MAGIC:
        return []
    # bytes 4..6 minor, 6..8 major, 8..10 constant_pool_count.
    count = struct.unpack_from(">H", blob, 8)[0]

    out: list[str] = []
    pos = 10
    index = 1
    while index < count:
        if pos >= n:
            break
        tag = blob[pos]
        pos += 1
        if tag == 1:  # CONSTANT_Utf8: u2 length, then that many bytes.
            if pos + 2 > n:
                break
            length = struct.unpack_from(">H", blob, pos)[0]
            pos += 2
            if pos + length > n:
                break
            if len(out) < MAX_UTF8_PER_CLASS:
                out.append(blob[pos:pos + length].decode("utf-8", "replace"))
            pos += length
            index += 1
        elif tag in (5, 6):  # Long / Double: u8, and consume TWO pool slots.
            pos += 8
            index += 2
        elif tag in (7, 8, 16, 19, 20):  # Class/String/MethodType/Module/Package: u2
            pos += 2
            index += 1
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):  # Int/Float/Refs/NameAndType/Dynamic: u4
            pos += 4
            index += 1
        elif tag == 15:  # MethodHandle: u1 reference_kind + u2 reference_index.
            pos += 3
            index += 1
        else:
            # Unknown tag: the pool is malformed. Stop rather than guess a size.
            break
    return out


# --- manifest -----------------------------------------------------------------


def _parse_manifest(text: str) -> dict[str, str]:
    """Main attributes out of MANIFEST.MF, honouring 72-byte continuation lines.

    A continuation line begins with a single space and appends to the previous
    value. Only the main section (up to the first blank line) is read.
    """
    attrs: dict[str, str] = {}
    key = ""
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if line == "":
            break  # end of main section
        if line.startswith(" ") and key:
            attrs[key] += line[1:]
            continue
        name, sep, value = line.partition(":")
        if sep:
            key = name.strip()
            attrs[key] = value.strip()
    return attrs


# --- detection helpers --------------------------------------------------------


def _harvest_iocs(haystack: str) -> IOCs:
    urls: dict[str, None] = {}
    ips: dict[str, None] = {}
    for m in _RE_URL.finditer(haystack):
        if len(urls) >= MAX_IOCS_PER_KIND:
            break
        urls.setdefault(_clip(m.group(), 300), None)
    for m in _RE_IP.finditer(haystack):
        if len(ips) >= MAX_IOCS_PER_KIND:
            break
        value = m.group()
        if _valid_ip(value):
            ips.setdefault(value, None)
    return IOCs(urls=list(urls), ips=list(ips))


# --- entry point --------------------------------------------------------------


def analyze(sample: Sample) -> AnalyzerResult:
    started = time.monotonic()

    def finish(result: AnalyzerResult) -> AnalyzerResult:
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    try:
        head = sample.read(4)
    except OSError as exc:
        return finish(
            AnalyzerResult.unavailable(NAME, f"sample unreadable: {type(exc).__name__}")
        )
    # Every ZIP local file header starts "PK". A jar that is not a zip is not ours.
    if not head.startswith(b"PK"):
        return finish(AnalyzerResult.not_applicable(NAME, sample.mime or "non-ZIP"))

    try:
        return finish(_analyze_zip(sample))
    except (zipfile.BadZipFile, OSError, EOFError, struct.error, ValueError) as exc:
        return finish(
            AnalyzerResult.unavailable(NAME, f"{type(exc).__name__}: {_clip(str(exc), 160)}")
        )


def _analyze_zip(sample: Sample) -> AnalyzerResult:
    signals: list[Signal] = []
    facts: dict[str, Any] = {}

    class_entries: list[str] = []
    native_libs: list[str] = []
    embedded_jars: list[str] = []
    manifest_text = ""

    with zipfile.ZipFile(sample.path) as zf:
        names = zf.namelist()[:MAX_ENTRIES_SCANNED]
        for name in names:
            low = name.lower()
            if low.endswith(".class"):
                class_entries.append(name)
            elif low.endswith(".jar"):
                embedded_jars.append(name)
            elif low.endswith(_NATIVE_SUFFIXES):
                native_libs.append(name)

        # Manifest is optional; a jar without one is unusual but not an error.
        for candidate in ("META-INF/MANIFEST.MF", "META-INF/manifest.mf"):
            if candidate in names:
                try:
                    with zf.open(candidate) as fh:
                        manifest_text = fh.read(MAX_MANIFEST_BYTES).decode(
                            "utf-8", "replace"
                        )
                    break
                except (KeyError, zipfile.BadZipFile, OSError):
                    manifest_text = ""

        # Constant-pool strings across a bounded number of classes.
        collected: list[str] = []
        parsed_classes = 0
        for entry in class_entries[:MAX_CLASSES]:
            try:
                info = zf.getinfo(entry)
            except KeyError:
                continue
            if info.file_size > MAX_CLASS_BYTES:
                continue  # decompression bomb guard
            try:
                with zf.open(entry) as fh:
                    blob = fh.read(MAX_CLASS_BYTES)
            except (zipfile.BadZipFile, OSError, EOFError):
                continue
            parsed_classes += 1
            for s in _constant_pool_utf8(blob):
                if len(s) <= MAX_STRING_LEN:
                    collected.append(s)
                if len(collected) >= MAX_TOTAL_STRINGS:
                    break
            if len(collected) >= MAX_TOTAL_STRINGS:
                break

    manifest = _parse_manifest(manifest_text) if manifest_text else {}
    main_class = manifest.get("Main-Class") or None
    class_path = manifest.get("Class-Path") or None

    # Single bounded detection text: substring search covers both exact class
    # descriptors ("java/lang/Runtime") and path prefixes ("java/lang/reflect").
    haystack = "\n".join(collected)
    if len(haystack) > MAX_HAYSTACK_BYTES:
        haystack = haystack[:MAX_HAYSTACK_BYTES]

    def has_all(*tokens: str) -> bool:
        return all(t in haystack for t in tokens)

    # The constant-pool entries as themselves, before they were joined.
    #
    # A substring test over the joined text cannot tell a method NAMED
    # `exec` from one named `execute`, and `Executor`/`ExecutorService` is
    # in essentially every server-side JAR. Membership in this set is the
    # difference between a reference to the method and a word that starts
    # the same way.
    pool = set(collected)

    def has_entry(*tokens: str) -> bool:
        return all(t in pool for t in tokens)

    def has_any(*tokens: str) -> bool:
        return any(t in haystack for t in tokens)

    facts["class_count"] = len(class_entries)
    facts["classes_parsed"] = parsed_classes
    facts["main_class"] = main_class
    facts["class_path"] = _clip(class_path) if class_path else None
    facts["has_manifest"] = bool(manifest_text)
    facts["embedded_jars"] = embedded_jars[:MAX_EVIDENCE_ITEMS]
    facts["native_libs"] = native_libs[:MAX_EVIDENCE_ITEMS]
    facts["strings_examined"] = len(collected)
    facts["strings_truncated"] = len(collected) >= MAX_TOTAL_STRINGS

    suspicious_classes: list[str] = []

    # --- Main-Class (info) ----------------------------------------------------
    if main_class:
        signals.append(
            Signal(
                id="jar.main_class",
                title="Executable entry point declared",
                severity="info",
                detail=(
                    f"The manifest names {main_class!r} as Main-Class, so the archive "
                    "is a runnable application, not a library. The entry point is the "
                    "first place to read when reversing what the jar does."
                ),
                evidence={"main_class": _clip(main_class), "class_path": facts["class_path"]},
            )
        )

    # --- Runtime.exec / ProcessBuilder (high) ---------------------------------
    # `has_entry`, not `has_all`: the second token has to BE the method
    # name. As a substring it matched `execute`, `Executor` and
    # `ExecutorService`, while `java/lang/Runtime` is present in any JAR
    # that calls `getRuntime().availableProcessors()` -- so the pair fired
    # `high` on ordinary software with a thread pool.
    if has_entry("java/lang/Runtime", "exec") or "java/lang/ProcessBuilder" in pool:
        matched = [
            t for t in ("java/lang/Runtime", "java/lang/ProcessBuilder")
            if t in haystack
        ]
        suspicious_classes.extend(matched)
        signals.append(
            Signal(
                id="jar.runtime_exec",
                title="Spawns external operating-system processes",
                severity="high",
                detail=(
                    "The bytecode references Runtime.exec or ProcessBuilder — the two "
                    "Java routes to launching a native command. Legitimate desktop apps "
                    "do this, but so does every dropper that shells out to the host, and "
                    "it is the single most direct path from a jar to command execution."
                ),
                evidence={"references": matched},
            )
        )

    # --- Class loading (high) -------------------------------------------------
    if has_any("java/net/URLClassLoader", "defineClass", "loadClass"):
        matched = [
            t for t in ("java/net/URLClassLoader", "defineClass", "loadClass")
            if t in haystack
        ]
        suspicious_classes.extend(matched)
        signals.append(
            Signal(
                id="jar.classloader",
                title="Loads classes at runtime",
                severity="high",
                detail=(
                    "References to URLClassLoader / defineClass / loadClass mean the jar "
                    "can pull and run code that is not in the archive on disk — from a "
                    "URL, a decrypted blob, or a downloaded payload. The bytes analysed "
                    "here are then not the bytes that ultimately execute."
                ),
                evidence={"references": matched},
            )
        )

    # --- Scripting engine (high) ----------------------------------------------
    if has_any("javax/script/ScriptEngine", "ScriptEngineManager"):
        matched = [
            t for t in ("javax/script/ScriptEngine", "ScriptEngineManager")
            if t in haystack
        ]
        suspicious_classes.extend(matched)
        signals.append(
            Signal(
                id="jar.script_engine",
                title="Embeds a scripting engine",
                severity="high",
                detail=(
                    "The jar uses javax.script (Nashorn/JavaScript or another JSR-223 "
                    "engine). Evaluating script text at runtime is arbitrary code "
                    "execution that never appears as Java bytecode, which is exactly why "
                    "loaders reach for it to stay off a static analyst's radar."
                ),
                evidence={"references": matched},
            )
        )

    # --- Reflection (medium) --------------------------------------------------
    if has_any("java/lang/reflect", "setAccessible", "getDeclaredMethod"):
        matched = [
            t for t in ("java/lang/reflect", "setAccessible", "getDeclaredMethod")
            if t in haystack
        ]
        suspicious_classes.extend(matched)
        signals.append(
            Signal(
                id="jar.reflection",
                title="Uses reflection to reach hidden members",
                severity="medium",
                detail=(
                    "Reflection APIs (setAccessible / getDeclaredMethod) let the code "
                    "call methods and touch fields the compiler would forbid. It is "
                    "common in frameworks, and equally common as the glue that invokes "
                    "a dynamically loaded or obfuscated payload by name."
                ),
                evidence={"references": matched},
            )
        )

    # --- Native code (medium) -------------------------------------------------
    uses_native_api = has_any("loadLibrary", "System.load")
    if native_libs or uses_native_api:
        suspicious_classes.extend(
            t for t in ("loadLibrary", "System.load") if t in haystack
        )
        detail_bits = []
        if native_libs:
            detail_bits.append(
                f"the archive bundles {len(native_libs)} native library file(s)"
            )
        if uses_native_api:
            detail_bits.append("the bytecode calls System.load / loadLibrary")
        signals.append(
            Signal(
                id="jar.native_libs",
                title="Carries or loads native code",
                severity="medium",
                detail=(
                    "This jar reaches outside the JVM sandbox: "
                    + " and ".join(detail_bits)
                    + ". Native libraries run as ordinary machine code with none of the "
                    "JVM's guarantees, and are a standard way to hide the real payload "
                    "from Java-level analysis."
                ),
                evidence={"native_libs": native_libs[:MAX_EVIDENCE_ITEMS]},
            )
        )

    # --- Nested jars (low) ----------------------------------------------------
    if embedded_jars:
        signals.append(
            Signal(
                id="jar.embedded_jar",
                title="Contains nested Java archives",
                severity="low",
                detail=(
                    f"The archive holds {len(embedded_jars)} nested .jar file(s). "
                    "Fat/uber jars do this legitimately, but nesting is also how a "
                    "second-stage payload is smuggled past a scanner that only looks at "
                    "the outer archive's classes."
                ),
                evidence={"embedded_jars": embedded_jars[:MAX_EVIDENCE_ITEMS]},
            )
        )

    # --- Obfuscation (low) ----------------------------------------------------
    basenames = [
        e.rsplit("/", 1)[-1][:-len(".class")]
        for e in class_entries
        if e.lower().endswith(".class")
    ]
    short = sum(1 for b in basenames if 1 <= len(b) <= 2)
    fraction = short / len(basenames) if basenames else 0.0
    facts["short_class_name_fraction"] = round(fraction, 3)
    if len(basenames) >= MIN_CLASSES_FOR_OBFUSCATION and fraction >= 0.5:
        signals.append(
            Signal(
                id="jar.obfuscated",
                title="Class names look obfuscated",
                severity="low",
                detail=(
                    f"{short} of {len(basenames)} class names are one or two characters "
                    f"({round(fraction * 100)}%). Name manglers such as ProGuard rename "
                    "classes to 'a', 'b', 'aa' to shrink and confuse; the same output is "
                    "produced deliberately to frustrate reverse engineering."
                ),
                evidence={
                    "short_names": short,
                    "total_names": len(basenames),
                    "fraction": round(fraction, 3),
                },
            )
        )

    # De-duplicate while preserving order.
    facts["suspicious_classes"] = list(dict.fromkeys(suspicious_classes))

    return AnalyzerResult(
        analyzer=NAME,
        ran=True,
        signals=signals,
        facts=facts,
        iocs=_harvest_iocs(haystack),
    )
