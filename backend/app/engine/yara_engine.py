"""The YARA tier of Cyclowareness Sandbox static analysis.

YARA is a signature engine: it matches byte patterns, it never runs the sample.
This module is the thin, defensive shell around it. Its job is threefold:

1. **Compile once, cache, and survive a bad rule file.** Every ``*.yar`` in the
   sibling ``rules/`` directory is compiled at import time, each file on its own
   so that one file with a syntax error is reported as an engine-level gap
   rather than taking every other rule down with it. The compiled result is
   cached for the life of the process.
2. **Scan with a hard timeout.** A rule set run against a hostile sample is a
   denial-of-service surface; the scan is bounded in wall-clock time and every
   sample-derived string is truncated before it reaches a Signal.
3. **Tell the truth about coverage.** ``rules_loaded()`` states exactly how many
   rules are active and which files failed, and when ``yara-python`` is not
   installed the analyzer returns ``AnalyzerResult.unavailable`` — it never
   returns an empty clean result for a scan that did not happen.

Severity lives with the rule, not here: each rule declares ``severity`` in its
``meta:`` block and this module reads it, defaulting to ``medium`` when absent.
So does the human wording — the Signal title and detail come from the rule's
``meta:`` ``description``.
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

from .contracts import SEVERITY_ORDER, AnalyzerResult, Sample, Severity, Signal

logger = logging.getLogger("sandbox.yara")

ANALYZER = "yara"
NAME = "yara"

#: Directory holding the rule pack. Sibling of this module.
RULES_DIR = Path(__file__).resolve().parent / "rules"

#: Wall-clock ceiling for a single sample scan, per rule file. YARA enforces
#: this internally and raises TimeoutError past it.
SCAN_TIMEOUT_SECONDS = 30

#: Never scan more than this many bytes. Samples are already capped at 32 MB by
#: storage, but the tier states its own bound so the guarantee is local.
MAX_SCAN_BYTES = 32 * 1024 * 1024

#: Sample-derived text (matched string bytes) is truncated to this before it is
#: put in a Signal's evidence.
SNIPPET_BYTES = 120

#: Per rule, at most this many matched-string instances are reported. A rule can
#: match thousands of times in a large file; the report needs a sample, not all.
MAX_MATCH_INSTANCES = 12

#: At most this many distinct rule matches become Signals. Beyond this the count
#: is reported but individual Signals are not emitted.
MAX_SIGNALS = 100

_VALID_SEVERITIES = frozenset(SEVERITY_ORDER)


# --- import-time compilation --------------------------------------------------
# All state below is populated exactly once by ``_load()`` and then cached.

_YARA_AVAILABLE: bool = False
_YARA_IMPORT_ERROR: str | None = None
#: file basename -> compiled yara.Rules
_COMPILED: dict[str, Any] = {}
#: file basename -> compile error string
_FAILED: dict[str, str] = {}
#: file basename -> number of rules compiled from it
_RULE_COUNTS: dict[str, int] = {}
_LOADED: bool = False


def _load() -> None:
    """Compile every rule file once. Idempotent; safe to call repeatedly."""
    global _YARA_AVAILABLE, _YARA_IMPORT_ERROR, _LOADED
    if _LOADED:
        return
    _LOADED = True

    try:
        import yara  # noqa: F401
    except Exception as exc:  # noqa: BLE001 — missing native dep is a stated gap
        _YARA_AVAILABLE = False
        _YARA_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
        logger.warning("yara-python not importable: %s", _YARA_IMPORT_ERROR)
        return

    _YARA_AVAILABLE = True

    if not RULES_DIR.is_dir():
        _FAILED["<rules-dir>"] = f"rules directory not found: {RULES_DIR}"
        logger.warning("yara rules directory missing: %s", RULES_DIR)
        return

    for path in sorted(RULES_DIR.glob("*.yar")):
        name = path.name
        try:
            compiled = yara.compile(filepath=str(path))
            _COMPILED[name] = compiled
            # Compiled Rules objects are iterable over their rules.
            try:
                _RULE_COUNTS[name] = sum(1 for _ in compiled)
            except Exception:  # noqa: BLE001
                _RULE_COUNTS[name] = 0
        except Exception as exc:  # noqa: BLE001 — a bad rule file is an engine gap
            _FAILED[name] = f"{type(exc).__name__}: {exc}"[:300]
            logger.warning("yara rule file %s failed to compile: %s", name, exc)

    if not _COMPILED and not _FAILED:
        _FAILED["<rules-dir>"] = f"no .yar files found in {RULES_DIR}"


def rules_loaded() -> dict[str, Any]:
    """How many rules are actually active, and what failed to load.

    The UI states coverage from this: an engine claiming to protect with rules
    it could not compile is exactly the "we did not look but say we did" failure
    the whole contract exists to prevent.
    """
    _load()
    return {
        "available": _YARA_AVAILABLE,
        "import_error": _YARA_IMPORT_ERROR,
        "rules_dir": str(RULES_DIR),
        "files_loaded": len(_COMPILED),
        "rules_active": sum(_RULE_COUNTS.values()),
        "rules_per_file": dict(_RULE_COUNTS),
        "failed_files": dict(_FAILED),
    }


# --- scanning -----------------------------------------------------------------


def _severity_of(meta: dict[str, Any]) -> Severity:
    raw = meta.get("severity")
    if isinstance(raw, str) and raw.lower() in _VALID_SEVERITIES:
        return raw.lower()  # type: ignore[return-value]
    return "medium"


def _snippet(data: bytes) -> str:
    """A matched-string preview: truncated, and printable so a log line is safe."""
    chunk = data[:SNIPPET_BYTES]
    text = chunk.decode("utf-8", "replace")
    # Neutralise control characters so the snippet cannot corrupt a terminal or
    # log line; the sample authored these bytes and is hostile.
    text = "".join(c if 32 <= ord(c) < 127 else "." for c in text)
    if len(data) > SNIPPET_BYTES:
        text += "…"
    return text


def _match_evidence(match: Any) -> dict[str, Any]:
    """Turn a yara.Match into bounded, sanitised evidence."""
    instances: list[dict[str, Any]] = []
    seen = 0
    # yara-python 4.3+ exposes match.strings as StringMatch objects each with a
    # list of instances; older shapes are (offset, identifier, data) tuples.
    for sm in getattr(match, "strings", []) or []:
        if seen >= MAX_MATCH_INSTANCES:
            break
        try:
            identifier = getattr(sm, "identifier", None)
            sm_instances = getattr(sm, "instances", None)
            if identifier is not None and sm_instances is not None:
                for inst in sm_instances:
                    if seen >= MAX_MATCH_INSTANCES:
                        break
                    instances.append(
                        {
                            "id": str(identifier)[:64],
                            "offset": int(getattr(inst, "offset", -1)),
                            "data": _snippet(bytes(getattr(inst, "matched_data", b"") or b"")),
                        }
                    )
                    seen += 1
            else:
                # Legacy tuple form: (offset, identifier, data)
                offset, ident, data = sm
                instances.append(
                    {
                        "id": str(ident)[:64],
                        "offset": int(offset),
                        "data": _snippet(bytes(data or b"")),
                    }
                )
                seen += 1
        except Exception:  # noqa: BLE001 — never let evidence shaping crash a scan
            continue

    ev: dict[str, Any] = {
        "namespace": str(getattr(match, "namespace", ""))[:64],
        "matched_strings": instances,
    }
    tags = list(getattr(match, "tags", []) or [])
    if tags:
        ev["tags"] = [str(t)[:32] for t in tags[:16]]
    return ev


#: Rules whose whole finding is "this file contains an executable". True of
#: every installer package by construction.
_CONTAINER_RULES = frozenset({"yara.embedded_pe_in_nonpe", "yara.embedded_executable"})

#: The formats that carry programs as their purpose. Same list as
#: `generic._EMBED_EXEMPT_EXTENSIONS`, plus the app-package containers.
_CONTAINER_EXTENSIONS = frozenset({
    ".msi", ".msp", ".msm", ".msix", ".msixbundle", ".appx", ".appxbundle",
    # Disk images are distribution media. An ISO is how operating systems,
    # installers and Linux distributions are shipped; every one of them carries
    # programs, because that is the entire point of the format.
    ".iso", ".img", ".dmg", ".vhd", ".vhdx", ".vmdk", ".udf",
})


def _carries_executables(sample: Sample) -> bool:
    return (sample.claimed_extension or "").lower() in _CONTAINER_EXTENSIONS


def analyze(sample: Sample) -> AnalyzerResult:
    """Scan the sample against every compiled rule file and map matches to Signals.

    Runs on every family — YARA does not care what identify.py decided the file
    is, and an embedded-PE or LOLBin rule firing on a "text" file is precisely
    the kind of contradiction worth surfacing.
    """
    started = time.perf_counter()
    _load()

    if not _YARA_AVAILABLE:
        return AnalyzerResult.unavailable(
            ANALYZER, f"yara-python not installed ({_YARA_IMPORT_ERROR})"
        )

    import yara

    if not _COMPILED:
        # We have the engine but no usable rules — that is unavailability, not a
        # clean sample. Say so, and carry the failing files as the reason.
        reason = "no YARA rules compiled successfully"
        if _FAILED:
            reason += f"; failures: {', '.join(sorted(_FAILED))}"
        return AnalyzerResult.unavailable(ANALYZER, reason[:300])

    # Size guard. Reading (not executing) a quarantined file is safe; we bound it
    # anyway so the tier's cost is independent of storage's cap.
    try:
        size = os.path.getsize(sample.path)
    except OSError as exc:
        return AnalyzerResult.unavailable(ANALYZER, f"sample unreadable: {exc}")
    truncated = size > MAX_SCAN_BYTES

    signals: list[Signal] = []
    scan_errors: dict[str, str] = {}
    matched_rules: list[str] = []

    for file_name, rules in _COMPILED.items():
        try:
            if truncated:
                with open(sample.path, "rb") as fh:
                    data = fh.read(MAX_SCAN_BYTES)
                matches = rules.match(data=data, timeout=SCAN_TIMEOUT_SECONDS)
            else:
                matches = rules.match(filepath=sample.path, timeout=SCAN_TIMEOUT_SECONDS)
        except yara.TimeoutError:
            scan_errors[file_name] = f"scan exceeded {SCAN_TIMEOUT_SECONDS}s timeout"
            logger.warning("yara scan of %s timed out on %s", file_name, sample.sha256[:12])
            continue
        except Exception as exc:  # noqa: BLE001 — a hostile sample tripped the scanner
            scan_errors[file_name] = f"{type(exc).__name__}: {exc}"[:200]
            logger.warning("yara scan of %s raised on %s: %s", file_name, sample.sha256[:12], exc)
            continue

        for match in matches:
            rule_name = str(getattr(match, "rule", "unknown"))
            matched_rules.append(rule_name)
            if len(signals) >= MAX_SIGNALS:
                continue
            meta = dict(getattr(match, "meta", {}) or {})
            severity = _severity_of(meta)
            description = str(meta.get("description", "") or "").strip()[:200]
            reference = str(meta.get("reference", "") or "").strip()[:200]
            evidence = _match_evidence(match)
            evidence["rule_file"] = file_name
            if reference:
                evidence["reference"] = reference
            signal_id = f"yara.{rule_name.lower()}"
            if signal_id in _CONTAINER_RULES and _carries_executables(sample):
                # An installer package carries executables — that is what it is
                # for. `generic.embedded_executable` was exempted for exactly
                # this in a297d63; the YARA rule that finds the same bytes was
                # not, so the GitHub CLI's and PuTTY's official MSIs were still
                # `Office.Downloader.EmbeddedPeInNonpe` at high severity.
                #
                # Keyed on the EXTENSION, not the mime: an MSI is an OLE
                # document, the same mime as a `.doc`, and a `.doc` carrying a
                # PE genuinely is a dropper.
                severity = "low"
            signals.append(
                Signal(
                    id=signal_id,
                    title=description or f"YARA rule {rule_name} matched",
                    severity=severity,
                    detail=(
                        f"Rule '{rule_name}' (from {file_name}) matched this sample."
                        + (f" {description}" if description else "")
                    ),
                    evidence=evidence,
                )
            )

    if len(matched_rules) > MAX_SIGNALS:
        signals.append(
            Signal(
                id="yara.match_cap_reached",
                title="More YARA matches than the report cap",
                severity="info",
                detail=(
                    f"{len(matched_rules)} rule matches occurred; the first {MAX_SIGNALS} are "
                    "shown individually and the rest are summarised only."
                ),
            )
        )

    signals.sort(key=lambda s: -SEVERITY_ORDER.get(s.severity, 0))

    facts: dict[str, Any] = {
        "rules_active": sum(_RULE_COUNTS.values()),
        "files_scanned": len(_COMPILED),
        "matched_rules": sorted(set(matched_rules))[:MAX_SIGNALS],
        "match_count": len(matched_rules),
        "scan_truncated": truncated,
        "scan_bytes": min(size, MAX_SCAN_BYTES),
    }
    if _FAILED:
        # Rule files that never compiled are an engine-level gap that belongs in
        # every report, not just in rules_loaded().
        facts["rule_files_failed_to_compile"] = dict(_FAILED)
    if scan_errors:
        facts["scan_errors"] = scan_errors

    result = AnalyzerResult(
        analyzer=ANALYZER,
        ran=True,
        signals=signals,
        facts=facts,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    return result


# Compile at import so the first scan pays no penalty and rules_loaded() is
# answerable immediately. A failure here is recorded, never raised.
_load()
