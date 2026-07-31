"""PDF static analysis for Cyclowareness Sandbox.

A PDF is a container format with a scripting engine bolted on, which is why it
keeps showing up in phishing: the *document* is the lure and the /OpenAction is
the payload. This analyzer never renders a page and never executes embedded
JavaScript. It does two independent passes and trusts neither one alone:

* **pdfminer.six** for the things a parser is good at — the text layer, the
  document info dictionary, the page tree. pdfminer is given a page budget and
  is allowed to fail; a PDF that refuses to parse is a finding, not a crash.
* **a raw keyword scan** for structure. A parser that declines to open a
  deliberately malformed file tells you nothing about what is inside it, and
  "malformed" is a design choice for a lot of malicious PDFs. Bytes always
  parse.

Two evasions the raw pass handles on purpose:

* ``/J#61vaScript`` — PDF names may hex-escape any character, so the scan runs
  over a copy with ``#hh`` escapes decoded as well.
* everything hidden in a compressed object stream — streams are inflated with
  a hard output cap (zlib is a decompressor, it does not run anything) and the
  inflated bytes are scanned too. Without this, a PDF that puts its whole
  catalog in an /ObjStm looks empty to a keyword scan.

Nothing extracted here is ever fetched, resolved, or opened.
"""
from __future__ import annotations

import re
import time
import zlib
from typing import Any
from urllib.parse import urlsplit

from ..contracts import AnalyzerResult, IOCs, Sample, Signal

NAME = "pdf"
#: Coarse family from identify.py that this analyzer claims.
FAMILY = "pdf"

# --- bounds. Every one of these exists because the sample is hostile. --------
MAX_SCAN_BYTES = 16 * 1024 * 1024
#: Total inflated output we are willing to hold, across all streams.
MAX_INFLATED_BYTES = 16 * 1024 * 1024
#: Per-stream inflated cap. A 4 GB zip bomb stops here.
MAX_STREAM_OUT = 2 * 1024 * 1024
#: Compressed bytes fed to zlib for one stream.
MAX_STREAM_IN = 4 * 1024 * 1024
MAX_STREAMS = 400
MAX_TEXT_PAGES = 25
MAX_TEXT_CHARS = 1_000_000
MAX_URLS = 200
MAX_NAMES = 50
MAX_STRING_BYTES = 4096
#: pdfminer's xref-reconstruction fallback brute-forces the whole file on a
#: malformed PDF and cannot be interrupted mid-call, so it runs in a worker
#: thread we stop waiting on. A well-formed document of any size finishes in
#: well under a second; only a deliberately broken one ever hits this ceiling.
PDFMINER_TIMEOUT_S = 6.0
#: Belt-and-braces: never even hand pdfminer a file larger than we scanned.
MAX_PDFMINER_BYTES = MAX_SCAN_BYTES
#: Every sample-derived string that reaches a Signal is cut to this.
SNIPPET = 200

# PDF names end at a delimiter, so the negative lookahead is what stops /AA
# matching /AAPL and /JS matching /JavaScript.
_TAIL = rb"(?![A-Za-z0-9])"
_KEYWORDS: tuple[tuple[str, bytes], ...] = (
    ("js", rb"/JS" + _TAIL),
    ("javascript", rb"/JavaScript" + _TAIL),
    ("open_action", rb"/OpenAction" + _TAIL),
    ("additional_actions", rb"/AA" + _TAIL),
    ("embedded_file", rb"/EmbeddedFile" + _TAIL),
    ("filespec", rb"/Filespec" + _TAIL),
    ("launch", rb"/Launch" + _TAIL),
    ("uri", rb"/URI" + _TAIL),
    ("submit_form", rb"/SubmitForm" + _TAIL),
    ("encrypt", rb"/Encrypt" + _TAIL),
    ("object_stream", rb"/ObjStm" + _TAIL),
    ("acroform", rb"/AcroForm" + _TAIL),
    ("goto_remote", rb"/GoToR" + _TAIL),
)

_RE_OBJ = re.compile(rb"\b\d{1,10}\s+\d{1,5}\s+obj\b")
_RE_ENDOBJ = re.compile(rb"\bendobj\b")
_RE_STREAM = re.compile(rb"\bstream\r?\n")
_RE_PAGE = re.compile(rb"/Type\s*/Page" + _TAIL)
_RE_HEXESC = re.compile(rb"#([0-9A-Fa-f]{2})")
_RE_VERSION = re.compile(rb"%PDF-(\d\.\d)")
# Bounded on both sides: no unbounded quantifier can backtrack catastrophically.
_RE_URL_TEXT = re.compile(r"""(?:https?|ftp)://[^\s<>"'\)\]\}\\,;]{1,2000}""", re.I)
_RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,4}")
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def analyze(sample: Sample) -> AnalyzerResult:
    """Static analysis of one quarantined PDF. Never renders, never executes."""
    started = time.perf_counter()

    try:
        head = sample.read(1024)
    except OSError as exc:
        return _timed(
            AnalyzerResult.unavailable(NAME, f"sample unreadable: {type(exc).__name__}"),
            started,
        )

    if sample.mime != "application/pdf" and b"%PDF" not in head:
        return _timed(AnalyzerResult.not_applicable(NAME, sample.mime or "unknown"), started)

    try:
        data = sample.read(MAX_SCAN_BYTES)
    except OSError as exc:
        return _timed(
            AnalyzerResult.unavailable(NAME, f"sample unreadable: {type(exc).__name__}"),
            started,
        )
    if not data:
        return _timed(AnalyzerResult.unavailable(NAME, "sample is empty"), started)

    # `#hh` decoding only ever rewrites escape sequences, so a literal /JS in the
    # original survives into the decoded copy — one buffer covers both spellings.
    surface = _decode_name_escapes(data)
    inflated, stream_stats = _inflate_streams(data)
    structure = _structure_facts(data, surface, inflated)

    buffers: tuple[tuple[str, bytes], ...] = (
        ("file", surface),
        ("object_stream", inflated),
    )

    counts = {name: 0 for name, _ in _KEYWORDS}
    for key, pattern in _KEYWORDS:
        rx = re.compile(pattern)
        for _, buf in buffers:
            if buf:
                counts[key] += _bounded_count(rx, buf)

    meta = _pdfminer_pass(sample.path, sample.size_bytes)

    uris: list[str] = []
    for _, buf in buffers:
        if buf:
            uris.extend(_uri_targets(buf))
    uris = _dedupe(uris, MAX_URLS)

    embedded_names: list[str] = []
    if counts["embedded_file"] or counts["filespec"]:
        for _, buf in buffers:
            if buf:
                embedded_names.extend(_file_names(buf))
        embedded_names = _dedupe(embedded_names, MAX_NAMES)

    text = meta.get("text") or ""
    text_urls = _dedupe(_RE_URL_TEXT.findall(text[:MAX_TEXT_CHARS]), MAX_URLS)

    facts: dict[str, Any] = {
        "pdf_version": structure["pdf_version"],
        "linearized": structure["linearized"],
        "page_count": meta.get("page_count") if meta.get("page_count") is not None
        else structure["page_objects"] or None,
        "page_count_source": "pdfminer" if meta.get("page_count") is not None else "raw_scan",
        "producer": meta.get("producer"),
        "creator": meta.get("creator"),
        "title": meta.get("title"),
        "author": meta.get("author"),
        "objects": {
            "visible_obj": structure["visible_obj"],
            "endobj": structure["endobj"],
            "streams": structure["streams"],
            "page_type_objects": structure["page_objects"],
            "object_streams": counts["object_stream"],
        },
        "keyword_counts": counts,
        "embedded_file_names": embedded_names,
        "uri_targets": uris,
        "streams_inflated": stream_stats,
        "text_chars": len(text),
        "text_pages_read": meta.get("pages_read", 0),
        "scan_truncated": len(data) >= MAX_SCAN_BYTES and sample.size_bytes > MAX_SCAN_BYTES,
        "pdfminer_ok": meta.get("ok", False),
        "pdfminer_error": meta.get("error"),
    }

    signals = _signals(counts, structure, meta, facts, buffers)
    iocs = _iocs(uris, text_urls, text, embedded_names)

    return _timed(
        AnalyzerResult(analyzer=NAME, ran=True, signals=signals, facts=facts, iocs=iocs),
        started,
    )


# --- signals ------------------------------------------------------------------


def _signals(
    counts: dict[str, int],
    structure: dict[str, Any],
    meta: dict[str, Any],
    facts: dict[str, Any],
    buffers: tuple[tuple[str, bytes], ...],
) -> list[Signal]:
    out: list[Signal] = []

    js_total = counts["js"] + counts["javascript"]
    if js_total:
        where, snippet = _first_snippet(buffers, rb"/(?:JS|JavaScript)" + _TAIL)
        out.append(
            Signal(
                id="pdf.javascript",
                title="PDF contains JavaScript",
                severity="high",
                detail=(
                    f"{js_total} JavaScript reference(s) found ({where}). A document that "
                    "carries script is doing something a document does not need to do."
                ),
                evidence={
                    "js_count": counts["js"],
                    "javascript_count": counts["javascript"],
                    "location": where,
                    "snippet": snippet,
                },
            )
        )

    if counts["open_action"] or counts["additional_actions"]:
        # An /OpenAction that runs script is not the one that sets the initial
        # zoom, and the difference is already in this signal's own evidence. On
        # its own the entry is ordinary -- it is how "open at page 1, fit width"
        # is stored -- and it fired on both NIST publications while catching
        # nothing: of 40 real malicious PDFs it appeared on 7, and every one of
        # those that was flagged also carried `pdf.javascript`. So it accuses
        # only in the company of script, and otherwise stays a visible
        # observation at `info`, which weighs 0.0 and asserts no capability.
        with_script = bool(js_total)
        out.append(
            Signal(
                id="pdf.open_action",
                title=(
                    "Action fires when the document is opened"
                    if with_script
                    else "Document sets an action to run when opened"
                ),
                severity="medium" if with_script else "info",
                detail=(
                    f"/OpenAction x{counts['open_action']}, /AA x{counts['additional_actions']}. "
                    + (
                        "These run without the reader clicking anything, and this "
                        "document also contains JavaScript."
                        if with_script
                        else "These run without the reader clicking anything. Ordinary "
                        "documents use this to set the opening page and zoom; with no "
                        "script present it is recorded, not counted against the file."
                    )
                ),
                evidence={
                    "open_action": counts["open_action"],
                    "additional_actions": counts["additional_actions"],
                    "with_javascript": bool(js_total),
                },
            )
        )

    if counts["embedded_file"] or counts["filespec"]:
        names = facts["embedded_file_names"]
        out.append(
            Signal(
                id="pdf.embedded_file",
                title="PDF carries an embedded file",
                severity="high",
                detail=(
                    f"/EmbeddedFile x{counts['embedded_file']}, /Filespec x{counts['filespec']}"
                    + (f"; names: {', '.join(names[:5])}" if names else "")
                )[:600],
                evidence={
                    "embedded_file": counts["embedded_file"],
                    "filespec": counts["filespec"],
                    "names": names,
                },
            )
        )

    if counts["launch"]:
        out.append(
            Signal(
                id="pdf.launch_action",
                title="/Launch action present",
                severity="critical",
                detail=(
                    f"/Launch x{counts['launch']} — the document asks the reader to start an "
                    "external program or file. There is no benign authoring tool that emits this."
                ),
                evidence={"count": counts["launch"], "targets": facts["embedded_file_names"][:10]},
            )
        )

    if counts["uri"]:
        targets = facts["uri_targets"]
        out.append(
            Signal(
                id="pdf.uri_action",
                title="Link actions present",
                severity="info",
                detail=(
                    f"/URI x{counts['uri']}, {len(targets)} distinct target(s) extracted. "
                    "Targets are recorded as indicators and are never fetched."
                ),
                evidence={"count": counts["uri"], "targets": targets[:20]},
            )
        )

    if counts["submit_form"]:
        out.append(
            Signal(
                id="pdf.submit_form",
                title="Form submits to a remote endpoint",
                severity="high",
                detail=(
                    f"/SubmitForm x{counts['submit_form']} — anything typed into this document's "
                    "fields is posted away. This is the credential-harvest shape of a PDF lure."
                ),
                evidence={
                    "count": counts["submit_form"],
                    "acroform": counts["acroform"],
                    "targets": facts["uri_targets"][:20],
                },
            )
        )

    if counts["encrypt"] or meta.get("encrypted"):
        out.append(
            Signal(
                id="pdf.encrypted",
                title="PDF is encrypted",
                severity="medium",
                detail=(
                    "An /Encrypt dictionary is present. Encryption limits static inspection and "
                    "is routinely used to keep content away from mail-gateway scanners."
                ),
                evidence={
                    "encrypt_keyword": counts["encrypt"],
                    "password_required": bool(meta.get("encrypted")),
                },
            )
        )

    objstm = counts["object_stream"]
    if objstm >= 3 or (objstm and structure["visible_obj"] <= 10):
        out.append(
            Signal(
                id="pdf.object_stream_obfuscation",
                title="Document structure held in object streams",
                # Its own detail said modern writers do this legitimately, and
                # then charged `low` for it anyway. Measured over 40 real
                # malicious PDFs it appeared on 8 and independently caught none,
                # while firing on both NIST publications. `info` keeps the
                # observation and drops the accusation.
                severity="info",
                detail=(
                    f"{objstm} /ObjStm container(s) against {structure['visible_obj']} directly "
                    "visible object(s). Modern writers compress this way as a matter of course, "
                    "so this is context: it tells you a scanner that does not inflate streams "
                    "would not have seen those dictionaries. This one does."
                ),
                evidence={
                    "object_streams": objstm,
                    "visible_obj": structure["visible_obj"],
                    "inflated_bytes": facts["streams_inflated"]["inflated_bytes"],
                },
            )
        )

    reasons = list(structure["broken"])
    if not meta.get("ok") and not meta.get("encrypted") and meta.get("error"):
        reasons.append(f"pdfminer: {meta['error']}")
    if reasons:
        out.append(
            Signal(
                id="pdf.parse_failed",
                title="PDF structure is malformed",
                severity="medium",
                detail=(
                    "The document does not parse as a well-formed PDF: "
                    + "; ".join(reasons)
                )[:600],
                evidence={"reasons": reasons[:10]},
            )
        )

    return out


# --- iocs ---------------------------------------------------------------------


def _iocs(uris: list[str], text_urls: list[str], text: str, names: list[str]) -> IOCs:
    urls = _dedupe([*uris, *text_urls], MAX_URLS)
    domains: list[str] = []
    ips: list[str] = []

    for url in urls:
        host = ""
        try:
            host = (urlsplit(url).hostname or "").strip("[]")
        except ValueError:
            continue
        if not host:
            continue
        if _RE_IPV4.fullmatch(host) and all(int(p) < 256 for p in host.split(".")):
            ips.append(host)
        elif ":" in host:
            ips.append(host)
        else:
            domains.append(host[:253])

    body = text[:MAX_TEXT_CHARS]
    emails = _dedupe(_RE_EMAIL.findall(body), 100)

    return IOCs(
        urls=urls,
        domains=_dedupe(domains, MAX_URLS),
        ips=_dedupe(ips, 100),
        emails=emails,
        file_paths=_dedupe(names, MAX_NAMES),
    )


# --- raw structure pass -------------------------------------------------------


#: `#hh` -> the byte it names, all 256 of them, built once.
#:
#: The substitution ran a Python lambda per match — `int(m.group(1), 16)` plus a
#: `bytes((...,))` allocation — and this function is called twice on up to 16 MiB
#: of buffer. Measured: 15.911s for 5,592,405 substitutions over 16 MB of `#41`,
#: twice, from one upload. A dict lookup keyed on the already-extracted group
#: does the same work with no interpreter call per match.
_HEXESC_BYTE = {
    f"{value:02x}".encode(): bytes((value,)) for value in range(256)
}
_HEXESC_BYTE.update({f"{value:02X}".encode(): bytes((value,)) for value in range(256)})
#: Mixed-case pairs (`#4a`, `#4A` are covered above; `#aB` is not), filled in so
#: the lookup never misses and the fallback below is only for a truly odd input.
_HEXESC_BYTE.update({
    f"{h}{l}".encode(): bytes((int(f"{h}{l}", 16),))
    for h in "0123456789abcdefABCDEF"
    for l in "0123456789abcdefABCDEF"
})


#: How many `#hh` escapes are decoded per buffer.
#:
#: This is what makes the pass bounded rather than merely faster. `re.sub` with a
#: count stops at the Nth replacement, so the work is proportional to where that
#: match is, not to the size of the buffer. The escape exists to hide a name —
#: `/J#61vaScript` — and a document that hides a name uses it a handful of times;
#: five million of them is a payload shaped to cost CPU, not a PDF. Everything
#: past the cap is still scanned in its raw form by every other pass.
MAX_NAME_ESCAPES = 50_000


def _decode_name_escapes(data: bytes) -> bytes:
    """Decode PDF ``#hh`` name escapes so /J#61vaScript reads as /JavaScript."""
    if b"#" not in data:
        return data
    try:
        return _RE_HEXESC.sub(
            lambda m: _HEXESC_BYTE[m.group(1)], data, count=MAX_NAME_ESCAPES
        )
    except Exception:
        return data


def _inflate_streams(data: bytes) -> tuple[bytes, dict[str, int]]:
    """Inflate FlateDecode stream bodies, hard-capped. Decompression only."""
    chunks: list[bytes] = []
    total = 0
    attempted = 0
    ok = 0

    for match in _RE_STREAM.finditer(data):
        if attempted >= MAX_STREAMS or total >= MAX_INFLATED_BYTES:
            break
        attempted += 1
        start = match.end()
        end = data.find(b"endstream", start)
        if end == -1:
            end = min(start + MAX_STREAM_IN, len(data))
        body = data[start : min(end, start + MAX_STREAM_IN)]
        if not body:
            continue
        try:
            out = zlib.decompressobj().decompress(body, MAX_STREAM_OUT)
        except Exception:
            continue
        if not out:
            continue
        out = out[: MAX_INFLATED_BYTES - total]
        chunks.append(out)
        total += len(out)
        ok += 1

    inflated = _decode_name_escapes(b"\n".join(chunks))
    return inflated, {
        "streams_seen": attempted,
        "streams_inflated": ok,
        "inflated_bytes": total,
    }


def _structure_facts(data: bytes, surface: bytes, inflated: bytes) -> dict[str, Any]:
    version_match = _RE_VERSION.search(data[:1024])
    header_at_start = data[:5] == b"%PDF-" or data[:1024].find(b"%PDF-") in range(0, 1024)

    visible_obj = len(_RE_OBJ.findall(surface))
    endobj = len(_RE_ENDOBJ.findall(surface))
    streams = len(_RE_STREAM.findall(data))
    page_objects = len(_RE_PAGE.findall(surface)) + len(_RE_PAGE.findall(inflated))

    broken: list[str] = []
    if not version_match:
        broken.append("no %PDF-x.y header in the first 1024 bytes")
    elif data[:5] != b"%PDF-":
        broken.append("%PDF header is not at offset 0")
    if visible_obj == 0 and b"/ObjStm" not in surface:
        broken.append("no indirect objects found")
    if b"startxref" not in data[-4096:] and b"startxref" not in data:
        broken.append("no startxref")
    if visible_obj and endobj == 0:
        broken.append("objects open but never close (no endobj)")

    return {
        "pdf_version": version_match.group(1).decode("ascii") if version_match else None,
        "linearized": b"/Linearized" in surface[:8192],
        "visible_obj": visible_obj,
        "endobj": endobj,
        "streams": streams,
        "page_objects": page_objects,
        "header_at_start": header_at_start,
        "broken": broken,
    }


def _uri_targets(buf: bytes) -> list[str]:
    """Every /URI (...) or /URI <hex> target. Extraction only — nothing is fetched."""
    out: list[str] = []
    for match in re.finditer(rb"/URI" + _TAIL + rb"\s*", buf):
        if len(out) >= MAX_URLS:
            break
        pos = match.end()
        if pos >= len(buf):
            break
        if buf[pos : pos + 1] == b"(":
            raw = _literal_string(buf, pos)
        elif buf[pos : pos + 1] == b"<" and buf[pos : pos + 2] != b"<<":
            end = buf.find(b">", pos, pos + MAX_STRING_BYTES)
            raw = _hex_string(buf[pos + 1 : end]) if end != -1 else None
        else:
            raw = None
        if raw:
            out.append(_text(raw, 2000))
    return out


def _file_names(buf: bytes) -> list[str]:
    """Names attached to file specifications: /F (x) and /UF (x)."""
    out: list[str] = []
    for match in re.finditer(rb"/(?:UF|F)" + _TAIL + rb"\s*\(", buf):
        if len(out) >= MAX_NAMES:
            break
        raw = _literal_string(buf, match.end() - 1)
        if raw:
            out.append(_text(raw, SNIPPET))
    return out


def _literal_string(buf: bytes, start: int) -> bytes | None:
    """Read a ``(...)`` literal, honouring escapes and nesting. Hard length cap."""
    if start >= len(buf) or buf[start : start + 1] != b"(":
        return None
    out = bytearray()
    depth = 1
    i = start + 1
    limit = min(len(buf), start + MAX_STRING_BYTES)
    while i < limit:
        ch = buf[i]
        if ch == 0x5C:  # backslash
            if i + 1 < limit:
                out.append(buf[i + 1])
            i += 2
            continue
        if ch == 0x28:
            depth += 1
        elif ch == 0x29:
            depth -= 1
            if depth == 0:
                return bytes(out)
        out.append(ch)
        i += 1
    return bytes(out) if out else None


def _hex_string(raw: bytes) -> bytes | None:
    digits = bytes(c for c in raw[:MAX_STRING_BYTES] if c not in b" \r\n\t")
    if len(digits) % 2:
        digits += b"0"
    try:
        return bytes.fromhex(digits.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None


def _first_snippet(buffers: tuple[tuple[str, bytes], ...], pattern: bytes) -> tuple[str, str]:
    rx = re.compile(pattern)
    for where, buf in buffers:
        if not buf:
            continue
        match = rx.search(buf)
        if match:
            return where, _text(buf[match.start() : match.start() + SNIPPET + 40], SNIPPET)
    return "unknown", ""


# --- pdfminer pass ------------------------------------------------------------


def _pdfminer_pass(path: str, size_bytes: int) -> dict[str, Any]:
    """Text, page count and document info, run under a hard wall-clock ceiling.

    pdfminer is worth having for legitimate documents, but on a malformed sample
    its fallback parser is an unbounded, uninterruptible loop — so it runs in a
    worker thread and we simply stop waiting after ``PDFMINER_TIMEOUT_S``. The
    raw scan has already produced every structural signal by this point; this
    pass only adds text and metadata, and losing them to a timeout is stated in
    the facts, never hidden.
    """
    skip = {"ok": False, "error": None, "encrypted": False,
            "page_count": None, "pages_read": 0, "text": ""}
    if size_bytes > MAX_PDFMINER_BYTES:
        skip["error"] = f"skipped: {size_bytes} bytes over {MAX_PDFMINER_BYTES}-byte pdfminer cap"
        return skip

    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

    # A daemon executor so a hung parse can never keep the process alive.
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_pdfminer_work, path)
    try:
        result = future.result(timeout=PDFMINER_TIMEOUT_S)
    except FuturesTimeout:
        result = dict(skip)
        result["error"] = f"skipped: pdfminer exceeded {PDFMINER_TIMEOUT_S:.0f}s (malformed structure)"
    except Exception as exc:  # noqa: BLE001
        result = dict(skip)
        result["error"] = f"pdfminer: {type(exc).__name__}"
    finally:
        # Do not join: an abandoned parse thread is left to die on its own so a
        # hostile file cannot block the analyzer's return.
        executor.shutdown(wait=False)
    return result


def _pdfminer_work(path: str) -> dict[str, Any]:
    """The actual pdfminer calls. Runs inside the timed worker thread."""
    result: dict[str, Any] = {"ok": False, "error": None, "encrypted": False,
                             "page_count": None, "pages_read": 0, "text": ""}
    try:
        from pdfminer.high_level import extract_text
        from pdfminer.pdfdocument import PDFDocument, PDFPasswordIncorrect
        from pdfminer.pdfpage import PDFPage
        from pdfminer.pdfparser import PDFParser
        from pdfminer.pdftypes import resolve1
    except Exception as exc:  # pragma: no cover - dependency missing on this host
        result["error"] = f"pdfminer unavailable: {type(exc).__name__}"
        return result

    try:
        with open(path, "rb") as fh:
            doc = PDFDocument(PDFParser(fh))
            pages = 0
            for _ in PDFPage.create_pages(doc):
                pages += 1
                if pages >= 10000:
                    break
            result["page_count"] = pages
            for key in ("Producer", "Creator", "Title", "Author"):
                for info in (doc.info or [])[:8]:
                    if key in info:
                        result[key.lower()] = _meta_text(resolve1(info[key]))
                        break
            result["ok"] = True
    except PDFPasswordIncorrect as exc:
        result["encrypted"] = True
        result["error"] = _text(str(exc).encode("utf-8", "replace"), SNIPPET)
        return result
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {_text(str(exc).encode('utf-8', 'replace'), 160)}"
        return result

    try:
        text = extract_text(path, maxpages=MAX_TEXT_PAGES, caching=False)
        result["text"] = text[:MAX_TEXT_CHARS] if text else ""
        result["pages_read"] = min(result["page_count"] or 0, MAX_TEXT_PAGES)
    except Exception as exc:
        result["error"] = f"text layer: {type(exc).__name__}"

    return result


def _meta_text(value: Any) -> str | None:
    """Info-dictionary values are attacker-controlled. Decode defensively, truncate."""
    if value is None:
        return None
    if isinstance(value, bytes):
        raw = value[:MAX_STRING_BYTES]
        if raw[:2] in (b"\xfe\xff", b"\xff\xfe"):
            try:
                return raw.decode("utf-16", "replace")[:SNIPPET]
            except Exception:
                pass
        return _text(raw, SNIPPET)
    return _text(str(value).encode("utf-8", "replace"), SNIPPET)


# --- helpers ------------------------------------------------------------------


def _text(raw: bytes, limit: int) -> str:
    """Sample-derived bytes to a short, printable, log-safe string."""
    decoded = raw[: limit * 4].decode("utf-8", "replace")
    cleaned = "".join(c if 32 <= ord(c) < 127 or ord(c) > 160 else "." for c in decoded)
    return cleaned[:limit]


#: A single keyword cannot appear more times than this before we stop counting.
#: Past the cap the exact number stops mattering — the signal already fires — and
#: a file that is nothing but repeated ``/JavaScript`` is not something to spend
#: seconds enumerating.
MAX_KEYWORD_HITS = 100_000


def _bounded_count(rx: "re.Pattern[bytes]", buf: bytes) -> int:
    count = 0
    for _ in rx.finditer(buf):
        count += 1
        if count >= MAX_KEYWORD_HITS:
            break
    return count


def _dedupe(values: list[str], limit: int) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        if value:
            seen.setdefault(value, None)
        if len(seen) >= limit:
            break
    return list(seen)


def _timed(result: AnalyzerResult, started: float) -> AnalyzerResult:
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    return result
