"""What is this file, actually?

Identification is a separate step from analysis for one reason: the submitter's
filename is a claim, and the gap between the claim and the content is itself one
of the most reliable malicious signals there is. ``invoice.pdf`` whose first two
bytes are ``MZ`` is not a mislabelled document, it is someone hoping you will
double-click it.

Detection reads the content. The extension is only ever compared against it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

#: Leading bytes -> (mime, human description, canonical extensions).
#: Ordered longest-first at match time so ZIP-family containers (which all start
#: PK\x03\x04) are resolved by their inner structure, not by the outer magic.
_MAGIC: tuple[tuple[bytes, str, str, tuple[str, ...]], ...] = (
    (b"MZ", "application/x-dosexec", "DOS/PE executable", (".exe", ".dll", ".sys", ".scr")),
    (b"\x7fELF", "application/x-elf", "ELF binary", (".elf", ".bin", ".so", ".o")),
    (b"\xca\xfe\xba\xbe", "application/java-vm", "Java class / Mach-O fat binary", (".class",)),
    (b"%PDF", "application/pdf", "PDF document", (".pdf",)),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage",
     "OLE2 compound document (legacy Office)", (".doc", ".xls", ".ppt", ".msi")),
    (b"Rar!\x1a\x07", "application/x-rar-compressed", "RAR archive", (".rar",)),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip archive", (".7z",)),
    (b"\x1f\x8b", "application/gzip", "gzip stream", (".gz", ".tgz")),
    (b"BZh", "application/x-bzip2", "bzip2 stream", (".bz2",)),
    (b"\xfd7zXZ\x00", "application/x-xz", "xz stream", (".xz",)),
    (b"\x89PNG\r\n\x1a\n", "image/png", "PNG image", (".png",)),
    (b"GIF8", "image/gif", "GIF image", (".gif",)),
    (b"\xff\xd8\xff", "image/jpeg", "JPEG image", (".jpg", ".jpeg")),
    (b"#!", "text/x-script", "script with a shebang", (".sh", ".py", ".pl")),
)

#: Offset-based magic that is not at byte 0.
_MAGIC_AT: tuple[tuple[int, bytes, str, str, tuple[str, ...]], ...] = (
    (257, b"ustar", "application/x-tar", "tar archive", (".tar",)),
    (32769, b"CD001", "application/x-iso9660-image", "ISO 9660 disk image", (".iso", ".img")),
)

#: Extensions the engine will accept a text-ish verdict for. Anything textual
#: that is not in here is still analysed — as a script, conservatively.
_SCRIPT_EXTENSIONS = {
    ".ps1": ("text/x-powershell", "PowerShell script"),
    ".js": ("text/javascript", "JavaScript"),
    ".jse": ("text/javascript", "encoded JScript"),
    ".vbs": ("text/vbscript", "VBScript"),
    ".vbe": ("text/vbscript", "encoded VBScript"),
    ".bat": ("text/x-msdos-batch", "Batch script"),
    ".cmd": ("text/x-msdos-batch", "Batch script"),
    ".py": ("text/x-python", "Python script"),
    ".sh": ("text/x-shellscript", "Shell script"),
    ".hta": ("application/hta", "HTML Application"),
    ".wsf": ("text/xml", "Windows Script File"),
}

#: Inside a ZIP container, these entries identify what the container really is.
_ZIP_MARKERS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("AndroidManifest.xml", "application/vnd.android.package-archive", "Android package", (".apk",)),
    ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
     "Word document (OOXML)", (".docx", ".docm")),
    ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
     "Excel workbook (OOXML)", (".xlsx", ".xlsm")),
    ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
     "PowerPoint presentation (OOXML)", (".pptx", ".pptm")),
    ("META-INF/MANIFEST.MF", "application/java-archive", "Java archive", (".jar", ".war")),
)


@dataclass(frozen=True)
class Identity:
    mime: str
    magic: str
    #: Canonical extensions for the detected content type.
    canonical_extensions: tuple[str, ...]
    claimed_extension: str
    extension_mismatch: bool
    #: Coarse family the analyzer registry dispatches on.
    family: str


def _zip_identity(path: str) -> tuple[str, str, tuple[str, ...]]:
    import zipfile

    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist()[:400])
    except Exception:
        return "application/zip", "ZIP archive", (".zip",)

    for marker, mime, magic, exts in _ZIP_MARKERS:
        if marker in names:
            return mime, magic, exts
    return "application/zip", "ZIP archive", (".zip",)


def _family_for(mime: str, claimed: str) -> str:
    if mime in ("application/x-dosexec",):
        return "pe"
    if mime in ("application/x-elf",):
        return "elf"
    if mime == "application/pdf":
        return "pdf"
    if mime.startswith("application/vnd.openxmlformats") or mime == "application/x-ole-storage":
        return "office"
    if mime in (
        "application/zip",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/gzip",
        "application/x-bzip2",
        "application/x-xz",
        "application/x-tar",
    ):
        return "archive"
    if mime in ("application/vnd.android.package-archive", "application/java-archive"):
        return "archive"
    if mime.startswith("text/") or mime == "application/hta" or claimed in _SCRIPT_EXTENSIONS:
        return "script"
    if mime == "application/x-iso9660-image":
        return "diskimage"
    return "unknown"


def _looks_textual(head: bytes) -> bool:
    if not head:
        return False
    if b"\x00" in head[:4096]:
        return False
    printable = sum(1 for b in head[:4096] if 9 <= b <= 13 or 32 <= b <= 126 or b >= 128)
    return printable / min(len(head), 4096) > 0.90


def identify(path: str, original_name: str) -> Identity:
    claimed = os.path.splitext(original_name)[1].lower()

    with open(path, "rb") as fh:
        head = fh.read(8192)

    mime = magic = None
    canonical: tuple[str, ...] = ()

    for prefix, m, desc, exts in _MAGIC:
        if head.startswith(prefix):
            mime, magic, canonical = m, desc, exts
            break

    if mime is None:
        for offset, marker, m, desc, exts in _MAGIC_AT:
            try:
                with open(path, "rb") as fh:
                    fh.seek(offset)
                    if fh.read(len(marker)) == marker:
                        mime, magic, canonical = m, desc, exts
                        break
            except OSError:
                continue

    if mime is None and head.startswith(b"PK\x03\x04"):
        mime, magic, canonical = _zip_identity(path)

    if mime is None:
        # puremagic is a wide, pure-python table; it is consulted after our own
        # checks rather than before, because it has no opinion about which ZIP
        # is an APK and which is a .docx.
        try:
            import puremagic

            guesses = puremagic.magic_file(path)
            if guesses:
                best = guesses[0]
                mime = best.mime_type or "application/octet-stream"
                magic = best.name or "unrecognised binary"
                canonical = tuple(e for e in [best.extension] if e)
        except Exception:
            pass

    if mime is None:
        if claimed in _SCRIPT_EXTENSIONS:
            mime, magic = _SCRIPT_EXTENSIONS[claimed]
            canonical = (claimed,)
        elif _looks_textual(head):
            mime, magic, canonical = "text/plain", "plain text", (".txt",)
        else:
            mime, magic, canonical = "application/octet-stream", "unrecognised binary", ()

    family = _family_for(mime, claimed)
    claimed_family = _family_for("", claimed) if claimed in _SCRIPT_EXTENSIONS else None

    # A claimed extension that the content contradicts. The point of this signal
    # is deception — a name chosen to make dangerous content look safe — so it
    # only fires when the FAMILY disagrees, not when two members of the same
    # family differ. A .txt that sniffs as text/csv is not a lie; a .pdf whose
    # bytes are a PE is. Unknown content contradicts nothing, and an unnamed
    # submission makes no claim.
    same_text_family = family == "script" and (
        claimed in _SCRIPT_EXTENSIONS or claimed in (".txt", ".csv", ".log", ".md", ".json", ".xml")
    )
    mismatch = bool(
        claimed
        and canonical
        and claimed not in canonical
        and mime != "application/octet-stream"
        and not same_text_family
    )

    return Identity(
        mime=mime,
        magic=magic,
        canonical_extensions=canonical,
        claimed_extension=claimed,
        extension_mismatch=mismatch,
        family=family,
    )
