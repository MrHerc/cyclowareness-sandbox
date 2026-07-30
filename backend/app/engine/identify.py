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
    # Every extension Windows legitimately gives a PE, not just the common four.
    # This is a FACT about the format, and a closed one — unlike a list of
    # "behaviours benign software performs", it can actually be completed.
    #
    # Measured cost of the short list: Python's own embeddable distribution puts
    # eleven `.pyd` files (C extension modules, PE by definition) on disk, and
    # every one was rated `malicious` at 60-66 on `generic.extension_mismatch`
    # alone — the engine's strongest deception signal, at HIGH severity, saying
    # a Microsoft-shipped Python module was disguising itself.
    (b"MZ", "application/x-dosexec", "DOS/PE executable", (
        ".exe", ".dll", ".sys", ".scr",
        ".pyd",   # Python C extension module
        ".node",  # Node.js native addon
        ".ocx",   # ActiveX control
        ".cpl",   # Control Panel applet
        ".drv",   # driver
        ".ax",    # DirectShow filter
        ".mui",   # multilingual resource
        ".tsp",   # telephony service provider
        ".efi",   # UEFI application
        ".com",   # DOS-era, still PE in practice
        ".msstyles",  # visual style
    )),
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

#: How many ZIP entry names identification will read. Bounded because the input
#: is hostile: a container with a million entries must not stall the analyzer.
MAX_ZIP_NAMES = 5000

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
    """What a ZIP container really is, from the parts it carries.

    Marker matching is by PREFIX over the whole entry list, not an exact name
    over the first 400 entries. Office writes parts like ``xl/workbook2.xml``
    when a workbook has been through certain tools, and a name-exact check sent
    those documents to the archive analyzer instead of the Office one — the
    macro analysis silently never ran. Reading every name also removes the
    trivial evasion of padding a container with 400 junk entries.
    """
    import zipfile

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()[:MAX_ZIP_NAMES]
    except Exception:
        return "application/zip", "ZIP archive", _ZIP_EXTENSIONS

    for marker, mime, magic, exts in _ZIP_MARKERS:
        prefix = marker.rsplit("/", 1)[0] + "/" if "/" in marker else marker
        stem = marker.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        for name in names:
            if name == marker:
                return mime, magic, exts
            # e.g. marker "xl/workbook.xml" also matches "xl/workbook2.xml"
            if "/" in marker and name.startswith(prefix):
                tail = name[len(prefix):]
                if tail.startswith(stem):
                    return mime, magic, exts
    return "application/zip", "ZIP archive", _ZIP_EXTENSIONS


#: Every extension that is legitimately a ZIP container. A `.msixbundle` IS a
#: zip — that is the format — so calling the extension a mismatch says the file
#: is disguised when it is exactly what it claims to be. Measured: Microsoft's
#: own Windows Terminal release was `Archive.Riskware.ExtensionMismatch` at
#: high severity for shipping in its documented format.
_ZIP_EXTENSIONS = (
    ".zip",
    # Windows app packages
    ".msix", ".msixbundle", ".appx", ".appxbundle",
    # Java / Android
    ".jar", ".war", ".ear", ".apk", ".aab",
    # OpenDocument and friends
    ".odt", ".ods", ".odp", ".odg",
    # everyday containers that are zip underneath
    ".epub", ".whl", ".egg", ".nupkg", ".crx", ".xpi", ".vsix", ".ipa",
)


#: Extensions the operating system will RUN if a user double-clicks them.
#: Extensions that promise a specific BINARY layout — a magic number, a header,
#: a container. If one of these holds plain text, the name and the bytes really
#: do disagree, and that is worth saying.
#:
#: The inverse of `_TEXTUAL_EXTENSIONS`, and bounded where that one is not:
#: formats with a real magic number are a closed set that barely changes, while
#: "extensions that hold text" grows every time someone ships a new config
#: format. Deliberately excludes `.pub` (an SSH public key is text) and every
#: source, config, markup and documentation extension.
_BINARY_FORMAT_EXTENSIONS = frozenset({
    # executables, libraries, objects
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".drv", ".ocx", ".pyd",
    ".so", ".dylib", ".o", ".obj", ".lib", ".elf", ".app", ".class", ".pyc",
    ".wasm", ".lnk",
    # installers and packages
    ".msi", ".msp", ".msm", ".cab", ".deb", ".rpm", ".pkg", ".dmg",
    ".msix", ".msixbundle", ".appx", ".appxbundle", ".nupkg", ".whl", ".egg",
    # documents with a container
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
    ".odt", ".ods", ".odp", ".odg", ".one", ".vsd", ".epub",
    # archives and disk images
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".zst", ".tar", ".lz",
    ".jar", ".war", ".ear", ".apk", ".aab", ".ipa",
    ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".udf",
    # media
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac", ".ogg", ".webm",
    # fonts and databases
    ".ttf", ".otf", ".woff", ".woff2", ".db", ".sqlite", ".mdb", ".pdb",
})

#: Mimes that are text, whichever subtype libmagic settles on. `message/rfc822`
#: is in here because that is what a git log looks like to libmagic.
_INERT_TEXT_MIMES = frozenset({
    "application/xml", "application/json", "application/javascript",
    "application/x-empty", "inode/x-empty", "message/rfc822",
    "application/x-ndjson", "application/toml", "application/yaml",
})


def _is_inert_text(mime: str) -> bool:
    return mime.startswith("text/") or mime in _INERT_TEXT_MIMES


#: Extensions Windows will actually RUN, one way or another — a shell, a script
#: host, a registry import, a shortcut.
#:
#: `identify()` routes every `text/*` mime into family `script`, and `script` is a
#: detonatable family, so a LICENSE file, a README, a man page, a CA bundle and a
#: `.desktop` entry were all being handed to a live Windows guest. Measured on the
#: detonation host: **226 detonations of files Windows cannot execute** — 87
#: `.txt`, 42 `.md`, 39 with no extension at all. Each one costs a guest and
#: several minutes, and each one comes back with signals about what the GUEST did
#: when asked to open something that does not run: `README.html` was reported with
#: `capev2.ransomware_file_modifications`.
WINDOWS_RUNS_THESE = frozenset({
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".com",
    ".vbs", ".vbe", ".vb", ".js", ".jse", ".wsf", ".wsh", ".ws",
    ".hta", ".msc", ".reg", ".lnk", ".url", ".scf", ".inf", ".pif",
    ".py", ".pyw", ".jar", ".sh",
})

#: Mimes whose CONTENT identifies a script, whatever the file is called. A
#: PowerShell dropper renamed `notes.txt` still gets detonated because of this —
#: the gate is about whether there is an execution path, never about whether the
#: submitter chose an honest name.
_EXECUTABLE_SCRIPT_MIMES = frozenset({
    "text/x-powershell", "text/x-msdos-batch", "text/vbscript",
    "text/javascript", "application/javascript", "text/x-python",
    "text/x-shellscript", "text/x-script", "application/hta",
})


def has_execution_path(claimed_extension: str | None, mime: str) -> bool:
    """Is there any way this file RUNS, rather than merely being read?

    Deliberately generous on the content side and strict on the name side: if
    either the bytes look like a script or the name is one Windows executes, the
    answer is yes. `.html` is NOT included — double-clicking a local HTML file
    opens a browser, and a browser rendering a page is not the sample executing
    on the host. Static analysis still reads every one of these in full; this only
    decides whether a guest is spent on it.
    """
    if (mime or "") in _EXECUTABLE_SCRIPT_MIMES:
        return True
    return (claimed_extension or "").lower() in WINDOWS_RUNS_THESE


EXECUTABLE_EXTENSIONS = frozenset({
    ".exe", ".scr", ".com", ".pif", ".cpl", ".dll", ".sys", ".drv", ".ocx",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".msi", ".msp", ".jar", ".lnk", ".reg", ".inf", ".apk",
    ".app", ".sh", ".py", ".pl", ".rb", ".php",
})

#: Extensions that make a file look like something to READ, WATCH or UNPACK —
#: the half of the trick that lowers a person's guard.
DOCUMENT_EXTENSIONS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
    ".txt", ".rtf", ".csv", ".log", ".md", ".htm", ".html", ".xml", ".json",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".tif", ".tiff",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso",
})


def disguised_name(name: str | None) -> tuple[str, str] | None:
    """`(what it looks like, what it runs as)` if the name is a disguise.

    The classic delivery trick: `invoice.pdf.exe`. Windows hides known
    extensions by default, so the victim sees `invoice.pdf` and double-clicks a
    program.

    The old test was "three or more dot-separated parts", which is both too
    loose and too tight. Too loose: `libcurl-x64.dll.a`, `archive.tar.gz` and a
    man page called `rclone.1` all have the shape and none is a disguise — that
    check put `Archive.Dropper.DoubleExtension` on five benign release zips.
    Too tight in the way that matters: it never looked at what the extensions
    MEAN, so it did not fire at all on a top-level upload, and `invoice.pdf.exe`
    submitted directly came back **clean**.

    A disguise is specifically: the last extension RUNS, and the one before it
    reads as something safe to open.
    """
    if not name:
        return None
    parts = name.strip().lower().rsplit(".", 2)
    if len(parts) < 3 or not parts[0]:
        return None
    _stem, looks_like, runs_as = parts
    looks_like, runs_as = f".{looks_like}", f".{runs_as}"
    if runs_as in EXECUTABLE_EXTENSIONS and looks_like in DOCUMENT_EXTENSIONS:
        return looks_like, runs_as
    return None


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
    if mime == "application/vnd.android.package-archive":
        return "apk"
    if mime == "application/java-archive":
        return "jar"
    if mime.startswith("text/") or mime == "application/hta" or claimed in _SCRIPT_EXTENSIONS:
        return "script"
    if mime == "application/x-iso9660-image":
        return "diskimage"
    # A raw .img / .iso with no recognisable magic still gets the disk-image
    # analyzer, which scans a filesystem-less image for embedded executables.
    if claimed in (".iso", ".img"):
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
    # Any plain-text document type sniffing as text is not a lie. The list has
    # to cover ordinary web/config/source extensions too — a .css file detected
    # as text/plain was being reported as an extension mismatch, which is the
    # engine's strongest deception signal.
    _TEXTUAL_EXTENSIONS = (
        ".txt", ".csv", ".log", ".md", ".json", ".xml", ".yaml", ".yml", ".ini",
        ".cfg", ".conf", ".toml", ".css", ".scss", ".html", ".htm", ".svg",
        ".ts", ".tsx", ".jsx", ".sql", ".rst", ".tex", ".c", ".h", ".cpp",
        ".java", ".go", ".rs", ".rb", ".php", ".pl", ".lua", ".r", ".m",
        # PEM-armoured crypto material is text by design. curl's own
        # `curl-ca-bundle.crt` — a CA trust store, the least deceptive file
        # imaginable — was rated malicious at 81.1 as
        # `Script.Downloader.ExtensionMismatch`.
        ".crt", ".cer", ".pem", ".key", ".pub", ".csr", ".p7b", ".asc", ".sig",
        # Man pages are roff source, i.e. text. `rclone.1` was MALICIOUS at 77.3
        # as `Script.Downloader.ExtensionMismatch`, and `upx.1` at 69.2 — the
        # manuals of the tools, shipped inside the tools' own archives.
        ".1", ".2", ".3", ".4", ".5", ".6", ".7", ".8", ".9", ".man", ".roff",
        # Unix packaging and desktop metadata, all plain text.
        ".desktop", ".service", ".def", ".po", ".pot", ".diff", ".patch",
        ".properties", ".tsv", ".less", ".kt", ".swift", ".cs", ".hpp",
    )
    same_text_family = family == "script" and (
        claimed in _SCRIPT_EXTENSIONS or claimed in _TEXTUAL_EXTENSIONS
    )
    mismatch = bool(
        claimed
        and canonical
        and claimed not in canonical
        and mime != "application/octet-stream"
        and not same_text_family
    )

    # A name and a body only disagree when the BODY IS MORE DANGEROUS THAN THE
    # NAME PROMISES. That is what this signal is for — the comment above says so
    # — but `_TEXTUAL_EXTENSIONS` tries to reach it by naming every extension in
    # the world that holds text, which is not a finite list. It was extended for
    # `.css`, then for PEM material, then for man pages, then for `.desktop`,
    # and still called three ordinary files disguised, at HIGH, the engine's
    # strongest deception signal:
    #
    #     git-log.txt        libmagic reads `commit <sha> / Author: / Date:`
    #                        as RFC 2822 email headers
    #     rg.bash            "the bytes are ascii text" — a .bash file is
    #     syncthing.plist    "the bytes are XML Document" — a .plist is
    #
    # So ask the bounded question instead. Text under a name that does not
    # promise a binary container is not a disguise, whichever subtype libmagic
    # picks for it. `invoice.pdf` holding a PowerShell script still is one,
    # because `.pdf` promises a container and does not have it.
    if mismatch and _is_inert_text(mime) and claimed not in _BINARY_FORMAT_EXTENSIONS:
        mismatch = False

    # A known script extension carries its specific content-type, so downstream
    # (platform naming, reporting) sees e.g. text/x-powershell rather than the
    # generic text/plain that a content sniff returns for any script.
    if family == "script" and claimed in _SCRIPT_EXTENSIONS:
        mime, magic = _SCRIPT_EXTENSIONS[claimed]
        if not canonical:
            canonical = (claimed,)

    return Identity(
        mime=mime,
        magic=magic,
        canonical_extensions=canonical,
        claimed_extension=claimed,
        extension_mismatch=mismatch,
        family=family,
    )
