"""Archive handling: open the container, never trust what is inside it.

An archive submitted for analysis is three attacks at once, and each has its own
bound here:

* **Zip bomb.** 42.zip is 42 KB and expands to 4.5 PB. Every entry is checked
  against a total-expansion budget *and* a per-entry ratio before a byte is
  written, and extraction is streamed so the budget can stop it mid-file.
* **Path traversal (Zip Slip).** Entry names are attacker-controlled strings,
  not paths. Nothing is ever extracted to a name derived from the archive; each
  member goes into quarantine under its own content hash, and the declared name
  survives only as metadata.
* **Recursive nesting.** An archive inside an archive inside an archive is a
  cheap way to exhaust an analyzer. Depth is capped, and the cap is a signal
  when it is hit, not a silent stop.

Encrypted archives are never brute-forced. The national sandbox hackathon brief is explicit about
this, and it is also the correct behaviour: the job pauses and asks for the
password, and the analyst supplying one is an act worth having in the audit log.
"""
from __future__ import annotations

import os
import zipfile
from dataclasses import dataclass, field

from .contracts import Signal
from .storage import StoredSample, store_bytes

#: Total bytes we are willing to write while unpacking one submission.
#:
#: It is spent through an :class:`ExpansionBudget` that the caller owns, because
#: this said "one submission" and was a fresh local in each of the four readers.
#: A nested archive is a separate `unpack` of a separate child job, so the real
#: ceiling was 256 MiB x every archive in the tree — bounded only by
#: `MAX_TOTAL_CHILD_JOBS`, which is 200. About 51 GiB written to quarantine from
#: one upload, from a zip of zips well under the size limit.
MAX_TOTAL_EXPANSION = 256 * 1024 * 1024
#: A single member larger than this is not extracted (it is still listed).
MAX_MEMBER_BYTES = 32 * 1024 * 1024
#: Compression ratio above which a member is treated as a bomb.
MAX_RATIO = 120
#: Below this, a high ratio is noise rather than a bomb: a 200-byte file of one
#: repeated character deflates to a handful of bytes and posts a ratio in the
#: dozens, and it expands to 200 bytes.
#:
#: The floor was `> 1024 * 1024`, a strict inequality on a round number the
#: submitter chooses. A member of EXACTLY 1 MiB at 1000:1 was therefore neither
#: skipped by the extraction guard nor reported by the signal — measured, 1 MiB
#: of zeros deflates to 1,033 bytes — and 500 of them is a 512 MiB expansion from
#: a 500 KB upload that the report calls unremarkable. 64 KiB is not a number
#: anyone lands on by accident, and it still expands to nothing worth stopping.
BOMB_SIZE_FLOOR = 64 * 1024
#: How deep nested archives are followed.
MAX_DEPTH = 3
#: Members listed/extracted per archive.
MAX_MEMBERS = 500

ARCHIVE_MIMES = {
    "application/zip",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    # tar and the single-stream compressors. `identify` has always called these
    # `archive`; this set did not contain them, and `_archive_stage` returns the
    # same value for "will not open" as for "not a container" -- so a gzipped
    # dropper was scored as a 1.7 clean text file with no signal saying anything
    # had been skipped. See `_read_tarlike`.
    "application/x-tar",
    "application/gzip",
    "application/x-bzip2",
    "application/x-xz",
    # APK and JAR are ZIP containers too, but they have dedicated deep analyzers
    # (manifest/permissions, Java class inspection) rather than generic member
    # promotion, so they are intentionally NOT unpacked here.
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    # A disk image is distribution media: what matters is the files a victim
    # sees once it is mounted. The diskimage analyzer already NAMED them, but
    # nothing opened them — so an ISO got a verdict about its contents with
    # nothing having read a byte of them, and "there is an executable inside"
    # was both the whole accusation and the whole examination.
    #
    # It matters in the other direction too, and more: an ISO is a standard way
    # to smuggle malware past mark-of-the-web. Promoting the members means the
    # container inherits its worst member's verdict, which is the answer to both
    # halves.
    "application/x-iso9660-image",
}


@dataclass
class ExpansionBudget:
    """Bytes a submission may still write while unpacking, at any depth.

    One object is shared by every `unpack` in a submission's tree — the same
    shape as the pipeline's `_ChildBudget`, and for the same reason: a limit that
    resets per archive is not a limit on the archive that contains archives.

    Callers that unpack a single container and nothing else may leave it out and
    get a fresh budget, which is what a direct `unpack(path, mime)` means.
    """

    remaining: int = MAX_TOTAL_EXPANSION

    def spend(self, count: int) -> None:
        self.remaining -= count

    def affordable(self, count: int) -> bool:
        return count <= self.remaining


class PasswordRequired(Exception):
    """The archive is encrypted and no usable password was supplied.

    ``attempted`` distinguishes the two ways to arrive here, because they need
    different words on screen. Nothing supplied yet is a prompt; a password that
    did not open the archive is an answer, and a UI that shows the same prompt
    for both leaves the analyst unable to tell "wrong password" from "my click
    did nothing".
    """

    def __init__(self, kind: str, *, attempted: bool = False):
        super().__init__(
            f"The password supplied did not open this {kind} archive."
            if attempted
            else f"{kind} archive is encrypted and needs a password"
        )
        self.kind = kind
        self.attempted = attempted


@dataclass
class Member:
    """One entry, as declared by the archive."""

    name: str
    size: int
    compressed_size: int
    encrypted: bool
    is_dir: bool
    #: Populated only when the member was actually extracted.
    stored: StoredSample | None = None
    skipped_reason: str | None = None

    @property
    def ratio(self) -> float:
        if self.compressed_size <= 0:
            return 0.0
        return self.size / self.compressed_size


@dataclass
class ArchiveResult:
    kind: str
    members: list[Member] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    encrypted: bool = False
    truncated: bool = False

    def extracted(self) -> list[Member]:
        return [m for m in self.members if m.stored is not None]


def _safe_display_name(raw: str) -> str:
    """The member name, made safe to show and impossible to use as a path.

    Anything path-like is flattened. This value is displayed and stored as
    metadata; it never reaches the filesystem, which is what actually prevents
    Zip Slip — the sanitising is so a crafted name cannot deceive a reader
    either (``invoice.pdf␡␡␡.exe`` and right-to-left overrides).
    """
    cleaned = raw.replace("\\", "/")
    cleaned = "".join(ch for ch in cleaned if ch.isprintable() and ch not in "‮‭‏")
    cleaned = cleaned.strip("/")
    return cleaned[:400] or "(unnamed)"


def _budget_signals(members: list[Member], kind: str) -> list[Signal]:
    signals: list[Signal] = []

    bombs = [m for m in members if m.ratio > MAX_RATIO and m.size >= BOMB_SIZE_FLOOR]
    if bombs:
        worst = max(bombs, key=lambda m: m.ratio)
        signals.append(
            Signal(
                id="archive.compression_bomb",
                title="Archive member expands far beyond its compressed size",
                severity="high",
                detail=(
                    f"{_safe_display_name(worst.name)} expands {worst.ratio:.0f}x "
                    f"({worst.compressed_size} bytes to {worst.size})."
                ),
                evidence={"member": _safe_display_name(worst.name), "ratio": round(worst.ratio, 1)},
            )
        )

    # `identify.disguised_name` rather than counting dots. Counting put
    # `Archive.Dropper.DoubleExtension` on five benign release zips, because
    # `libcurl-x64.dll.a` and a man page called `rclone.1` have the same shape as
    # `invoice.pdf.exe` and mean nothing like it.
    from .identify import disguised_name

    double = [m for m in members if not m.is_dir and disguised_name(m.name)]
    if double:
        signals.append(
            Signal(
                id="archive.double_extension",
                title="Archive contains a file with a deceptive double extension",
                severity="high",
                detail=", ".join(_safe_display_name(m.name) for m in double[:5]),
                evidence={"members": [_safe_display_name(m.name) for m in double[:20]]},
            )
        )

    executables = [
        m
        for m in members
        if not m.is_dir
        and os.path.splitext(m.name)[1].lower()
        in {".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".lnk"}
    ]
    if executables:
        signals.append(
            Signal(
                id="archive.contains_executable",
                title="Archive contains executable content",
                severity="medium",
                detail=f"{len(executables)} executable or scripting member(s) in a {kind} archive.",
                evidence={"members": [_safe_display_name(m.name) for m in executables[:20]]},
            )
        )

    if any(m.name.startswith(("/", "../")) or "/../" in m.name for m in members):
        signals.append(
            Signal(
                id="archive.path_traversal",
                title="Archive member name attempts to escape the extraction directory",
                severity="critical",
                detail="A member is named so that a naive extractor would write outside the target directory.",
                evidence={
                    "members": [
                        _safe_display_name(m.name)
                        for m in members
                        if m.name.startswith(("/", "../")) or "/../" in m.name
                    ][:20]
                },
            )
        )

    return signals


# --- ZIP ----------------------------------------------------------------------


def _read_zip(path: str, password: str | None, budget: ExpansionBudget) -> ArchiveResult:
    result = ArchiveResult(kind="zip")
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            result.truncated = True
            infos = infos[:MAX_MEMBERS]

        for info in infos:
            encrypted = bool(info.flag_bits & 0x1)
            result.members.append(
                Member(
                    name=info.filename,
                    size=info.file_size,
                    compressed_size=info.compress_size,
                    encrypted=encrypted,
                    is_dir=info.is_dir(),
                )
            )

        result.encrypted = any(m.encrypted for m in result.members)
        if result.encrypted and not password:
            raise PasswordRequired("ZIP")

        pwd = password.encode() if password else None
        for member, info in zip(result.members, infos):
            if member.is_dir:
                continue
            if member.size > MAX_MEMBER_BYTES:
                member.skipped_reason = "larger than the per-member limit"
                continue
            if member.ratio > MAX_RATIO and member.size >= BOMB_SIZE_FLOOR:
                member.skipped_reason = "compression ratio exceeds the bomb threshold"
                continue
            if not budget.affordable(member.size):
                member.skipped_reason = "total expansion budget exhausted"
                result.truncated = True
                continue
            try:
                with zf.open(info, pwd=pwd) as fh:
                    data = fh.read(MAX_MEMBER_BYTES + 1)
                if len(data) > MAX_MEMBER_BYTES:
                    member.skipped_reason = "declared size understated the real size"
                    continue
                budget.spend(len(data))
                member.stored = store_bytes(data)
            except RuntimeError as exc:  # bad password / unsupported encryption
                if "password" in str(exc).lower():
                    raise PasswordRequired("ZIP", attempted=bool(password)) from exc
                member.skipped_reason = f"could not be read: {exc}"[:200]
            except Exception as exc:  # noqa: BLE001 — one bad member is not a failed job
                member.skipped_reason = f"could not be read: {type(exc).__name__}"

    return result


# --- tar, gzip, bzip2, xz -----------------------------------------------------
#
# THESE WERE IDENTIFIED AS ARCHIVES AND NEVER OPENED.
#
# `identify._family_for` mapped `application/gzip`, `x-bzip2`, `x-xz` and
# `x-tar` to family `archive`; `ARCHIVE_MIMES` did not contain them; and
# `pipeline._archive_stage` returns `(None, False)` for a mime it will not
# unpack -- the same value it returns for "this is not a container at all". So
# nothing was extracted, nothing was promoted to a child job, and nothing said
# so. Measured by the pentest: `gzip dropper.ps1` turned a 70.0 / malicious
# verdict into 1.7 / clean with zero signals. One command, and the product's
# entire purpose is bypassed -- in the ordinary shapes of a mail attachment.
#
# The stdlib opens all four, so the fix is to open them rather than only to
# disclose them. The disclosure stays as well, for whatever is left.

_TARLIKE_MIMES = {
    "application/x-tar",
    "application/gzip",
    "application/x-bzip2",
    "application/x-xz",
}

#: Suffixes stripped to name the single member of a bare compressed stream.
_STREAM_SUFFIXES = (".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".Z")


def _read_tarlike(path: str, mime: str, budget: ExpansionBudget) -> ArchiveResult:
    """A tar (optionally compressed), or a single compressed stream.

    `tarfile` transparently handles `.tar.gz` / `.tar.bz2` / `.tar.xz`, so it is
    tried first; a bare `gzip`ped file is not a tar and falls through to the
    single-stream path.

    Three things this refuses on purpose, because a tar can express them and a
    ZIP cannot:

    * anything that is not a regular file -- a symlink, hardlink, device or FIFO
      is a way to make an extractor write outside the tree or block on open();
    * a member whose name escapes the archive (`..`, an absolute path). The name
      is never used as a path here -- members are stored by content hash -- but
      it is displayed, and a name that looks like an escape is worth recording;
    * anything past the shared expansion budget, which is what stops a bomb.
    """
    result = ArchiveResult(kind="tar")

    try:
        import tarfile

        with tarfile.open(path, "r:*") as tf:
            infos = []
            for info in tf:                      # streaming: never getmembers()
                infos.append(info)
                if len(infos) > MAX_MEMBERS:
                    result.truncated = True
                    infos.pop()
                    break

            for info in infos:
                member = Member(
                    name=_safe_display_name(info.name),
                    size=int(info.size),
                    # tar's header does not carry a per-member compressed size;
                    # the whole stream is compressed as one. Reporting the
                    # uncompressed size for both keeps `ratio` at 1.0 rather
                    # than inventing a ratio the format cannot express.
                    compressed_size=int(info.size),
                    encrypted=False,
                    is_dir=info.isdir(),
                )
                result.members.append(member)
                if member.is_dir:
                    continue
                if not info.isfile():
                    member.skipped_reason = (
                        f"not a regular file ({_tar_kind(info)}); extracting it would "
                        "act on the filesystem rather than read bytes"
                    )
                    continue
                if member.size > MAX_MEMBER_BYTES:
                    member.skipped_reason = "larger than the per-member limit"
                    continue
                if not budget.affordable(member.size):
                    member.skipped_reason = "total expansion budget exhausted"
                    result.truncated = True
                    continue
                try:
                    handle = tf.extractfile(info)
                    if handle is None:
                        member.skipped_reason = "could not be read: no data stream"
                        continue
                    with handle:
                        data = handle.read(MAX_MEMBER_BYTES + 1)
                    if len(data) > MAX_MEMBER_BYTES:
                        member.skipped_reason = "declared size understated the real size"
                        continue
                    budget.spend(len(data))
                    member.stored = store_bytes(data)
                except Exception as exc:  # noqa: BLE001 — one bad member is not a failed job
                    member.skipped_reason = f"could not be read: {type(exc).__name__}"

        # A TAR THAT PARSED TO NOTHING IS PROBABLY NOT A TAR.
        #
        # The end of a tar is two 512-byte blocks of zeros, so a stream that is
        # ALL zeros parses as a valid, empty archive -- and `gzip` of a few
        # megabytes of zeros is exactly the shape of the simplest decompression
        # bomb. Returning an empty result there would have reported "a container
        # with nothing in it" and never decompressed a byte, which is a
        # different way of missing the payload than the one this function was
        # written to fix. Fall through and read it as a stream.
        if result.members:
            return result
    except Exception:  # noqa: BLE001 — not a tar; try the single-stream shapes
        pass

    if mime == "application/x-tar":
        # A bare .tar that yielded no members really is an empty tar; there is
        # no compressed stream underneath to fall back to.
        return ArchiveResult(kind="tar")
    return _read_compressed_stream(path, mime, budget)


def _tar_kind(info) -> str:
    if info.issym():
        return "symlink"
    if info.islnk():
        return "hardlink"
    if info.ischr() or info.isblk():
        return "device node"
    if info.isfifo():
        return "FIFO"
    return "special entry"


def _read_compressed_stream(path: str, mime: str, budget: ExpansionBudget) -> ArchiveResult:
    """One file, compressed with gzip / bzip2 / xz. The commonest evasion shape.

    Decompressed in bounded chunks rather than in one call: `gzip.open().read()`
    on a bomb allocates whatever the stream expands to, and the point of the
    budget is that nothing here gets to choose how much memory it uses.
    """
    import bz2
    import gzip
    import lzma

    openers = {
        "application/gzip": gzip.open,
        "application/x-bzip2": bz2.open,
        "application/x-xz": lzma.open,
    }
    result = ArchiveResult(kind=mime.rsplit("/", 1)[-1].lstrip("x-") or "stream")
    opener = openers.get(mime)
    if opener is None:
        return result

    name = os.path.basename(path)
    for suffix in _STREAM_SUFFIXES:
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    member = Member(
        name=_safe_display_name(name or "decompressed"),
        size=0,
        compressed_size=os.path.getsize(path) if os.path.exists(path) else 0,
        encrypted=False,
        is_dir=False,
    )
    result.members.append(member)

    chunks: list[bytes] = []
    total = 0
    try:
        with opener(path, "rb") as fh:          # type: ignore[operator]
            while True:
                chunk = fh.read(1024 * 256)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_MEMBER_BYTES:
                    member.skipped_reason = "larger than the per-member limit"
                    return result
                if not budget.affordable(total):
                    member.skipped_reason = "total expansion budget exhausted"
                    result.truncated = True
                    return result
                chunks.append(chunk)
    except Exception as exc:  # noqa: BLE001
        member.skipped_reason = f"could not be read: {type(exc).__name__}"
        return result

    data = b"".join(chunks)
    member.size = len(data)
    budget.spend(len(data))
    member.stored = store_bytes(data)
    return result


# --- ISO 9660 -----------------------------------------------------------------


#: How much of the image is read to walk it. The directory structures live near
#: the front; a bigger image is not a reason to hold a gigabyte in memory, and
#: whatever is past this is reported as unexamined rather than pretended upon.
MAX_ISO_BYTES = 256 * 1024 * 1024


def _read_iso(path: str, budget: ExpansionBudget) -> ArchiveResult:
    """Extract the files a victim would see after mounting the image.

    The directory walk is `analyzers.diskimage._walk_iso` — the same hand-written
    ECMA-119 parser the analyzer already uses, rather than a second one that
    could disagree with it. Nothing is mounted, mapped or run: a directory
    record names a block and a length, and this reads those bytes.
    """
    from .analyzers import diskimage

    result = ArchiveResult(kind="iso")
    with open(path, "rb") as fh:
        data = fh.read(MAX_ISO_BYTES + 1)
    if len(data) > MAX_ISO_BYTES:
        result.truncated = True
        data = data[:MAX_ISO_BYTES]

    block_size = diskimage._u16le(data, diskimage._PVD_OFFSET + diskimage._PVD_BLOCK_SIZE_OFFSET)
    if block_size not in diskimage._VALID_BLOCK_SIZES:
        block_size = diskimage.DEFAULT_BLOCK_SIZE
    root = diskimage._PVD_OFFSET + diskimage._PVD_ROOT_RECORD_OFFSET
    entries = diskimage._walk_iso(
        data, diskimage._u32le(data, root + 2), diskimage._u32le(data, root + 10), block_size
    )

    if len(entries) > MAX_MEMBERS:
        result.truncated = True
        entries = entries[:MAX_MEMBERS]

    for entry in entries:
        member = Member(
            name=entry["name"],
            size=int(entry["size"]),
            compressed_size=int(entry["size"]),   # ISO 9660 does not compress.
            encrypted=False,
            is_dir=bool(entry["is_dir"]),
        )
        result.members.append(member)
        if member.is_dir:
            continue
        if member.size > MAX_MEMBER_BYTES:
            member.skipped_reason = "larger than the per-member limit"
            continue
        if not budget.affordable(member.size):
            member.skipped_reason = "total expansion budget exhausted"
            result.truncated = True
            continue
        start = int(entry.get("lba", 0)) * block_size
        end = start + member.size
        # A directory record can claim a block and a length that are not in the
        # file. The sample chose both numbers, so neither is trusted.
        if start < 0 or member.size < 0 or end > len(data):
            member.skipped_reason = "declared extent lies outside the image"
            result.truncated = True
            continue
        try:
            payload = data[start:end]
            budget.spend(len(payload))
            member.stored = store_bytes(payload)
        except Exception as exc:  # noqa: BLE001 — one bad member is not a failed job
            member.skipped_reason = f"could not be read: {type(exc).__name__}"

    return result


# --- 7z -----------------------------------------------------------------------


def _read_7z(path: str, password: str | None, budget: ExpansionBudget) -> ArchiveResult:
    import py7zr

    result = ArchiveResult(kind="7z")
    try:
        needs_password = py7zr.is_7zfile(path) and _seven_zip_is_encrypted(path)
    except Exception:
        needs_password = False

    if needs_password and not password:
        result.encrypted = True
        raise PasswordRequired("7z")

    try:
        with py7zr.SevenZipFile(path, mode="r", password=password) as zf:
            for info in zf.list()[:MAX_MEMBERS]:
                result.members.append(
                    Member(
                        name=info.filename,
                        size=info.uncompressed or 0,
                        compressed_size=int(info.compressed or 0),
                        encrypted=needs_password,
                        is_dir=bool(info.is_directory),
                    )
                )
            result.encrypted = needs_password

            # Unlike ZIP, py7zr has no per-member streaming read: it decompresses
            # into writers we hand it. So the budget is applied twice — once to
            # the declared sizes, to pick what is worth asking for at all, and
            # again to the bytes as they arrive, because a 7z header can
            # understate every size in it.
            # `planned` is the declared-size half. It starts at what the
            # submission has left and is NOT spent from the shared budget here:
            # the header chose these numbers, and the bytes that actually arrive
            # are what gets charged, below.
            planned = budget.remaining
            targets: list[str] = []
            by_name: dict[str, Member] = {}
            for member in result.members:
                if member.is_dir:
                    continue
                by_name[member.name] = member
                if member.size > MAX_MEMBER_BYTES:
                    member.skipped_reason = "larger than the per-member limit"
                    continue
                if member.ratio > MAX_RATIO and member.size >= BOMB_SIZE_FLOOR:
                    member.skipped_reason = "compression ratio exceeds the bomb threshold"
                    continue
                if member.size > planned:
                    member.skipped_reason = "total expansion budget exhausted"
                    result.truncated = True
                    continue
                planned -= member.size
                targets.append(member.name)

            for name, data in _seven_zip_read(zf, targets, budget.remaining).items():
                member = by_name.get(name)
                if member is None:
                    continue
                if len(data) > MAX_MEMBER_BYTES:
                    member.skipped_reason = "declared size understated the real size"
                    result.truncated = True
                    continue
                budget.spend(len(data))
                member.stored = store_bytes(data)
    except py7zr.exceptions.PasswordRequired as exc:
        raise PasswordRequired("7z", attempted=bool(password)) from exc
    except Exception as exc:
        # A WRONG password does not announce itself. py7zr hands the ciphertext
        # to LZMA and LZMA says `LZMAError: Corrupt input data` — no mention of a
        # password anywhere in it. So the message test alone sent a mistyped
        # password down the generic-failure path, and the job COMPLETED with
        # "container could not be inspected": the prompt disappeared, and the
        # analyst was told the archive was broken rather than that they had
        # fumbled the password.
        #
        # `needs_password` is not a guess — it was determined from the archive's
        # own header before any password was tried. Encrypted, a password was
        # supplied, and the data would not decompress: that is the password.
        if "password" in str(exc).lower() or (needs_password and password):
            raise PasswordRequired("7z", attempted=bool(password)) from exc
        raise

    return result


def _seven_zip_read(zf, targets: list[str], total: int) -> dict[str, bytes]:
    """Read the selected members into memory, whichever py7zr generation is installed.

    py7zr 0.x offered ``read()``/``readall()``, which return file-like buffers;
    1.x removed both in favour of a writer factory. The engine shipped calling
    ``readall()`` while pinned to ``py7zr>=0.22``, so on any current install every
    .7z raised AttributeError, the archive analyzer was recorded as merely
    unavailable, and a dropper inside a .7z was reported clean. Both call shapes
    are supported here so the pin can move without this breaking again.
    """
    if not targets:
        return {}

    factory = _bytes_factory(MAX_MEMBER_BYTES, total)
    if factory is not None:
        zf.extract(targets=targets, factory=factory)
        out: dict[str, bytes] = {}
        for name, product in factory.products.items():
            product.seek(0)
            out[name] = product.read(MAX_MEMBER_BYTES + 1)
        return out

    buffers = zf.read(targets) or {}
    return {name: buf.read(MAX_MEMBER_BYTES + 1) for name, buf in buffers.items()}


def _bytes_factory(per_member: int, total: int):
    """A py7zr writer factory that keeps every member under a shared budget.

    py7zr's own ``BytesIOFactory`` takes a single per-file limit and no total, so
    a 7z declaring five hundred members would be decompressed into five hundred
    buffers of that size. Returns None on a py7zr too old to have the factory
    API, which is the signal to fall back to ``read()``.
    """
    try:
        from py7zr.io import Py7zBytesIO, WriterFactory
    except Exception:  # noqa: BLE001 — py7zr < 1.0 has no io module
        return None

    class _BudgetedFactory(WriterFactory):
        def __init__(self) -> None:
            self.products: dict[str, Py7zBytesIO] = {}

        def create(self, filename: str):
            # Charged against what has already landed, because the size of a
            # member is only known once it has been written.
            spent = sum(p.size() for p in self.products.values())
            allowance = max(0, min(per_member, total - spent))
            product = Py7zBytesIO(filename, allowance + 1)
            self.products[filename] = product
            return product

        def get(self, filename: str):
            return self.products[filename]

    return _BudgetedFactory()


def _seven_zip_is_encrypted(path: str) -> bool:
    import py7zr

    try:
        with py7zr.SevenZipFile(path, mode="r") as zf:
            return bool(zf.needs_password())
    except py7zr.exceptions.PasswordRequired:
        return True
    except Exception as exc:  # noqa: BLE001
        # "Cannot open" is not "encrypted". Assuming encryption here parked every
        # corrupt or truncated .7z at awaiting_password — a prompt no password
        # can ever satisfy — instead of reporting a container that could not be
        # inspected, which is the honest and actionable outcome.
        return "password" in str(exc).lower()


# --- RAR ----------------------------------------------------------------------


def _read_rar(path: str, password: str | None, budget: ExpansionBudget) -> ArchiveResult:
    import rarfile

    result = ArchiveResult(kind="rar")
    try:
        with rarfile.RarFile(path) as rf:
            infos = rf.infolist()[:MAX_MEMBERS]
            for info in infos:
                result.members.append(
                    Member(
                        name=info.filename,
                        size=info.file_size or 0,
                        compressed_size=info.compress_size or 0,
                        encrypted=bool(getattr(info, "needs_password", lambda: False)()),
                        is_dir=info.isdir(),
                    )
                )
            result.encrypted = rf.needs_password() or any(m.encrypted for m in result.members)
            if result.encrypted and not password:
                raise PasswordRequired("RAR")
            if password:
                rf.setpassword(password)

            for member, info in zip(result.members, infos):
                if (member.is_dir or member.size > MAX_MEMBER_BYTES
                        or not budget.affordable(member.size)):
                    if not member.is_dir:
                        member.skipped_reason = "exceeds an extraction limit"
                    continue
                try:
                    data = rf.read(info)
                    budget.spend(len(data))
                    member.stored = store_bytes(data)
                except Exception as exc:  # noqa: BLE001
                    member.skipped_reason = f"could not be read: {type(exc).__name__}"
    except rarfile.BadRarFile as exc:
        # Same shape as the 7z case: an encrypted RAR opened with the wrong
        # password fails as corruption, not as an authentication error.
        if result.encrypted and password:
            raise PasswordRequired("RAR", attempted=True) from exc
        raise
    except rarfile.NeedFirstVolume as exc:
        raise ValueError("multi-volume RAR: the first volume was not submitted") from exc
    except rarfile.RarCannotExec as exc:
        # rarfile shells out to `unrar`, which is not installed everywhere. This
        # is an honest capability gap, not a clean verdict.
        raise RuntimeError(
            "RAR extraction needs the `unrar` binary, which is not installed on this host"
        ) from exc

    return result


# --- entry point ---------------------------------------------------------------


def unpack(
    path: str,
    mime: str,
    password: str | None = None,
    budget: ExpansionBudget | None = None,
) -> ArchiveResult:
    """Open an archive and quarantine every member we are willing to extract.

    Raises :class:`PasswordRequired` when the container is encrypted and no
    password was given — the caller parks the job rather than guessing.

    `budget` is the submission's remaining expansion allowance. Pass the same
    object for every archive in one tree; omit it and this container gets a fresh
    `MAX_TOTAL_EXPANSION` of its own.
    """
    budget = budget if budget is not None else ExpansionBudget()
    if mime == "application/x-iso9660-image":
        result = _read_iso(path, budget)
    elif mime == "application/x-7z-compressed":
        result = _read_7z(path, password, budget)
    elif mime == "application/x-rar-compressed":
        result = _read_rar(path, password, budget)
    elif mime in _TARLIKE_MIMES:
        result = _read_tarlike(path, mime, budget)
    else:
        result = _read_zip(path, password, budget)

    result.signals = _budget_signals(result.members, result.kind)
    if result.encrypted:
        result.signals.append(
            Signal(
                id="archive.encrypted",
                title="Archive is password-protected",
                severity="medium",
                detail=(
                    "Encrypted archives defeat mail and endpoint scanning, which is why "
                    "attackers use them to deliver payloads and to exfiltrate data. The "
                    "password was supplied by the submitter; it was not guessed."
                ),
            )
        )
    if result.truncated:
        result.signals.append(
            Signal(
                id="archive.truncated",
                title="Archive was only partially unpacked",
                severity="info",
                detail=(
                    "Extraction stopped at a safety limit (member count, member size, or the "
                    "total expansion budget). Members beyond that point were not analysed."
                ),
            )
        )
    return result
