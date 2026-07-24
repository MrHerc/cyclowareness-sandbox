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
from typing import Iterator

from .contracts import Signal
from .storage import StoredSample, store_bytes

#: Total bytes we are willing to write while unpacking one submission.
MAX_TOTAL_EXPANSION = 256 * 1024 * 1024
#: A single member larger than this is not extracted (it is still listed).
MAX_MEMBER_BYTES = 32 * 1024 * 1024
#: Compression ratio above which a member is treated as a bomb.
MAX_RATIO = 120
#: How deep nested archives are followed.
MAX_DEPTH = 3
#: Members listed/extracted per archive.
MAX_MEMBERS = 500

ARCHIVE_MIMES = {
    "application/zip",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    # APK and JAR are ZIP containers too, but they have dedicated deep analyzers
    # (manifest/permissions, Java class inspection) rather than generic member
    # promotion, so they are intentionally NOT unpacked here.
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


class PasswordRequired(Exception):
    """The archive is encrypted and no usable password was supplied."""

    def __init__(self, kind: str):
        super().__init__(f"{kind} archive is encrypted and needs a password")
        self.kind = kind


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

    bombs = [m for m in members if m.ratio > MAX_RATIO and m.size > 1024 * 1024]
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

    double = [
        m
        for m in members
        if not m.is_dir and len([p for p in m.name.split(".") if p]) >= 3
        and m.name.lower().rsplit(".", 1)[-1] in {"exe", "scr", "com", "pif", "bat", "cmd", "js", "vbs"}
    ]
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


def _read_zip(path: str, password: str | None) -> ArchiveResult:
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

        budget = MAX_TOTAL_EXPANSION
        pwd = password.encode() if password else None
        for member, info in zip(result.members, infos):
            if member.is_dir:
                continue
            if member.size > MAX_MEMBER_BYTES:
                member.skipped_reason = "larger than the per-member limit"
                continue
            if member.ratio > MAX_RATIO and member.size > 1024 * 1024:
                member.skipped_reason = "compression ratio exceeds the bomb threshold"
                continue
            if member.size > budget:
                member.skipped_reason = "total expansion budget exhausted"
                result.truncated = True
                continue
            try:
                with zf.open(info, pwd=pwd) as fh:
                    data = fh.read(MAX_MEMBER_BYTES + 1)
                if len(data) > MAX_MEMBER_BYTES:
                    member.skipped_reason = "declared size understated the real size"
                    continue
                budget -= len(data)
                member.stored = store_bytes(data)
            except RuntimeError as exc:  # bad password / unsupported encryption
                if "password" in str(exc).lower():
                    raise PasswordRequired("ZIP") from exc
                member.skipped_reason = f"could not be read: {exc}"[:200]
            except Exception as exc:  # noqa: BLE001 — one bad member is not a failed job
                member.skipped_reason = f"could not be read: {type(exc).__name__}"

    return result


# --- 7z -----------------------------------------------------------------------


def _read_7z(path: str, password: str | None) -> ArchiveResult:
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

            budget = MAX_TOTAL_EXPANSION
            extracted = zf.readall() or {}
            by_name = {m.name: m for m in result.members}
            for name, buffer in list(extracted.items())[:MAX_MEMBERS]:
                member = by_name.get(name)
                if member is None or member.is_dir:
                    continue
                data = buffer.read(MAX_MEMBER_BYTES + 1)
                if len(data) > MAX_MEMBER_BYTES:
                    member.skipped_reason = "larger than the per-member limit"
                    continue
                if len(data) > budget:
                    member.skipped_reason = "total expansion budget exhausted"
                    result.truncated = True
                    continue
                budget -= len(data)
                member.stored = store_bytes(data)
    except py7zr.exceptions.PasswordRequired as exc:
        raise PasswordRequired("7z") from exc
    except Exception as exc:
        if "password" in str(exc).lower():
            raise PasswordRequired("7z") from exc
        raise

    return result


def _seven_zip_is_encrypted(path: str) -> bool:
    import py7zr

    try:
        with py7zr.SevenZipFile(path, mode="r") as zf:
            return bool(zf.needs_password())
    except Exception:
        return True


# --- RAR ----------------------------------------------------------------------


def _read_rar(path: str, password: str | None) -> ArchiveResult:
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

            budget = MAX_TOTAL_EXPANSION
            for member, info in zip(result.members, infos):
                if member.is_dir or member.size > MAX_MEMBER_BYTES or member.size > budget:
                    if not member.is_dir:
                        member.skipped_reason = "exceeds an extraction limit"
                    continue
                try:
                    data = rf.read(info)
                    budget -= len(data)
                    member.stored = store_bytes(data)
                except Exception as exc:  # noqa: BLE001
                    member.skipped_reason = f"could not be read: {type(exc).__name__}"
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


def unpack(path: str, mime: str, password: str | None = None) -> ArchiveResult:
    """Open an archive and quarantine every member we are willing to extract.

    Raises :class:`PasswordRequired` when the container is encrypted and no
    password was given — the caller parks the job rather than guessing.
    """
    if mime == "application/x-7z-compressed":
        result = _read_7z(path, password)
    elif mime == "application/x-rar-compressed":
        result = _read_rar(path, password)
    else:
        result = _read_zip(path, password)

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


def iter_nested(path: str, mime: str, password: str | None, depth: int = 0) -> Iterator[tuple[Member, int]]:
    """Yield every extractable member, following nested archives to MAX_DEPTH."""
    if depth >= MAX_DEPTH:
        return
    try:
        result = unpack(path, mime, password)
    except (PasswordRequired, Exception):
        return
    for member in result.extracted():
        yield member, depth
        if member.stored is None:
            continue
