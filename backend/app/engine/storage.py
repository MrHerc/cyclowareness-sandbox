"""Quarantine: where an untrusted sample is allowed to sit, and nowhere else.

Everything here exists because the input is hostile by definition. The rules:

* The sample is written under a **content-addressed** name (its SHA-256), never
  under the name the submitter chose. A filename is attacker-controlled data;
  treating it as a path is how ``../../etc/cron.d/x`` and ``report.pdf.exe`` get
  written somewhere they are read back from.
* Permissions are stripped to owner read-only, and the file is never marked
  executable. On a host that mounts the quarantine ``noexec`` this is belt and
  braces; on one that does not, it is the only brace.
* Size is capped **while streaming**, not after. A ``Content-Length`` header is
  a claim by the sender, and checking it after the write is a disk-fill away
  from an outage.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

#: Hard ceiling for a single submitted sample. The national sandbox hackathon brief suggests 10 MB
#: for the hackathon MVP; archives are additionally bounded by their own
#: expansion limits in archives.py.
MAX_SAMPLE_BYTES = 32 * 1024 * 1024

_CHUNK = 64 * 1024


class SampleTooLarge(ValueError):
    def __init__(self, limit: int):
        super().__init__(f"Sample exceeds the {limit // (1024 * 1024)} MB limit")
        self.limit = limit


class EmptySample(ValueError):
    def __init__(self) -> None:
        super().__init__("Sample is empty")


#: Free space below which submissions are refused.
#:
#: The quarantine shares the host's data filesystem with PostgreSQL and Docker,
#: so running it dry is not a storage problem, it is an outage. 2 GiB is enough
#: headroom for the database to keep writing while an operator responds, and it
#: is far above the per-sample ceiling so a legitimate upload is never the thing
#: that crosses it.
MIN_FREE_BYTES = 2 * 1024 * 1024 * 1024


class QuarantineFull(RuntimeError):
    """The disk holding the quarantine has no headroom left."""

    def __init__(self, free: int, required: int) -> None:
        super().__init__(
            f"Quarantine storage is nearly full: {free // (1024 * 1024)} MB free, "
            f"{required // (1024 * 1024)} MB required. New submissions are refused "
            "until space is reclaimed — configure SAMPLE_RETENTION_DAYS or free the "
            "volume. Analysis already stored is unaffected."
        )
        self.free = free
        self.required = required


def _free_bytes(path) -> int | None:
    """Free bytes on the filesystem holding `path`, or None if it cannot be read."""
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


@dataclass(frozen=True)
class StoredSample:
    path: str
    size_bytes: int
    sha256: str
    md5: str


def quarantine_root() -> Path:
    """Where samples live. Overridable so tests never touch the real tree."""
    root = Path(os.environ.get("SANDBOX_QUARANTINE", "")) if os.environ.get(
        "SANDBOX_QUARANTINE"
    ) else Path(tempfile.gettempdir()) / "cyclowareness-sandbox-quarantine"
    root.mkdir(parents=True, exist_ok=True)
    return root


def quarantine_is_noexec() -> bool | None:
    """Would the kernel refuse to execute a file in the quarantine?

    THIS WAS A CLAIM IN THREE FILES AND NOWHERE ELSE. `docker-compose.yml`,
    `SECURITY.md` and `DEPLOY.md` all stated the quarantine is mounted
    `noexec,nosuid,nodev`; the live deployment had 1,362 samples on a plain
    `rw,relatime` directory, and a shell script written there ran. The
    documents described a control nobody had applied.

    So the product reports it rather than asserting it. Read from
    `/proc/mounts`, longest matching mount point wins -- the same rule the
    kernel uses -- and `None` on a platform that has no `/proc/mounts`, which is
    "cannot tell" rather than a guess in either direction.

    Deliberately NOT wired into `validate_production`: the quarantine is a
    temporary directory under pytest and on any developer machine, so booting
    would refuse everywhere except the one host that already has it right.
    `/api/capabilities` publishes it, which puts it in front of the operator
    without turning a hardening step into an outage.
    """
    try:
        target = quarantine_root().resolve()
        with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as handle:
            entries = [line.split() for line in handle]
    except (OSError, ValueError):
        return None

    best: tuple[int, str] | None = None
    for parts in entries:
        if len(parts) < 4:
            continue
        point, options = parts[1], parts[3]
        try:
            resolved = Path(point).resolve()
        except (OSError, ValueError):
            continue
        if resolved == target or resolved in target.parents:
            depth = len(resolved.parts)
            if best is None or depth > best[0]:
                best = (depth, options)
    if best is None:
        return None
    return "noexec" in best[1].split(",")


def _harden(path: Path) -> None:
    """Owner-read-only, and explicitly not executable.

    Best-effort: on Windows the POSIX bits are largely advisory, which is why
    the deployed engine is expected to run on Linux with the quarantine mounted
    noexec. Failing to chmod must not fail the job — the analysis never runs the
    file regardless, and losing the sample would hide the finding.
    """
    try:
        os.chmod(path, stat.S_IRUSR)
    except OSError:
        pass


def store_stream(stream: BinaryIO, *, max_bytes: int = MAX_SAMPLE_BYTES) -> StoredSample:
    """Stream into quarantine, hashing as we go, refusing to exceed the cap.

    The temporary file is written inside the quarantine tree, not the system
    temp dir, so a sample never lands on a volume that might be exec-mounted —
    and so an interrupted upload cannot leave debris outside the quarantine.
    """
    root = quarantine_root()

    # NOTHING BOUNDED THE QUARANTINE IN AGGREGATE.
    #
    # `max_bytes` caps ONE sample. Retention is opt-in and off by default, and no
    # free-space check existed anywhere, so a single submit-only API key -- the
    # credential the design treats as the low-privilege one, pasted into CI
    # pipelines and SIEM connectors -- could fill the host's only data filesystem
    # in single-digit hours, taking PostgreSQL and Docker down with it.
    #
    # A FLOOR RATHER THAN A CEILING. A configured byte quota would be one more
    # number to keep in step with the disk; what actually matters is whether the
    # machine can still write, so submissions are refused while less than
    # `MIN_FREE_BYTES` remains. 507 (Insufficient Storage) rather than 500,
    # because this is a condition an operator resolves, not a bug.
    free = _free_bytes(root)
    if free is not None and free < MIN_FREE_BYTES:
        raise QuarantineFull(free, MIN_FREE_BYTES)

    sha, md5 = hashlib.sha256(), hashlib.md5()
    size = 0

    fd, tmp_name = tempfile.mkstemp(dir=root, prefix=".partial-")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = stream.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise SampleTooLarge(max_bytes)
                sha.update(chunk)
                md5.update(chunk)
                out.write(chunk)

        if size == 0:
            raise EmptySample()

        digest = sha.hexdigest()
        # Content-addressed: two submissions of the same bytes are one file, and
        # the path can never be steered by the submitted name.
        final = root / digest[:2] / digest
        final.parent.mkdir(parents=True, exist_ok=True)
        if final.exists():
            tmp.unlink(missing_ok=True)
        else:
            shutil.move(str(tmp), str(final))
            _harden(final)

        return StoredSample(
            path=str(final), size_bytes=size, sha256=digest, md5=md5.hexdigest()
        )
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def store_bytes(data: bytes, *, max_bytes: int = MAX_SAMPLE_BYTES) -> StoredSample:
    import io

    return store_stream(io.BytesIO(data), max_bytes=max_bytes)


def sample_path(sha256: str) -> Path | None:
    """Where a sample's bytes would be, or None if the digest is unusable.

    The content-addressed layout `root / digest[:2] / digest` lived only inside
    `store_stream`, so anything else that needed to know whether a sample still
    exists had to re-derive it — and the one caller that needed it instead read
    a database column, which is how an evidence export came to assert that a
    file was retained when the disk it lived on had been wiped.

    Returns the path whether or not it exists; `exists()` is the caller's
    question. None only for a missing or malformed digest, because guessing a
    path from a bad hash would answer that question wrongly.
    """
    digest = (sha256 or "").strip().lower()
    if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
        return None
    return quarantine_root() / digest[:2] / digest


def sample_exists(sha256: str) -> bool:
    """Whether this deployment still holds the bytes. Never raises."""
    path = sample_path(sha256)
    if path is None:
        return False
    try:
        return path.is_file()
    except OSError:
        # An unreadable quarantine is not a retained sample. Reporting False is
        # the safe direction: the claim this feeds is "we still hold the file".
        return False


def iter_quarantined() -> Iterator[Path]:
    for shard in quarantine_root().iterdir():
        if shard.is_dir():
            yield from (p for p in shard.iterdir() if p.is_file())


def purge_older_than(days: int) -> int:
    """Retention. Samples are evidence, but they are also live malware."""
    import time

    cutoff = time.time() - days * 86400
    removed = 0
    for path in iter_quarantined():
        try:
            if path.stat().st_mtime < cutoff:
                path.chmod(stat.S_IWUSR | stat.S_IRUSR)
                path.unlink()
                removed += 1
        except OSError:
            continue
    return removed
