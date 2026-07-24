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
