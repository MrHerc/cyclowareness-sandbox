"""877 of 1451 jobs were labelled "Uploaded" when nobody uploaded them.

`JobDetail` printed the provenance as a two-way choice:

    {job.source === 'url' ? 'From URL' : 'Uploaded'}

Everything that is not a URL becomes "Uploaded". On the live deployment the
sources are `upload: 573, archive_member: 877, url: 1` -- so **60% of the
evidence in the system carried a false origin**. An `archive_member` is a file
the engine extracted from a submitted archive; nobody uploaded it, and it is
often the only interesting thing in the submission.

That matters more here than in an ordinary UI. The exports feed a NIS2/DORA
incident record and a signed evidence bundle, and provenance is a large part of
what makes evidence evidence.

`CHANNEL_LABELS` in ui.tsx already held the right words for all four values.
Nothing read them; the ternary was written separately and drifted.

There is no frontend test runner in this repo, so this checks the contract from
the side that has one: every value the backend can put in `source` must have a
label on the page, and the two-way ternary must not come back.
"""
from __future__ import annotations

import re
from pathlib import Path

from app.engine.models import JobSource

#: `JobSource` is a plain constants class, not an Enum -- no `.value`, not
#: iterable. Read the attributes it actually has.
SOURCES = {
    name: value
    for name, value in vars(JobSource).items()
    if not name.startswith("_") and isinstance(value, str)
}

FRONTEND = Path(__file__).resolve().parents[2] / "frontend" / "src"
UI = FRONTEND / "components" / "ui.tsx"
JOB_DETAIL = FRONTEND / "pages" / "JobDetail.tsx"


def _labels() -> dict[str, str]:
    """Parse `CHANNEL_LABELS` out of ui.tsx."""
    source = UI.read_text(encoding="utf-8")
    block = source[source.index("CHANNEL_LABELS"):]
    block = block[: block.index("}")]
    return dict(re.findall(r"(\w+)\s*:\s*'([^']*)'", block))


def test_every_backend_source_has_a_label() -> None:
    """A value with no label falls through to a generic string, or to a lie."""
    labels = _labels()
    missing = [v for v in SOURCES.values() if v not in labels]
    assert not missing, (
        f"CHANNEL_LABELS in ui.tsx has no entry for {missing}; the report will "
        f"show a humanised guess instead of what the backend meant"
    )


def test_no_label_is_empty() -> None:
    assert all(v.strip() for v in _labels().values()), _labels()


def test_the_two_way_guess_is_gone() -> None:
    """The exact expression that produced the false "Uploaded"."""
    text = JOB_DETAIL.read_text(encoding="utf-8")
    assert "'From URL' : 'Uploaded'" not in text, (
        "JobDetail is back to guessing provenance from whether the source is a "
        "URL; archive members are not uploads"
    )
    assert "sourceLabel(job.source)" in text


def test_archive_members_are_not_called_uploads() -> None:
    """The specific claim, named so a future reader sees why this file exists."""
    labels = _labels()
    assert labels[JobSource.ARCHIVE_MEMBER] != labels[JobSource.UPLOAD]
    assert "upload" not in labels[JobSource.ARCHIVE_MEMBER].lower()
