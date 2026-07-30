"""A revision id longer than 32 characters breaks the upgrade on Postgres only.

Alembic's default version table is:

    CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)

so a revision id of 33 characters runs its DDL and then fails to record itself
with `StringDataRightTruncation`. Postgres wraps DDL in a transaction and rolls
the whole thing back, so nothing is half-applied — but the service is then in a
loop where every boot re-attempts the migration and every boot fails.

Measured on the real deployment: `0007_first_completed_and_manifest` (33 chars)
did exactly this. **SQLite has no length limit on that column, so the entire test
suite passed** — the same shape of blind spot as `?status=%00`, which is a 500 on
Postgres and fine on SQLite.

This is cheap to check and impossible to notice by reading.
"""
from __future__ import annotations

import pathlib
import re

import pytest

#: Alembic's own default. Not ours to change: a deployment that already has the
#: table has a varchar(32), and widening it would itself need a migration.
ALEMBIC_VERSION_NUM_LENGTH = 32

VERSIONS = pathlib.Path(__file__).resolve().parents[1] / "migrations" / "versions"


#: `revision = "x"` and `revision: str = "x"` are both used in this tree, and a
#: pattern that only matched the first silently skipped three migrations and made
#: the ladder check pass on an incomplete set. The `test_the_versions_directory
#: _is_not_empty` guard below exists because of that.
_ASSIGN = r'^{key}\s*(?::\s*[^=]+)?=\s*"([^"]+)"'


def _revisions() -> list[tuple[str, str]]:
    out = []
    for path in sorted(VERSIONS.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for key in ("revision", "down_revision"):
            for match in re.finditer(_ASSIGN.format(key=key), text, re.M):
                out.append((path.name, match.group(1)))
    return out


def test_every_migration_file_was_parsed() -> None:
    """A guard that passes vacuously is worse than no guard.

    The first version of this parser matched only `revision = "x"` and missed the
    three files written as `revision: str = "x"` — so the ladder check below
    validated four migrations out of seven and reported success.
    """
    assert VERSIONS.is_dir(), VERSIONS
    files = list(VERSIONS.glob("*.py"))
    assert files, "no migrations found; the glob is wrong"
    parsed = {name for name, _rev in _revisions()}
    missed = {p.name for p in files} - parsed
    assert not missed, f"these migration files declare no revision this parser sees: {missed}"


@pytest.mark.parametrize("case", _revisions(), ids=[f"{n}:{r}" for n, r in _revisions()])
def test_every_revision_id_fits_the_version_column(case) -> None:
    filename, revision = case
    assert len(revision) <= ALEMBIC_VERSION_NUM_LENGTH, (
        f"{filename}: revision id {revision!r} is {len(revision)} characters. "
        f"alembic_version.version_num is VARCHAR({ALEMBIC_VERSION_NUM_LENGTH}), so "
        "this upgrade records itself on SQLite and fails on PostgreSQL."
    )


def test_the_adoption_ladder_names_a_real_revision() -> None:
    """`db._ADOPTION_LADDER` stamps a pre-Alembic database at one of these ids.
    A typo there is a boot failure on a customer's database and on nobody's
    development machine."""
    from app import db

    known = {rev for _f, rev in _revisions()}
    for revision, columns in db._ADOPTION_LADDER:
        assert revision in known, f"{revision} is not a revision in {VERSIONS}"
        assert columns, f"{revision} has no marker columns; it can never match"


def test_every_migration_that_adds_a_column_has_a_ladder_rung() -> None:
    """The ladder's own comment says every column-adding migration adds a rung,
    and forgetting is not cosmetic: a database built by `create_all()` from the
    current models already HAS the column, gets stamped too low, and the next
    upgrade dies on `duplicate column name`. Four tests caught it once; this
    catches it in one.
    """
    from app import db

    rungs = {revision for revision, _c in db._ADOPTION_LADDER}
    missing = []
    for path in sorted(VERSIONS.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "add_column" not in text:
            continue
        match = re.search(r'^revision\s*=\s*"([^"]+)"', text, re.M)
        if not match:
            continue
        revision = match.group(1)
        if revision == db.BASELINE_REVISION:
            continue
        if revision not in rungs:
            missing.append(f"{path.name} ({revision})")
    assert not missing, (
        "these migrations add a column but have no rung in db._ADOPTION_LADDER: "
        + ", ".join(missing)
    )
