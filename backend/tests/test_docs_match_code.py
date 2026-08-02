"""Documentation that disagrees with the code, caught mechanically.

An audit of this repository found six served endpoints absent from the API
reference, a queue field added the same day and never documented, a variable the
dynamic tier depends on that appeared in no document at all, a compose file
setting a name nothing reads, and two capabilities described as "deferred" months
after they shipped.

None of that is exotic. It is what happens to prose while code moves, and the
only durable answer is to check it the same way the code is checked. A prose
claim a customer relies on is part of the product: an operator who follows
DEPLOY.md exactly and still sees "no dynamic worker attached" has been given a
defect, not a documentation nit.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
API_DIR = REPO / "backend" / "app" / "api"
API_DOC = REPO / "docs" / "api.md"

MARKDOWN = sorted(
    p for p in REPO.rglob("*.md")
    if "node_modules" not in p.parts and ".git" not in p.parts
    and "frontend/dist" not in p.as_posix()
)


def _served_routes() -> set[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    for path in API_DIR.glob("*.py"):
        src = path.read_text(encoding="utf-8")
        prefix_match = re.search(r'APIRouter\(prefix="([^"]*)"', src)
        prefix = prefix_match.group(1) if prefix_match else ""
        for m in re.finditer(r'@router\.(get|post|delete|put|patch)\("([^"]*)"', src):
            routes.add((m.group(1).upper(), prefix + m.group(2)))
    return routes


ROUTES = sorted(_served_routes())


def test_there_are_routes_to_check() -> None:
    """Guards the guard: a broken parse here would silently pass everything."""
    assert len(ROUTES) >= 20, f"only found {len(ROUTES)} routes — parser broken?"


@pytest.mark.parametrize("verb,route", ROUTES, ids=[f"{v} {r}" for v, r in ROUTES])
def test_every_served_endpoint_is_documented(verb: str, route: str) -> None:
    doc = API_DOC.read_text(encoding="utf-8")
    # Match on the literal part before any path parameter, so
    # /api/result/{public_id} is satisfied by documenting /api/result/.
    stem = route.split("{")[0].rstrip("/")
    assert stem in doc, f"{verb} {route} is served but absent from docs/api.md"


def test_the_queue_contract_documents_every_field_it_returns() -> None:
    """A worker implementer reads this page, not the source."""
    from app.api import dynamic  # noqa: F401

    doc = API_DOC.read_text(encoding="utf-8")
    src = (API_DIR / "dynamic.py").read_text(encoding="utf-8")
    block = src.split("def dynamic_queue", 1)[1].split("def ", 1)[0]
    for field in re.findall(r'"(\w+)":', block):
        assert field in doc, f"queue item field '{field}' is undocumented"


@pytest.mark.parametrize(
    "variable",
    [
        "DYNAMIC_WORKER_TOKEN",
        "SANDBOX_DYNAMIC_WORKER",
        "SANDBOX_QUARANTINE",
        # Decides whether the worker checks containment before detonating at all.
        # An operator who does not know it exists gets no gate, and the only sign
        # is one line at startup.
        "CONTAINMENT_CHECK",
        # Whether the evidence this product exists to produce is signed at all.
        # Unset, every report is stamped UNSIGNED and the audit chain has no
        # anchor — `/api/audit/verify` says `anchored: false`. It appeared in no
        # document and in no .env.example, so an operator following the setup
        # exactly produced an unanchored deployment and had no way to know.
        "SIGNING_KEY",
        # Retention is opt-in and deletes a customer's evidence when it is not.
        # `/api/capabilities` printed "Set SAMPLE_RETENTION_DAYS to bound the
        # malware held on disk" — naming a variable that was documented nowhere.
        "SAMPLE_RETENTION_DAYS",
        "REPORT_RETENTION_DAYS",
        # The one deliberate hole in the sovereignty promise. An air-gapped
        # deployment has to be able to find it in order to close it.
        "SOVEREIGN_ALLOW_URL_FETCH",
        # Copied verbatim into a NIS2 Article 23 / DORA Article 19 record.
        "ENTITY_NAME",
    ],
)
def test_environment_variables_the_product_depends_on_are_documented(variable) -> None:
    """SANDBOX_DYNAMIC_WORKER gated the entire dynamic tier and was in no document.

    An operator could set the documented token, attach a worker, watch it post
    reports, and still read "the sample was not run" on every one of them.

    This list is hand-maintained, which is its weakness: `CONTAINMENT_CHECK` was
    added to the worker and passed this file untouched, because a fixed list
    cannot notice a variable nobody added to it. Add the entry when you add the
    variable.
    """
    where = [p.name for p in MARKDOWN if variable in p.read_text(encoding="utf-8")]
    assert where, f"{variable} is read by the code but documented nowhere"


def test_compose_only_sets_variables_something_reads() -> None:
    """`WORKER_POLL_SECONDS` sat in compose for months and nothing ever read it.

    Two ways a variable is legitimately "read": named literally in our source, or
    declared as a pydantic settings field, which maps `MAX_SAMPLE_MB` to
    `max_sample_mb` without the string ever appearing. Missing the second is how
    the first draft of this test reported a false positive, which is the failure
    mode that gets a test deleted rather than fixed.

    AND THEN THE TEST NEUTRALISED ITSELF. The filter below read
    `"test" not in p.parts` against a directory named `tests`, so it excluded
    nothing: all 107 test files were concatenated into `code`, and `is_read()`
    returned True for any name merely MENTIONED in a test — including in the
    line above, which names `WORKER_POLL_SECONDS`. The test passed for the exact
    variable it was written about, and `docker-compose.yml` went on setting a
    variable the worker never read (it reads `POLL_INTERVAL_SECONDS`,
    `worker/config.py:163`, and kept its 15 s default while compose said 10).

    A guard that cannot fail is worse than no guard: it is a green tick over the
    thing it was supposed to watch.
    """
    compose = REPO / "docker-compose.yml"
    if not compose.exists():  # pragma: no cover
        pytest.skip("no docker-compose.yml")
    code = "\n".join(
        p.read_text(encoding="utf-8")
        for p in (*(REPO / "backend").rglob("*.py"), *(REPO / "worker").rglob("*.py"))
        # `"tests"`, plural: the directory is `backend/tests`, and the singular
        # matched no path part at all.
        if "tests" not in p.parts
    )
    #: Environment belonging to third-party images (Grafana, Prometheus), which
    #: our code has no business reading.
    third_party_prefixes = ("GF_", "PROMETHEUS_", "POSTGRES_", "MONGO_")
    runtime = {"PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "TZ", "PATH", "HOME"}

    def is_read(name: str) -> bool:
        return name in code or re.search(rf"^\s*{name.lower()}\s*:", code, re.M) is not None

    orphans = [
        name
        for name in re.findall(
            r"^\s{6,}([A-Z][A-Z0-9_]{3,}):", compose.read_text(encoding="utf-8"), re.M
        )
        if name not in runtime
        and not name.startswith(third_party_prefixes)
        and not is_read(name)
    ]
    assert not orphans, f"docker-compose sets variables nothing reads: {orphans}"


@pytest.mark.parametrize("doc", MARKDOWN, ids=[p.name for p in MARKDOWN])
def test_markdown_links_to_repository_files_resolve(doc: Path) -> None:
    """A runbook that points at a file which does not exist is not a runbook."""
    text = doc.read_text(encoding="utf-8")
    broken = []
    for target in re.findall(r"\]\(([^)#?]+)\)", text):
        if target.startswith(("http://", "https://", "mailto:", "#", "<")):
            continue
        candidate = (doc.parent / target).resolve()
        if not candidate.exists():
            broken.append(target)
    assert not broken, f"{doc.relative_to(REPO)} links to missing files: {broken}"
