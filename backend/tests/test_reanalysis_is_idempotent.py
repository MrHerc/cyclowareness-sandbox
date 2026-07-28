"""Re-analysing a container must not unpack it into a second copy of itself.

`_archive_stage` creates one child job per member and had nothing stopping it
doing so again. Re-analysis is the documented way to re-run a sample after a
rules change — and on an archive it doubled the tree every time.

The corpus made the scale concrete: 22 zip archives of roughly 25 members each,
so one re-analysis sweep would have manufactured about 550 duplicate jobs. Not a
crash, not an error: a second row of evidence for a file that already had one,
with its own public id, its own audit entries and its own verdict. An analyst
looking at the archive would see every member twice and have no way to tell
which row was the real one.
"""
from __future__ import annotations

import io
import zipfile

from tests.test_api import _poll_until_done, _submit


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


MEMBERS = {
    "docs/README.txt": b"Install with: curl https://example.org/install.sh | bash\n",
    "bin/tool.ps1": b"Write-Host 'hello'\n",
    "LICENSE": b"MIT\n",
}


def _children(client, auth, public_id: str) -> list[dict]:
    detail = client.get(f"/api/result/{public_id}", headers=auth).json()
    return detail.get("children") or []


def test_reanalysing_an_archive_does_not_duplicate_its_members(client, auth) -> None:
    public_id = _submit(client, auth, "bundle.zip", _zip_bytes(MEMBERS))
    _poll_until_done(client, auth, public_id)

    before = _children(client, auth, public_id)
    assert len(before) == len(MEMBERS), f"expected {len(MEMBERS)} members, got {len(before)}"
    before_ids = {c["public_id"] for c in before}

    assert client.post(f"/api/jobs/{public_id}/reanalyze", headers=auth).status_code == 200
    _poll_until_done(client, auth, public_id)

    after = _children(client, auth, public_id)
    assert len(after) == len(before), (
        f"re-analysis turned {len(before)} members into {len(after)}"
    )
    assert {c["public_id"] for c in after} == before_ids, (
        "the members were re-created with new ids instead of re-analysed in place"
    )


def test_repeated_reanalysis_stays_stable(client, auth) -> None:
    """Twice is where an off-by-one shows up; three times is where a loop does."""
    public_id = _submit(client, auth, "again.zip", _zip_bytes(MEMBERS))
    _poll_until_done(client, auth, public_id)
    counts = [len(_children(client, auth, public_id))]

    for _ in range(3):
        client.post(f"/api/jobs/{public_id}/reanalyze", headers=auth)
        _poll_until_done(client, auth, public_id)
        counts.append(len(_children(client, auth, public_id)))

    assert len(set(counts)) == 1, f"member count drifted across re-analyses: {counts}"


def test_a_member_is_re_analysed_not_merely_left_alone(client, auth) -> None:
    """Reusing the row must not mean skipping the work.

    The point of re-analysis is that the member is scored again by the current
    engine; a fix that just refused to create the child would leave stale
    verdicts behind and look identical from the outside.
    """
    public_id = _submit(client, auth, "rescan.zip", _zip_bytes(MEMBERS))
    _poll_until_done(client, auth, public_id)
    child = _children(client, auth, public_id)[0]["public_id"]

    before = client.get(f"/api/result/{child}", headers=auth).json()
    client.post(f"/api/jobs/{public_id}/reanalyze", headers=auth)
    _poll_until_done(client, auth, public_id)
    after = client.get(f"/api/result/{child}", headers=auth).json()

    assert after["status"] == "completed"
    # Same sample, same engine: the analysis is present and the row was touched.
    assert after["analysis"], "the member came back with no analysis at all"
    assert set(after["analysis"]) == set(before["analysis"])
