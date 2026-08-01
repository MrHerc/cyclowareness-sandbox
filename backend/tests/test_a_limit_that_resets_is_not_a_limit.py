"""Bounds that reset per container bound nothing about the container of containers.

Two of them, found together because they are the same mistake:

* `MAX_TOTAL_EXPANSION` is documented as "one submission" and was a fresh local
  in each of the four archive readers. A nested archive is a separate `unpack`
  on a separate child job, and `MAX_TOTAL_CHILD_JOBS` is 200 — so one upload
  could write 200 x 256 MiB to quarantine.
* OOXML body text was bounded per zip entry (`MAX_ENTRY_BYTES`, 4 MiB) and
  truncated only after every entry had been read and joined. 2,000 entries is
  8 GiB of bytes plus their decoded strings, and XML compresses about 100:1, so
  an 8 MB .docx reaches it.

Neither needs a malicious *sample* to trigger — just a large boring one — which
is why they are tested with ordinary files rather than with a real bomb.
"""
from __future__ import annotations

import io
import os
import zipfile

import pytest

from app.engine import archives
from app.engine.analyzers import office


# --- the expansion budget is the submission's, not the archive's --------------


def _zip_of(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    return buf.getvalue()


def test_one_budget_object_is_spent_by_every_archive_it_is_passed_to(tmp_path) -> None:
    """The finding. Two unpacks sharing a budget must not each get the full one."""
    # Incompressible, so the member clears the bomb-ratio check and the budget
    # is the only thing that can stop it — which is what is under test.
    body = os.urandom(2 * 1024 * 1024)
    for n in (1, 2):
        (tmp_path / f"a{n}.zip").write_bytes(_zip_of({f"m{n}.bin": body}))

    budget = archives.ExpansionBudget(remaining=3 * 1024 * 1024)
    first = archives.unpack(str(tmp_path / "a1.zip"), "application/zip", None, budget)
    second = archives.unpack(str(tmp_path / "a2.zip"), "application/zip", None, budget)

    assert len(first.extracted()) == 1, "the first archive fit and should have been extracted"
    assert second.extracted() == [], "the second archive was handed a spent budget and ignored it"
    assert second.truncated
    assert second.members[0].skipped_reason == "total expansion budget exhausted"


def test_the_budget_left_out_is_a_fresh_one() -> None:
    """A caller unpacking a single container keeps the old, simple contract."""
    assert archives.ExpansionBudget().remaining == archives.MAX_TOTAL_EXPANSION


def test_a_submission_shares_one_expansion_budget_across_its_tree() -> None:
    """The pipeline's per-submission budget object carries it, next to the
    child-job count — one object per tree, both meters on it."""
    from app.engine.pipeline import _ChildBudget

    a, b = _ChildBudget(), _ChildBudget()
    a.expansion.spend(1024)
    assert a.expansion.remaining == archives.MAX_TOTAL_EXPANSION - 1024
    assert b.expansion.remaining == archives.MAX_TOTAL_EXPANSION, (
        "two submissions must not share a budget either"
    )


def test_every_reader_takes_the_budget_rather_than_minting_one() -> None:
    """A reader that still says `budget = MAX_TOTAL_EXPANSION` has reopened it.

    Cheap and blunt on purpose: the defect was four copies of one line, and the
    fifth copy would be added by whoever writes the next format's reader.
    """
    import inspect

    source = inspect.getsource(archives)
    assert "budget = MAX_TOTAL_EXPANSION" not in source, (
        "a reader is minting its own expansion budget again"
    )
    for reader in ("_read_zip", "_read_iso", "_read_7z", "_read_rar"):
        signature = inspect.signature(getattr(archives, reader))
        assert "budget" in signature.parameters, f"{reader} does not take the budget"


# --- OOXML body text is bounded in aggregate ---------------------------------


def test_ooxml_body_text_is_capped_across_every_entry(tmp_path) -> None:
    """The finding: 4 MiB per entry x 2,000 entries, truncated only at the end."""
    part = b"<w:t>" + b"B" * 900_000 + b"</w:t>"
    entries = {"[Content_Types].xml": b"<Types/>"}
    entries.update({f"word/part{n}.xml": part for n in range(40)})
    path = tmp_path / "big.docx"
    path.write_bytes(_zip_of(entries))

    _external, body, *_rest = office._ooxml_relationships_and_body(str(path))

    # 40 x ~900 KB is 36 MB of body text; the aggregate budget is 2 MB.
    assert len(body) <= office.MAX_BODY_BYTES, len(body)


def test_the_body_budget_does_not_stop_the_relationship_walk(tmp_path) -> None:
    """Spending the body budget must not blind the analyzer to the actual
    finding — an external relationship target is the remote-template vector, and
    it is in a .rels part that may sort after a megabyte of body XML."""
    rels = (
        b'<Relationships><Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        b'relationships/attachedTemplate" '
        b'Target="http://evil.example/t.dotm" TargetMode="External"/></Relationships>'
    )
    entries = {f"word/aaa{n}.xml": b"<w:t>" + b"C" * 900_000 + b"</w:t>" for n in range(10)}
    entries["word/_rels/settings.xml.rels"] = rels
    path = tmp_path / "late.docx"
    path.write_bytes(_zip_of(entries))

    external, body, *_rest = office._ooxml_relationships_and_body(str(path))

    assert len(body) <= office.MAX_BODY_BYTES
    assert any("evil.example" in row["target"] for row in external), external


def test_a_short_document_still_gets_all_of_its_text(tmp_path) -> None:
    """The cap must be invisible to a real document."""
    path = tmp_path / "small.docx"
    path.write_bytes(_zip_of({
        "word/document.xml": b"<w:t>contact http://example.com/x for the invoice</w:t>",
    }))

    _external, body, *_rest = office._ooxml_relationships_and_body(str(path))
    assert "http://example.com/x" in body


def test_hyperlink_targets_are_charged_to_the_body_budget(tmp_path) -> None:
    """A .rels part can hold tens of thousands of hyperlink targets, and each one
    was appended to the body window unmetered."""
    link = (
        b'<Relationship Id="r" Type="http://schemas.openxmlformats.org/'
        b'officeDocument/2006/relationships/hyperlink" '
        b'Target="http://example.com/' + b"d" * 1500 + b'" TargetMode="External"/>'
    )
    path = tmp_path / "links.docx"
    path.write_bytes(_zip_of({
        "word/_rels/document.xml.rels": b"<Relationships>" + link * 4000 + b"</Relationships>",
    }))

    _external, body, *_rest = office._ooxml_relationships_and_body(str(path))
    # 4,000 x ~1.5 KB is ~6 MB of targets against a 2 MB budget.
    assert len(body) <= office.MAX_BODY_BYTES + 2000, len(body)


@pytest.mark.parametrize("name", ["MAX_BODY_BYTES", "MAX_ENTRY_BYTES", "MAX_ZIP_ENTRIES"])
def test_the_ooxml_bounds_are_named_constants(name) -> None:
    """So the next person reading `MAX_ENTRY_BYTES` sees the aggregate one too."""
    assert isinstance(getattr(office, name), int)
