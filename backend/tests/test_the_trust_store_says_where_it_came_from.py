"""The trust store said `provenance: bootstrapped`, and it was right to.

`trust_anchors.py` read every fingerprint out of a certificate chain embedded in
a signed binary on the detonation host. That is trust-on-first-use with a
hand-checked anchor, and the module never pretended otherwise: its docstring
named the missing step — *comparing each fingerprint with the authority's own
published thumbprint* — called it the operator's job before production, and
`describe()` carried `bootstrapped` into every report so the caveat travelled
with the claim instead of living in a comment.

Nobody had done it. It is done now, by `tools/verify_anchor_provenance.py`,
which fetches each anchor from the issuing authority's own distribution point:

    9 of 10   the authority publishes a certificate whose SHA-256 is exactly
              the pinned value — DigiCert x2, GlobalSign, Microsoft x5, Sectigo
    1 of 10   Certum. Its published `Certum Trusted Network CA 2` is SELF-SIGNED
              (b676f2ed…, 2011-2046); the certificate HandBrake carries, and
              therefore the one this list read, is the cross-signed issuance of
              the same name (08e7eac9…, 2021-2029). They share a subject public
              key — sha256 6b3b57e9…, measured, not assumed — so anchoring
              either trusts the same key.

These tests keep the two halves honest: that every shipped anchor has a recorded
confirmation, and that the store drops back to `bootstrapped` the moment one
does not. What is trusted did not change. What the product may SAY about it did.
"""
from __future__ import annotations

import re

import pytest

from app.engine import trust_anchors


def test_every_shipped_anchor_records_where_it_was_confirmed() -> None:
    missing = sorted(
        f"{sha[:16]} {name}"
        for sha, name in trust_anchors.SHIPPED_ANCHORS.items()
        if sha not in trust_anchors.ANCHOR_PROVENANCE
    )
    assert not missing, (
        "an anchor with no recorded confirmation is still bootstrapped, however "
        "carefully it was chosen: " + "; ".join(missing)
    )


def test_the_provenance_table_describes_no_anchor_that_is_not_shipped() -> None:
    """A stale entry would keep `vendor-published` alive after an anchor was
    removed and a new one added — the count would still match."""
    extra = sorted(set(trust_anchors.ANCHOR_PROVENANCE) - set(trust_anchors.SHIPPED_ANCHORS))
    assert not extra, extra


def test_each_confirmation_names_a_url_and_what_matched() -> None:
    for sha, entry in trust_anchors.ANCHOR_PROVENANCE.items():
        assert entry.get("url", "").startswith(("http://", "https://")), sha
        assert entry.get("match"), sha
        # `sha256` is proof; anything else has to say what it is instead.
        assert "sha256" in entry["match"] or "public key" in entry["match"], entry


def test_the_store_reports_that_it_was_checked() -> None:
    described = trust_anchors.describe()
    assert described["provenance"] == "vendor-published", described
    assert described["confirmed_against_authority"] == len(trust_anchors.SHIPPED_ANCHORS)
    # And the thing that has NOT changed, which the report must keep saying.
    assert described["revocation_checked"] is False


def test_an_unconfirmed_anchor_takes_the_whole_store_back_to_bootstrapped(monkeypatch) -> None:
    """A list is only as checked as its least-checked entry.

    The failure this prevents is quiet: someone adds an eleventh authority,
    every existing anchor is still confirmed, and the store goes on reporting
    `vendor-published` over a fingerprint nobody compared with anything.
    """
    shipped = dict(trust_anchors.SHIPPED_ANCHORS)
    shipped["f" * 64] = "Some Authority Nobody Checked"
    monkeypatch.setattr(trust_anchors, "SHIPPED_ANCHORS", shipped)

    described = trust_anchors.describe()
    assert described["provenance"] == "bootstrapped", described
    assert described["confirmed_against_authority"] == len(shipped) - 1


def test_an_operator_supplied_list_is_still_the_operators_claim(monkeypatch) -> None:
    """`replace: true` discards the shipped list, so its confirmations say
    nothing about what is actually loaded.

    BOTH globals are set, and the first version of this test set only
    `_replace` — which made it pass or fail depending on what had run before it.
    `describe()` calls `anchors()` before it reads `_replace`, and `anchors()`
    lazily calls `_load_override()` when `_extra is None`, which assigns
    `_extra, _replace = {}, False`. So a patched `_replace` survived only if
    some earlier test had already triggered the load. Setting `_extra` too is
    also the more faithful fixture: an operator override never produces one
    without the other.
    """
    monkeypatch.setattr(trust_anchors, "_extra", {"a" * 64: "an operator's own anchor"})
    monkeypatch.setattr(trust_anchors, "_replace", True)

    described = trust_anchors.describe()
    assert described["provenance"] == "operator", described
    assert described["replaced_shipped_list"] is True
    assert described["anchors"] == 1, "replace means the shipped list is gone"


def test_the_certum_exception_is_written_down_not_just_true() -> None:
    """The one anchor that does NOT match its authority's published fingerprint
    is the one most likely to be 'tidied up' by someone who does not know why.

    Anyone deleting the cross-certificate explanation has to delete an
    assertion about it too.
    """
    certum = [sha for sha, name in trust_anchors.SHIPPED_ANCHORS.items()
              if "Certum" in name]
    assert len(certum) == 1, certum
    entry = trust_anchors.ANCHOR_PROVENANCE[certum[0]]
    assert "public key" in entry["match"], entry
    assert "cross-signed" in entry["match"], entry


@pytest.mark.parametrize("sha", sorted(trust_anchors.ANCHOR_PROVENANCE))
def test_recorded_fingerprints_are_well_formed(sha) -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", sha), sha


def test_the_tool_that_does_the_checking_is_in_the_repository() -> None:
    """The check needs a network, so it cannot live in the engine — but a check
    that exists only in somebody's shell history is not repeatable, and this
    module's whole argument is that the operator must be able to redo it."""
    import pathlib

    # Walk up rather than counting parents: the module sits at
    # backend/app/engine/ in the repository and at /app/app/engine/ in the
    # image, and a fixed index is right in exactly one of those.
    tool = None
    for parent in pathlib.Path(trust_anchors.__file__).resolve().parents:
        candidate = parent / "tools" / "verify_anchor_provenance.py"
        if candidate.is_file():
            tool = candidate
            break
    assert tool is not None, "tools/verify_anchor_provenance.py is not in the tree"
    source = tool.read_text(encoding="utf-8")
    # It must never report success for something it could not retrieve.
    assert "unconfirmed" in source
    assert "same-key" in source
