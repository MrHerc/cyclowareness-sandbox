"""Which code-signing authorities this deployment trusts — as data, not policy.

WHY THIS IS A SEPARATE FILE
---------------------------
Chain validation needs a trust store, and the answer is not "use certifi". The
Mozilla bundle is a *TLS* store; measured against the corpus on the detonation
host, the issuers that actually appear over signed software are code-signing
hierarchies that are not in it:

    Microsoft Root Certificate Authority 2011      50 files
    Microsoft Root Certificate Authority            2 files
    DigiCert Assured ID Root CA                     2 files   (also in the TLS bundle)
    DigiCert Trusted G4 Code Signing RSA4096        1 file
    AddTrust External CA Root                       1 file

So a store has to be shipped. For a product whose whole claim is sovereign
evidence, *which certificate authorities we trust* is not a detail to bake into
an engine — it is a statement, and the operator has to be able to read it,
audit it and change it. Hence: a list of fingerprints with their provenance
written next to them, and an operator override.

WHAT AN ANCHOR IS
-----------------
The SHA-256 of an issuing certificate — a root, or an intermediate. Pinning an
INTERMEDIATE is not weaker than pinning its root for this purpose: to forge a
chain to `Microsoft Code Signing PCA 2024`, an attacker needs Microsoft to issue
them a certificate, which is the same barrier as trusting the root above it. It
is also the only option available offline for a root that is not distributed
with the operating system this runs on — the root is not carried inside the
signed file, only the intermediate is.

HOW THE SHIPPED LIST WAS OBTAINED, AND ITS LIMIT
------------------------------------------------
Every fingerprint below was read out of the certificate chain embedded in a
signed binary of the named vendor, on the detonation host, and is recorded here
with the subject it belongs to. That is trust-on-first-use with a hand-checked
anchor: it is honest bootstrapping, **not proof**, and this module does not
pretend otherwise — `describe()` reports `provenance: "bootstrapped"` so the
claim travels with the report instead of living only in a comment.

What CAN be checked offline, and is, by
`tools/verify_trust_anchors.py`:

* every fingerprint is a well-formed SHA-256 and unique;
* every anchor is a real CA certificate that at least one sample chains to;
* no anchor is a timestamping authority, and none has expired;
* the fingerprint recomputes from the certificate bytes, so a typo cannot
  silently disable an anchor (a wrong fingerprint fails open — the chain simply
  stops verifying — which is the quiet failure this catches).

What CANNOT be checked without a network, and is therefore the operator's job
before production: comparing each fingerprint with the authority's own published
thumbprint. Run `tools/verify_trust_anchors.py --print` to get them in a form
that can be diffed against a vendor page.

The list is deliberately short. Adding an authority widens what the engine will
treat as trustworthy, so it is a decision, and it should look like one.

OVERRIDING IT
-------------
Set ``CYCLO_TRUST_ANCHORS`` to a JSON file:

    {"anchors": {"<sha256 hex>": "what it is"}, "replace": false}

``replace: true`` discards the shipped list entirely — an operator who wants to
trust only authorities they chose themselves gets exactly that.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any

logger = logging.getLogger(__name__)

#: sha256 hex -> human description. Written lowercase, without colons.
#:
#: Provenance for every entry is the vendor's own signed binaries as read on the
#: detonation host; see the module docstring before trusting them.
#: The rule the shipped list was selected by, written down because selecting is
#: the decision:
#:
#:   * anchor the HIGHEST certificate the chain actually provides — the
#:     self-signed root when one is present, otherwise the topmost CA. The reason
#:     to anchor an intermediate is that the root above it is neither distributed
#:     with this Linux image nor carried inside the signed file, and that is as
#:     true of Certum, Sectigo and GlobalSign as it is of Microsoft. An earlier
#:     pass allowed a mid-chain anchor only for Microsoft, which was an arbitrary
#:     carve-out and left ILSpy (Certum) and syncthing (Sectigo) unverifiable;
#:   * only from a recognised public code-signing authority, named in the tool
#:     that regenerates this list;
#:   * only within the linked part of the chain — see
#:     `authenticode._links_verified`;
#:   * an EXPIRED authority may still be anchored, and is reported as expired.
#:     This was argued both ways. Excluding them is the tidier rule, and it was
#:     tried: it dropped verification from 94 benign files to 62, because
#:     `Microsoft Code Signing PCA 2011` expired on 2026-07-08 and thirty-two
#:     genuine Microsoft binaries are signed under it. The security gain is
#:     close to nil — expiry does not make the authority's private key more
#:     available, and abusing this anchor still requires a certificate Microsoft
#:     itself issued — while the cost is thirty-two correctly-identified files
#:     losing a waiver that only ever silences STRUCTURAL signals. What would
#:     properly gate an expired anchor is the RFC 3161 countersignature
#:     timestamp, i.e. "was this signed while the authority was valid", which is
#:     what Windows checks and this engine does not yet parse. Until it does,
#:     expiry is reported, not enforced. `UTN-USERFirst-Object` (expired
#:     2020-05-30) is still left out for a different reason: everything under it
#:     is SHA-1 and fails `WEAK_DIGESTS` anyway, so anchoring it buys nothing;
#:   * never a TIMESTAMPING authority. It attests to WHEN, not WHO, and a
#:     hierarchy that can vouch for a time must not be able to vouch for code;
#:   * never a root that arrives inside the artefact it signs. `curl-for-win`
#:     ships its own self-signed "curl-for-win Root CA 2024"; trusting that would
#:     mean any file carrying its own CA is trusted, which is not a check.
SHIPPED_ANCHORS: dict[str, str] = {
    # DigiCert CS RSA4096 Root G5
    #   self-signed root, expires 2046-01-14
    "7353b6d6c2d6da4247773f3f07d075decb5134212bead0928ef1f46115260941":
        "DigiCert CS RSA4096 Root G5",
    # DigiCert Trusted Root G4
    #   self-signed root, expires 2038-01-15
    "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988":
        "DigiCert Trusted Root G4",
    # GlobalSign Code Signing Root R45
    #   self-signed root, expires 2045-03-18
    "7b9d553e1c92cb6e8803e137f4f287d4363757f5d44b37d52f9fca22fb97df86":
        "GlobalSign Code Signing Root R45",
    # Microsoft Identity Verification Root Certificate Authority 2020
    #   self-signed root, expires 2045-04-16
    "5367f20c7ade0e2bca790915056d086b720c33c1fa2a2661acf787e3292e1270":
        "Microsoft Identity Verification Root Certificate Authority 2020",
    # Microsoft Code Signing PCA 2011
    #   intermediate of Microsoft Root Certificate Authority 2011
    #   EXPIRED 2026-07-08 — kept deliberately; see the expiry note above. Thirty
    #   two genuine Microsoft binaries are signed under it, and
    #   `tools/verify_trust_anchors.py` reports the expiry on every run so it
    #   cannot be forgotten. Retire it once the countersignature timestamp is
    #   parsed, or once nothing in the corpus needs it.
    "56da8722afd94066ffe1e4595473a4854892b843a0827d53fb7d8f4aeed1e18b":
        "Microsoft Code Signing PCA 2011",
    # Microsoft Code Signing PCA 2024
    #   intermediate of Microsoft Root Certificate Authority 2011, expires 2036-03-22
    "3dadfaf812dd1bbaef45834ccbd188f3cd97139e2ed1aca69c2dd63082142f8f":
        "Microsoft Code Signing PCA 2024",
    # Microsoft ID Verified Code Signing PCA 2021
    #   intermediate of Microsoft Identity Verification Root CA 2020, expires 2036-04-01
    "3d29798cc5d3f0644a7e0dc9cb1cade523ea5ec83b335109b605bfeaa7d5f5c1":
        "Microsoft ID Verified Code Signing PCA 2021",
    # Microsoft Windows Third Party Component CA 2013
    #   intermediate of Microsoft Root Certificate Authority 2011, expires 2028-05-01
    "8ef01bb5e07987053659e039e5a72580c88c444bc1a31ab412ce81a4ad53044e":
        "Microsoft Windows Third Party Component CA 2013",
    # Certum Trusted Network CA 2
    #   intermediate of Certum Trusted Network CA, expires 2029-09-17
    "08e7eac998a62c4155cc4cbc5eda32f5b41a12c012f29ab3433bd366348149f0":
        "Certum Trusted Network CA 2",
    # Sectigo Public Code Signing CA R36
    #   intermediate of Sectigo Public Code Signing Root R46, expires 2036-03-21
    "7fb0f58d71130abe724969f1cdc9b6a8d3274da18d059229b009a5b9b5557445":
        "Sectigo Public Code Signing CA R36",
}

#: Anchors an operator added, loaded once from CYCLO_TRUST_ANCHORS.
_extra: dict[str, str] | None = None
_replace = False
_lock = threading.Lock()


def _load_override() -> None:
    global _extra, _replace
    _extra, _replace = {}, False
    path = os.environ.get("CYCLO_TRUST_ANCHORS", "").strip()
    if not path:
        return
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except Exception as exc:  # noqa: BLE001 - operator config, never fatal
        logger.warning("trust anchors file %s unusable: %s", path, exc)
        return
    anchors = doc.get("anchors") if isinstance(doc, dict) else None
    if not isinstance(anchors, dict):
        logger.warning("trust anchors file %s has no 'anchors' object", path)
        return
    clean: dict[str, str] = {}
    for key, value in list(anchors.items())[:4096]:
        key = str(key).replace(":", "").replace(" ", "").lower()
        if len(key) == 64 and all(c in "0123456789abcdef" for c in key):
            clean[key] = str(value)[:200]
    _extra = clean
    _replace = bool(doc.get("replace"))
    logger.info(
        "trust anchors: %d from %s (%s shipped list)",
        len(clean), path, "replacing" if _replace else "extending",
    )


def anchors() -> dict[str, str]:
    """The effective anchor set."""
    global _extra
    if _extra is None:
        with _lock:
            if _extra is None:
                _load_override()
    if _replace:
        return dict(_extra or {})
    merged = dict(SHIPPED_ANCHORS)
    merged.update(_extra or {})
    return merged


def reset_cache() -> None:
    """Forget the loaded override. For tests, and for a config reload."""
    global _extra, _replace
    with _lock:
        _extra, _replace = None, False


def anchor_for(chain) -> str:
    """The description of the first certificate in `chain` that is anchored.

    The LEAF is checked too, deliberately: pinning a specific publisher's own
    certificate is a legitimate thing for an operator to want, and refusing it
    here would only push them to do it somewhere worse.
    """
    known = anchors()
    if not known:
        return ""
    try:
        from cryptography.hazmat.primitives import hashes
    except Exception:  # pragma: no cover
        return ""
    for cert in chain or ():
        try:
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        except Exception:
            continue
        found = known.get(fingerprint)
        if found:
            return found
    return ""


def describe() -> dict[str, Any]:
    """What the report and `/api/capabilities` say about the trust store."""
    effective = anchors()
    return {
        "anchors": len(effective),
        "shipped": len(SHIPPED_ANCHORS),
        "operator_supplied": len(_extra or {}),
        "replaced_shipped_list": bool(_replace),
        "source": os.environ.get("CYCLO_TRUST_ANCHORS", "") or "built in",
        # Never implied, always stated: there is no network in this engine.
        "revocation_checked": False,
        # The shipped fingerprints were read from signed binaries of the named
        # vendors, not compared against the authorities' published thumbprints —
        # that needs a network and a person. The claim travels with the report
        # rather than living only in a source comment. An operator who has done
        # the comparison, or who supplies their own list, gets "operator".
        "provenance": "operator" if _replace else "bootstrapped",
    }
