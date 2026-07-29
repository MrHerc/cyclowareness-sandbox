"""Signed, reproducible attestation of a completed analysis.

An analysis is only evidence if a third party can check it without trusting us.
That needs three things, and this module is all three:

1. **An engine manifest.** A verdict is reproducible only if the thing that
   produced it can be pinned. The manifest records the application version, every
   analyzer that loaded and the version of its module, the digest of the YARA
   ruleset, the scoring coefficients and the rule/model split actually in effect,
   the impact-rating notation, the versions of the parser libraries whose output
   feeds the score, and the map of analyzers that did *not* load. Change any one
   of those and the verdict may legitimately differ; the manifest is what lets a
   reviewer see that it did.

2. **A canonical encoding.** ``canonical_bytes`` is a total function from a report
   to bytes: keys sorted, no insignificant whitespace, ASCII-escaped, floats
   rounded to a fixed precision, timestamps normalised to UTC at second
   precision. The same analysis of the same bytes therefore produces the *same
   bytes*, on any host, in any locale, under any dict insertion order. Everything
   else here is built on that; if it drifts, the signature is worthless.

3. **A detached Ed25519 signature** over those bytes, verifiable with nothing but
   the public key and ``tools/verify_report.py``.

**What a signature proves.** That the deployment holding this private key emitted
exactly these bytes, and that not one bit of the report, the manifest or the
engine identification has changed since. That is a chain-of-custody claim, and it
is the whole of the claim.

**What it does not prove.** That the verdict is *correct*. A signature is not a
second opinion: a wrong verdict, honestly signed, is a signed wrong verdict. It
also says nothing about whether the private key is held by whom you think — that
is the operator's key-management problem, and the recipient must obtain the public
key out of band (``GET /api/attestation/pubkey``, or from the contract) rather
than trusting the copy travelling inside the report.

**Reproducibility is scoped, deliberately.** The ``report.reproducible`` section
is byte-identical across submissions of the same bytes under the same manifest —
that is asserted in the test suite. ``report.submission`` is not, and must not be:
it names *this* submission (its id, who sent it, when it completed). Both are
signed; only the first is claimed to be stable, and the digest of it is carried
in ``reproducible_digest`` so two reports can be compared with one string
comparison.

Nothing here executes, opens or re-reads the sample. It reads an already-completed
job row, exactly like the rest of ``report.py``.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.metadata as _metadata
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __version__
from . import analyzers, impact as impact_mod, report as report_mod, scoring
from .contracts import RISK_BANDS

try:  # pragma: no cover - exercised only on a host without the wheel
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except Exception:  # noqa: BLE001
    ed25519 = None  # type: ignore[assignment]

try:
    from .yara_engine import RULES_DIR
except Exception:  # noqa: BLE001 — yara-python missing must not cost the manifest
    RULES_DIR = Path(__file__).resolve().parent / "rules"

#: The signed document's schema. Bump this if the *shape* of what is signed
#: changes, because an old verifier must fail loudly rather than silently check
#: a different document than the one it was written for.
SCHEMA = "cyclowareness-sandbox.attestation/1"

ALGORITHM = "Ed25519"

#: Named in the export so a verifier written against it can refuse anything else.
CANONICALIZATION = "cyclowareness/json-canonical-1"

#: Ed25519 seeds are exactly 32 bytes (RFC 8032). A shorter one is a truncated
#: paste, not a weaker key, and must be refused rather than padded.
SEED_BYTES = 32

#: Floats are rounded here before encoding. Scores carry one decimal and model
#: contributions three; six is comfortably below the point where two runs of the
#: same arithmetic could disagree, and above any precision the engine claims.
FLOAT_PRECISION = 6

#: Per-analyzer fields that record how long something took rather than what was
#: found. They are stripped from the reproducible section: wall-clock timing
#: differs on every run and would make byte-identity impossible to claim.
VOLATILE_ANALYZER_FIELDS = ("duration_ms",)

#: Report keys that describe *this submission* rather than the analysis. They move
#: to ``report.submission``. Note that ``source`` deliberately stays behind: the
#: impact rating reads whether the sample arrived by URL, so it is an input to the
#: verdict, not a submission detail.
SUBMISSION_KEYS = (
    "job_id",
    "submitted_url",
    "status",
    "generated_at",
    # When this submission happened and how long it took. Every one of them is
    # wall-clock and therefore different on every run of the same bytes, so they
    # belong here and nowhere else. They are still SIGNED — `report.submission`
    # is inside the signature — they are simply not part of the half that claims
    # to be byte-identical.
    "submitted_at",
    "started_at",
    "completed_at",
    "duration_ms",
)

#: The parser libraries whose behaviour is an input to the verdict. A YARA or
#: pefile upgrade can legitimately change what a rerun finds, and a reviewer
#: comparing two reports needs to be able to see that before concluding the engine
#: is non-deterministic.
_PINNED_LIBRARIES = ("yara-python", "pefile", "oletools", "pdfminer.six", "puremagic", "stix2")


# ============================================================================
# canonical serialisation
# ============================================================================


def _canonical(value: Any) -> Any:
    """Normalise one value into the small set of types the encoder accepts.

    The normalisation happens *before* ``json.dumps`` rather than inside a custom
    encoder because CPython's C encoder cannot be asked to format floats
    differently — the only reliable way to fix float rendering is to fix the
    values first.
    """
    # bool before int: bool is an int subclass and json must keep it a bool.
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        # NaN and +-Infinity are not JSON. Encoding them anyway (Python's default)
        # produces a document no conforming parser can read back, so a verifier
        # would fail on a report that was never tampered with.
        if not math.isfinite(value):
            return None
        # `+ 0.0` collapses -0.0, which reprs as "-0.0" and would otherwise make
        # two arithmetically identical runs produce different bytes.
        return round(value, FLOAT_PRECISION) + 0.0
    if isinstance(value, datetime):
        # The job row stores naive UTC. Second precision on purpose: SQLite and
        # PostgreSQL do not agree on sub-second storage, and a report that changes
        # bytes when the database engine changes is not a canonical report.
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, dict):
        # Keys are coerced to str: sorting a mix of str and int keys raises, and
        # an unsigned report is worse than a stringified key.
        return {str(k): _canonical(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        # Order is preserved, never sorted — the engine's ordering (worst signal
        # first) is a finding, not an encoding detail.
        return [_canonical(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    return str(value)


def canonical_bytes(document: Any) -> bytes:
    """The one true byte encoding of a report. Deterministic by construction."""
    return json.dumps(
        _canonical(document),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def digest(document: Any) -> str:
    """``sha256:<hex>`` over the canonical bytes — a citable one-line identity."""
    return "sha256:" + hashlib.sha256(canonical_bytes(document)).hexdigest()


# ============================================================================
# engine manifest
# ============================================================================


def ruleset_digest() -> dict[str, Any]:
    """A digest over the YARA rule pack, computed from the files themselves.

    Deliberately not the compiled rules: compilation depends on the installed
    yara-python, so a host that cannot compile would report no ruleset at all,
    and the manifest must still be able to say which rules were on disk.
    """
    files: list[dict[str, str]] = []
    accumulator = hashlib.sha256()
    for path in sorted(Path(RULES_DIR).glob("*.yar")) if Path(RULES_DIR).is_dir() else []:
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        file_hash = hashlib.sha256(raw).hexdigest()
        # Name and content both feed the roll-up, so renaming a rule file changes
        # the digest even when its bytes do not.
        accumulator.update(path.name.encode("utf-8"))
        accumulator.update(file_hash.encode("ascii"))
        files.append({"file": path.name, "sha256": file_hash})
    return {
        "sha256": accumulator.hexdigest(),
        "file_count": len(files),
        "files": files,
    }


def _module_version(module: Any) -> str:
    """A version for a module that almost certainly declares none.

    The analyzers are first-party and carry no ``__version__``, so the digest of
    their source is the version: it is what actually determines their output, and
    it changes exactly when their behaviour can.
    """
    declared = getattr(module, "__version__", None)
    if isinstance(declared, str) and declared:
        return declared
    source = getattr(module, "__file__", None)
    if source:
        try:
            return "src-sha256:" + hashlib.sha256(Path(source).read_bytes()).hexdigest()[:16]
        except OSError:
            pass
    return "unknown"


def _analyzer_manifest() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for entry in analyzers.registry():
        module_name = getattr(entry.fn, "__module__", "")
        entries.append(
            {
                "name": entry.name,
                "module": module_name,
                "families": sorted(entry.families),
                "version": _module_version(sys.modules.get(module_name)),
            }
        )
    entries.sort(key=lambda e: e["name"])
    return entries


def _library_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for name in _PINNED_LIBRARIES:
        try:
            versions[name] = _metadata.version(name)
        except _metadata.PackageNotFoundError:
            # An absent parser is a real difference between two deployments, so
            # it is recorded rather than omitted.
            versions[name] = "not-installed"
    return versions


def engine_manifest() -> dict[str, Any]:
    """Exactly what produced a verdict, in enough detail to reproduce it."""
    manifest = {
        "product": "Cyclowareness Sandbox",
        "app_version": __version__,
        "analyzers": _analyzer_manifest(),
        "unavailable_analyzers": analyzers.unavailable_analyzers(),
        "yara_ruleset": ruleset_digest(),
        "scoring": {
            "model": "expert-weighted logistic (8 features)",
            "feature_weights": dict(scoring.WEIGHTS),
            "bias": scoring.BIAS,
            # The rule/model split is runtime-tunable from the admin UI, so the
            # value in effect at the time of the verdict is recorded, not the
            # default. Two reports that disagree because someone re-weighted the
            # engine must be able to show that.
            "blend": scoring.get_weights(),
            # The bands are what turn a score into the word an analyst reads.
            "risk_bands": [
                {"min_score": threshold, "label": label} for threshold, label in RISK_BANDS
            ],
        },
        "impact_rating": {"notation": impact_mod.NOTATION},
        "libraries": _library_versions(),
    }
    manifest["digest"] = digest(manifest)
    return manifest


# ============================================================================
# the attestation document
# ============================================================================


#: Keys inside a dynamic analyzer's `facts` that identify THIS RUN rather than
#: what the sample did. A CAPE task number is different on every detonation of
#: the same bytes, so leaving it in made `reproducible_digest` — the one field
#: this module exists to let two parties compare with a single string comparison
#: — different every time, which quietly falsifies the module's central claim.
VOLATILE_FACT_KEYS = (
    "task_id", "started_at", "completed_at", "duration_ms", "analysis_started",
    "machine", "guest", "guest_ip", "task_started_on", "task_completed_on",
)

def _clean_facts(facts: Any) -> Any:
    if not isinstance(facts, dict):
        return facts
    return {k: v for k, v in facts.items() if k not in VOLATILE_FACT_KEYS}


def _strip_volatile(analysis: Any) -> Any:
    if not isinstance(analysis, dict):
        return analysis
    cleaned: dict[str, Any] = {}
    for name, payload in analysis.items():
        if isinstance(payload, dict):
            entry = {k: v for k, v in payload.items() if k not in VOLATILE_ANALYZER_FIELDS}
            if "facts" in entry:
                entry["facts"] = _clean_facts(entry["facts"])
            cleaned[name] = entry
        else:
            cleaned[name] = payload
    return cleaned


def build_report(job) -> dict[str, Any]:
    """Split a rendered report into its reproducible half and its submission half.

    Built by *subtraction* from ``report.as_json`` rather than by an allowlist, so
    a finding added to the JSON export cannot be silently missing from the signed
    evidence. The determinism regression test is what catches the opposite
    mistake — a new volatile field leaking into the reproducible half.
    """
    body = report_mod.as_json(job)
    submission = {key: body.pop(key, None) for key in SUBMISSION_KEYS}
    submission["submitted_by"] = getattr(job, "submitted_by", None)
    submission["received_at"] = getattr(job, "created_at", None)
    submission["completed_at"] = getattr(job, "completed_at", None)
    # `generated_at` is when this export was rendered; it is not a fact about the
    # analysis and it must not sit in the half we call reproducible.
    submission["generated_at"] = datetime.now(timezone.utc)

    body["analyzers"] = _strip_volatile(body.get("analyzers"))

    return {
        "reproducible": body,
        "reproducible_digest": digest(body),
        "submission": _canonical(submission),
    }


def build_document(job) -> dict[str, Any]:
    """The sub-document the signature covers: schema, manifest, report."""
    return {"schema": SCHEMA, "manifest": engine_manifest(), "report": build_report(job)}


def signed_payload(envelope: dict[str, Any]) -> bytes:
    """The exact bytes a signature is over, taken from an export envelope.

    A verifier must be able to reconstruct these from the JSON it was handed and
    nothing else, so the payload is precisely three named keys — never "the whole
    response minus the signature", which would change meaning the day a field is
    added beside it.
    """
    return canonical_bytes({key: envelope[key] for key in ("schema", "manifest", "report")})


# ============================================================================
# keys, signing, verification
# ============================================================================


class SigningUnavailable(Exception):
    """No usable signing key. Carries the sentence the report will print."""


def load_private_key(seed_b64: str):
    """An Ed25519 private key from a base64 32-byte seed."""
    if ed25519 is None:
        raise SigningUnavailable(
            "the `cryptography` package is not installed on this host, so no "
            "signature could be produced"
        )
    try:
        seed = base64.b64decode(seed_b64.strip(), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SigningUnavailable("SIGNING_KEY is not valid base64") from exc
    if len(seed) != SEED_BYTES:
        raise SigningUnavailable(
            f"SIGNING_KEY decodes to {len(seed)} bytes; an Ed25519 seed is {SEED_BYTES}"
        )
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def public_key_b64(private_key) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def key_id(public_key: str) -> str:
    """A short, stable label for a key. Derived, so no operator has to name one."""
    return hashlib.sha256(public_key.encode("ascii")).hexdigest()[:16]


def sign(payload: bytes, private_key) -> str:
    return base64.b64encode(private_key.sign(payload)).decode("ascii")


def verify(report_bytes: bytes, signature: str, public_key: str) -> bool:
    """Does ``signature`` cover exactly ``report_bytes`` under ``public_key``?

    Returns False for every failure — bad signature, malformed base64, wrong key
    length. A verifier that raises on malformed input teaches its callers to wrap
    it in ``except: pass``, which is how tampering gets treated as a parse error.
    """
    if ed25519 is None:
        return False
    try:
        raw_key = base64.b64decode(public_key, validate=True)
        raw_signature = base64.b64decode(signature, validate=True)
        loaded = ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
        loaded.verify(raw_signature, report_bytes)
        return True
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 — malformed input is a failed verification
        return False


def deployment_key(settings) -> Any:
    """The configured private key, or None with the reason it is absent.

    Returns ``(key, reason)``. A demo build deliberately does not invent a key:
    an ephemeral per-boot key would produce signatures that verify today and
    against nothing tomorrow, which is a worse lie than saying "unsigned".
    """
    seed = (getattr(settings, "signing_key", "") or "").strip()
    if not seed:
        return None, (
            "No SIGNING_KEY is configured on this deployment, so this report is "
            "UNSIGNED. Its contents are unverified: anyone holding the file could "
            "have altered them. Configure SIGNING_KEY (a base64 32-byte Ed25519 "
            "seed) to produce attributable evidence."
        )
    try:
        return load_private_key(seed), None
    except SigningUnavailable as exc:
        return None, f"This report is UNSIGNED: {exc}."


def attest(job, *, settings) -> dict[str, Any]:
    """The full export: the signed document, its detached signature, and the key.

    When no key is configured the document is still produced in full — the report
    is the point — but ``signed`` is false and ``unsigned_reason`` says so in a
    sentence a reader of the file will understand without knowing our config.
    """
    envelope = build_document(job)
    payload = signed_payload(envelope)

    private_key, reason = deployment_key(settings)
    if private_key is None:
        envelope.update(
            {
                "algorithm": ALGORITHM,
                "canonicalization": CANONICALIZATION,
                "payload_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                "signed": False,
                "signature": None,
                "public_key": None,
                "key_id": None,
                "unsigned_reason": reason,
            }
        )
        return envelope

    public = public_key_b64(private_key)
    envelope.update(
        {
            "algorithm": ALGORITHM,
            "canonicalization": CANONICALIZATION,
            "payload_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "signed": True,
            "signature": sign(payload, private_key),
            "public_key": public,
            "key_id": key_id(public),
            "unsigned_reason": None,
        }
    )
    return envelope


def public_key_info(settings) -> dict[str, Any]:
    """What ``/api/attestation/pubkey`` publishes, signed reports or not."""
    private_key, reason = deployment_key(settings)
    if private_key is None:
        return {
            "algorithm": ALGORITHM,
            "canonicalization": CANONICALIZATION,
            "public_key": None,
            "key_id": None,
            "signing_enabled": False,
            "detail": reason,
        }
    public = public_key_b64(private_key)
    return {
        "algorithm": ALGORITHM,
        "canonicalization": CANONICALIZATION,
        "public_key": public,
        "key_id": key_id(public),
        "signing_enabled": True,
        # Said here as well as in the module docstring: this endpoint is the
        # convenient way to get the key, not the trustworthy one. A recipient who
        # takes the key from the same channel as the report has verified nothing.
        "detail": (
            "Ed25519 public key for this deployment. Verify a signed report with "
            "tools/verify_report.py. For evidentiary use, obtain this key over a "
            "channel independent of the report itself."
        ),
    }
