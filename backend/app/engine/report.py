"""Cyclowareness Sandbox report rendering: JSON, STIX 2.1, and PDF.

Three exports, one job. Everything here is a *view* of an already-completed
`SandboxJob` row — it reads the persisted analysis (`job.analysis`,
`job.iocs`, `job.tiers`, `job.score_breakdown`) and reshapes it. It never
re-runs an analyzer, never touches the sample on disk, and never executes
anything: the report is downstream of analysis, and the sample is malware.

The one claim this module is most careful about is the tiers claim. A report
that shows a verdict without also stating that dynamic analysis did not run is
claiming more than the engine did, so every format carries the tier record
verbatim and, in the PDF, in a sentence a non-specialist can read.

The job row stores each `AnalyzerResult` as its `to_dict()` shape, so the code
below works on plain dicts, defensively — a missing key is a gap to render, not
a crash.
"""
from __future__ import annotations

import io
import ipaddress
from datetime import datetime, timezone
from typing import Any

from . import impact as impact_mod
from .contracts import SEVERITY_ORDER, risk_level

# --- bounds -------------------------------------------------------------------
#: STIX bundles and PDF tables are bounded so a pathological job (thousands of
#: extracted IOCs) cannot produce a multi-megabyte report or a slow render.
MAX_STIX_INDICATORS = 40
MAX_STIX_ATTACK_PATTERNS = 30
MAX_PDF_IOCS_PER_KIND = 40
MAX_PDF_SIGNALS = 200
MAX_PDF_MEMBERS = 200
MAX_PDF_TECHNIQUES = 30
STR_LIMIT = 300


# ============================================================================
# extraction helpers — all read the persisted job row, defensively
# ============================================================================


def _num(value: Any, default: float = 0.0) -> float:
    """Coerce a score/size field to a float. A NULL numeric column reads back as
    None (the getattr default only fires when the attribute is *absent*), so
    every numeric render goes through this rather than trusting the value."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _utc(value: Any) -> str | None:
    """A timestamp an external system can read without guessing.

    The columns are `timestamp without time zone` holding UTC, so a bare
    `.isoformat()` produces `2026-07-28T13:27:03.382547` — no offset, and
    therefore no way for a reader to know it is not local time. The same instant
    appeared in four different forms across this product's outputs: naive here,
    `+00:00` in the incident export, `Z` in the signed one, epoch-milliseconds in
    CEF. Anything consuming two of them had to know which was which.

    Everything this module emits is UTC with an explicit offset. A value that is
    already aware is converted rather than relabelled, so a future column that
    does carry a zone cannot be silently mis-stamped.
    """
    if not isinstance(value, datetime):
        return None
    aware = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    return aware.astimezone(timezone.utc).isoformat()


def _duration_ms(job) -> int | None:
    """How long the analysis actually took, when both ends are known."""
    started = getattr(job, "started_at", None)
    finished = getattr(job, "completed_at", None)
    if not isinstance(started, datetime) or not isinstance(finished, datetime):
        return None
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    if finished.tzinfo is None:
        finished = finished.replace(tzinfo=timezone.utc)
    delta = (finished - started).total_seconds() * 1000.0
    return int(delta) if delta >= 0 else None


#: Names of the operator's own detonation estate. Not evidence about the sample
#: — evidence about where the sample happened to be run.
#:
#: These exports are the ones that leave the building: the PDF someone attaches
#: to a mail, the incident record a regulator receives, the signed evidence copy
#: sent to an insurer or a partner. Measured on the live deployment,
#: `detonation-01` appeared in 19 of 40 signed exports, which tells a reader the
#: hostname of the machine that runs live malware for this organisation.
#:
#: The ENGINE stays. `capev2` is a real input to the verdict, the manifest
#: exists to pin what produced it, and a reader comparing two reports needs it.
#: What goes is the machine. An operator who needs to know which worker ran a
#: job still sees it in the interface, on `/api/result`, inside their own
#: deployment.
#: Removed from every dict in the payload.
#:
#: `machine` is NOT here, and that is the point. `pe.py` and `elf.py` both
#: use `facts["machine"]` for the sample's target ARCHITECTURE -- AMD64,
#: x86-64, ARM64 -- so a blanket removal deleted a fact about the SAMPLE
#: from export.json and from the signed evidence, because it shares a name
#: with a fact about the infrastructure. Architecture is not incidental
#: here: ARM64 is why CAPE had no matching guest for eleven samples, and it
#: is the first thing an analyst checks when a detonation produced nothing.
_INFRASTRUCTURE_KEYS = ("worker", "hostname", "host", "worker_host", "guest_ip")

#: Removed only from the DYNAMIC tier, where `machine` means "which of our
#: guests ran this" rather than "what this binary was built for".
_DYNAMIC_ONLY_KEYS = ("machine",)


def _infrastructure_names(job) -> tuple[str, ...]:
    """The names this deployment calls its own detonation machines.

    Read off the row rather than configured, because the point is to scrub rows
    that ALREADY contain them: 19 of 40 signed exports on the live deployment
    carried `detonation-01`, and re-analysis does not rewrite a stored sentence.
    """
    names: list[str] = []
    for source in (getattr(job, "dynamic", None), (getattr(job, "tiers", None) or {}).get("dynamic")):
        if isinstance(source, dict):
            for key in _INFRASTRUCTURE_KEYS:
                value = source.get(key)
                if isinstance(value, str) and len(value.strip()) > 2:
                    names.append(value.strip())
    return tuple(dict.fromkeys(names))


def _without_infrastructure(
    value: Any, names: tuple[str, ...] = (), *, extra_keys: tuple[str, ...] = ()
) -> Any:
    drop = _INFRASTRUCTURE_KEYS + extra_keys
    if isinstance(value, dict):
        return {
            k: _without_infrastructure(v, names, extra_keys=extra_keys)
            for k, v in value.items()
            if k not in drop
        }
    if isinstance(value, list):
        return [_without_infrastructure(v, names, extra_keys=extra_keys) for v in value]
    if isinstance(value, str) and names:
        # Key-based removal cannot reach a hostname built into a SENTENCE, and
        # one was: "Detonated on the capev2 worker (detonation-01)." The
        # sentence no longer says it, but rows written before that still do.
        for name in names:
            if name in value:
                value = value.replace(name, "the attached worker")
    return value


def _analysis(job) -> dict[str, Any]:
    value = getattr(job, "analysis", None)
    return value if isinstance(value, dict) else {}


def _ran_results(job) -> list[tuple[str, dict[str, Any]]]:
    return [
        (n, p)
        for n, p in _analysis(job).items()
        if isinstance(p, dict) and p.get("ran")
    ]


def _all_signals(job) -> list[dict[str, Any]]:
    """Every signal across every analyzer that ran, worst severity first."""
    out: list[dict[str, Any]] = []
    for name, payload in _ran_results(job):
        for signal in payload.get("signals", []) or []:
            if isinstance(signal, dict):
                out.append({**signal, "analyzer": name})
    out.sort(key=lambda s: -SEVERITY_ORDER.get(s.get("severity", "info"), 0))
    return out


def _yara_hits(job) -> list[str]:
    """Rule names, gathered from the yara analyzer's facts and yara.* signals."""
    hits: list[str] = []
    yara = _analysis(job).get("yara", {}) or {}
    facts = yara.get("facts", {}) or {}
    for key in ("matches", "rules", "hits"):
        value = facts.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    hits.append(item)
                elif isinstance(item, dict):
                    name = item.get("rule") or item.get("name") or item.get("rule_name")
                    if name:
                        hits.append(str(name))
    for name, payload in _ran_results(job):
        for signal in payload.get("signals", []) or []:
            if not isinstance(signal, dict):
                continue
            if str(signal.get("id", "")).startswith("yara."):
                evidence = signal.get("evidence", {}) or {}
                rule = evidence.get("rule") or evidence.get("rule_name")
                hits.append(str(rule) if rule else str(signal.get("title", signal.get("id"))))
    return list(dict.fromkeys(h[:STR_LIMIT] for h in hits if h))


def _macros(job) -> list[str]:
    """VBA/OLE macro descriptors lifted from any analyzer's facts."""
    macros: list[str] = []
    for _name, payload in _ran_results(job):
        facts = payload.get("facts", {}) or {}
        for key in ("macros", "vba_macros", "macro_streams"):
            value = facts.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        macros.append(item)
                    elif isinstance(item, dict):
                        macros.append(
                            str(item.get("name") or item.get("stream") or item.get("vba") or item)[:STR_LIMIT]
                        )
    return list(dict.fromkeys(macros))


def _behaviors(job) -> list[dict[str, Any]]:
    """Statically-inferred capabilities.

    These are NOT observed dynamic behaviors — nothing was detonated. They are
    the capability-class signals the static analyzers raised (a macro that runs
    on open, an import chain that can inject, a script that downloads and
    executes). The distinction is stated on the report itself.
    """
    from .scoring import _CAPABILITY_PREFIXES

    out: list[dict[str, Any]] = []
    for signal in _all_signals(job):
        sid = str(signal.get("id", ""))
        if any(sid.startswith(prefix) for prefix in _CAPABILITY_PREFIXES):
            out.append(
                {
                    "id": sid,
                    "title": signal.get("title", ""),
                    "severity": signal.get("severity", "info"),
                    "analyzer": signal.get("analyzer", ""),
                }
            )
    return out


def _tiers_summary(job) -> list[dict[str, Any]]:
    """A flat, human-facing 'what ran / what did not and why' list."""
    tiers = getattr(job, "tiers", None) or {}
    summary: list[dict[str, Any]] = []
    for name in ("static", "dynamic"):
        tier = tiers.get(name)
        if not isinstance(tier, dict):
            summary.append({"tier": name, "ran": False, "detail": "not recorded"})
            continue
        summary.append(
            {
                "tier": name,
                "ran": bool(tier.get("ran")),
                "detail": str(tier.get("detail", ""))[:STR_LIMIT],
                "unavailable_analyzers": tier.get("unavailable_analyzers", {}) or {},
            }
        )
    return summary


def _tiers_phrase(job) -> str:
    """"static analysis" / "static and dynamic analysis" / "no analysis tier".

    The sentence an export uses to describe what the assessment rests on, derived
    from the tier record rather than written as a literal.
    """
    ran = [t["tier"] for t in _tiers_summary(job) if t.get("ran")]
    if not ran:
        return "an assessment with no analysis tier recorded"
    return " and ".join(ran) + " analysis"


def _tier_caveats(job) -> list[str]:
    """One sentence per tier that did not run, in the words the JSON export uses."""
    return [
        f"The {t['tier']} analysis tier did not run. Any finding that tier would "
        "have produced is absent from this assessment."
        for t in _tiers_summary(job)
        if not t.get("ran")
    ]


def _archive_tree(job) -> list[dict[str, Any]]:
    archive = _analysis(job).get("archive", {}) or {}
    facts = archive.get("facts", {}) or {}
    members = facts.get("members")
    return members if isinstance(members, list) else []


def _top_reasons(job) -> list[dict[str, Any]]:
    breakdown = getattr(job, "score_breakdown", None) or {}
    reasons = breakdown.get("top_reasons")
    if isinstance(reasons, list) and reasons:
        return reasons
    # Fall back to the three worst signals if scoring did not record reasons.
    return [
        {
            "id": s.get("id"),
            "title": s.get("title"),
            "severity": s.get("severity"),
            "detail": str(s.get("detail", ""))[:STR_LIMIT],
        }
        for s in _all_signals(job)[:3]
    ]


def _what_it_is(job) -> str:
    magic = getattr(job, "magic", "") or "unrecognised content"
    family = getattr(job, "family", "") or "unknown"
    mime = getattr(job, "mime", "") or "application/octet-stream"
    text = f"{magic} ({mime}), classified as family '{family}'."
    if getattr(job, "extension_mismatch", 0):
        text += " Its content does not match its claimed file extension."
    return text


def _verdict(job) -> dict[str, Any]:
    value = getattr(job, "verdict", None)
    return value if isinstance(value, dict) else {}


def _impact(job) -> dict[str, Any]:
    """The Cyclowareness Impact Rating, reading the pre-rename column too.

    The column was called `cvss` until 0003 renamed it. The rename carries the
    values, so a migrated row answers to `impact`; the fallback is for a job
    object reconstructed from a payload exported before the rename, which would
    otherwise render an empty severity panel on an export that clearly has one.
    """
    value = getattr(job, "impact", None)
    if not isinstance(value, dict) or not value:
        value = getattr(job, "cvss", None)
    return value if isinstance(value, dict) else {}


def _mitre(job) -> list[dict[str, Any]]:
    value = getattr(job, "mitre", None)
    if not isinstance(value, list):
        return []
    return [t for t in value if isinstance(t, dict)]


def _assessed_malicious(job) -> bool:
    """Did the engine actually call this sample malicious?

    Only this may license an accusation in an export. The multi-engine verdict
    is the authoritative label; the risk band is the fallback for rows written
    before the verdict column existed, where nothing else records the call.
    """
    label = str(_verdict(job).get("verdict", "") or "").strip().lower()
    if label:
        return label == "malicious"
    return (getattr(job, "risk_level", "low") or "low") in ("high", "critical")


def _attack_url(technique_id: str) -> str:
    """The canonical ATT&CK page for a technique.

    Sub-techniques live under their parent as a path segment ("T1059.001" ->
    /techniques/T1059/001/), not as a dotted id — a TIP that follows the naive
    form gets a 404 instead of the reference the analyst needs.
    """
    parent, _, sub = technique_id.partition(".")
    if sub:
        return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
    return f"https://attack.mitre.org/techniques/{parent}/"


# ============================================================================
# JSON
# ============================================================================


def as_json(job) -> dict:
    """The brief schema plus the full forensic payload.

    SCRUBBED AS A WHOLE, not field by field. Four fields were wrapped in
    `_without_infrastructure` and the rest were not, so `signals`, `top_reasons`
    and the verdict/impact/MITRE blocks still carried "Detonated on the capev2
    worker (detonation-01)" straight out of the building. Wrapping the whole
    payload once means the next field added is covered by default, which is the
    only way a rule like this survives.
    """
    _own_names = _infrastructure_names(job)
    payload = {
        # --- brief-mandated schema ---
        "job_id": getattr(job, "public_id", None),
        "filename": getattr(job, "original_name", "") or "",
        "sha256": getattr(job, "sha256", "") or "",
        "mime": getattr(job, "mime", "") or "",
        "yara_hits": _yara_hits(job),
        "macros": _macros(job),
        "behaviors": _behaviors(job),
        "ai_score": _num(getattr(job, "ai_score", 0.0)),
        "final_score": _num(getattr(job, "final_score", 0.0)),
        "risk_level": getattr(job, "risk_level", "low") or "low",
        # --- analyst-facing assessment ---
        # The verdict, the impact rating and the ATT&CK mapping are the three
        # outputs that go into a case file. They are computed per job and were
        # reaching only the UI, so an exported report was missing the whole
        # assessment; they are carried verbatim so the export and the screen
        # cannot disagree.
        "verdict": _verdict(job),
        "impact": _impact(job),
        "mitre": _mitre(job),
        # --- full detail ---
        "md5": getattr(job, "md5", "") or "",
        "size_bytes": getattr(job, "size_bytes", 0),
        "magic": getattr(job, "magic", "") or "",
        "family": getattr(job, "family", "") or "",
        "extension_mismatch": bool(getattr(job, "extension_mismatch", 0)),
        "source": getattr(job, "source", "") or "",
        "submitted_url": getattr(job, "submitted_url", None),
        "status": getattr(job, "status", "") or "",
        "rule_score": _num(getattr(job, "rule_score", 0.0)),
        "score_breakdown": _without_infrastructure(
            getattr(job, "score_breakdown", None) or {}, _own_names
        ),
        "signals": _all_signals(job),
        # Per analyzer, because `machine` means two different things.
        # In `dynamic.*` it is which of OUR guests ran the sample; in `pe`
        # and `elf` it is the sample's own target architecture, and
        # deleting that from the evidence loses the first thing an analyst
        # checks when a detonation produced nothing.
        "analyzers": {
            name: _without_infrastructure(
                payload, _own_names,
                extra_keys=_DYNAMIC_ONLY_KEYS if name.startswith("dynamic.") else (),
            )
            for name, payload in _analysis(job).items()
        },
        "iocs": getattr(job, "iocs", None) or {},
        # The tiers are where `machine` means one of OUR guests.
        "tiers": _without_infrastructure(
            getattr(job, "tiers", None) or {}, _own_names,
            extra_keys=_DYNAMIC_ONLY_KEYS),
        "tiers_summary": _without_infrastructure(
            _tiers_summary(job), _own_names, extra_keys=_DYNAMIC_ONLY_KEYS),
        "top_reasons": _top_reasons(job),
        "archive_tree": _archive_tree(job),
        # WHEN, not just what.
        #
        # The only time in this export was `generated_at` — the instant the
        # button was pressed. An evidence document that cannot say when the
        # sample was received or when the analysis finished is not evidence; it
        # is a screenshot with a clock on it. Every incident timeline, every
        # "what did you know and when" question, and every correlation with
        # another system's logs needs these three.
        # WHETHER THE EVIDENCE STILL EXISTS.
        #
        # `retention.sweep` deletes the quarantined bytes and stamps
        # `sample_deleted_at`, and the only reader of that column anywhere was
        # the dynamic ingest. So an evidence document went on publishing a
        # SHA-256 and inviting the reader to check it against the original,
        # while the original had been deleted by policy and nothing said so.
        # "We hold the file" and "we hold a hash of a file we no longer have"
        # are different claims.
        "sample_retained": getattr(job, "sample_deleted_at", None) is None,
        "sample_deleted_at": _utc(getattr(job, "sample_deleted_at", None)),
        "submitted_at": _utc(getattr(job, "created_at", None)),
        "started_at": _utc(getattr(job, "started_at", None)),
        "completed_at": _utc(getattr(job, "completed_at", None)),
        "duration_ms": _duration_ms(job),
        "generated_at": _utc(datetime.now(timezone.utc)),
        "schema": "cyclowareness-sandbox.report/1",
    }
    return _without_infrastructure(payload, _own_names)


# ============================================================================
# STIX 2.1
# ============================================================================


def _stix_escape(value: str) -> str:
    """Escape a value for a STIX string literal (single-quoted)."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _ioc_patterns(iocs: dict[str, list[str]]) -> list[tuple[str, str, str]]:
    """Build (pattern, kind, value) tuples for the top IOCs, most-useful first.

    Order matters: network indicators are the most actionable, so they lead and
    fill the bounded indicator budget before file paths and mutexes.
    """
    def pat_url(v: str) -> str:
        return f"[url:value = '{_stix_escape(v)}']"

    def pat_domain(v: str) -> str:
        return f"[domain-name:value = '{_stix_escape(v)}']"

    def pat_ip(v: str) -> str:
        # AN IPv6 ADDRESS IS NOT AN ipv4-addr. Every extracted IP was emitted as
        # `ipv4-addr`, so a bundle carrying `2001:db8::1` published a pattern
        # matching an object type that can never hold that value — silently
        # unmatchable in every TIP that ingests it, and wrong in a document whose
        # whole claim is that the spec is enforced for us.
        return f"[{_ip_type(v)}:value = '{_stix_escape(v)}']"

    def pat_email(v: str) -> str:
        return f"[email-addr:value = '{_stix_escape(v)}']"

    def pat_hash(v: str) -> str:
        algo = "SHA-256" if len(v) == 64 else "MD5" if len(v) == 32 else "SHA-1"
        return f"[file:hashes.'{algo}' = '{_stix_escape(v)}']"

    builders = [
        ("urls", "url", pat_url),
        ("domains", "domain-name", pat_domain),
        # The per-value type is decided in `_ip_kind`, below; "ip" is the marker
        # that this row is version-dependent rather than a STIX type name.
        ("ips", "ip", pat_ip),
        ("emails", "email-addr", pat_email),
        ("hashes", "file", pat_hash),
    ]

    out: list[tuple[str, str, str]] = []
    for field_name, kind, builder in builders:
        for value in iocs.get(field_name, []) or []:
            if not isinstance(value, str) or not value.strip():
                continue
            value = value.strip()[:STR_LIMIT]
            if _is_own_infrastructure(value):
                continue
            out.append((builder(value), kind, value))
            if len(out) >= MAX_STIX_INDICATORS:
                return out
    return out


def _is_own_infrastructure(value: str) -> bool:
    """Is this address the sandbox itself rather than anything the sample chose?

    A detonation guest talks to its own gateway, its sinkhole and its result
    server before it talks to anything a malware author picked, so those
    addresses come back in every report from every sample. Published as an
    Indicator with `indicator_types=["malicious-activity"]`, they are an
    accusation a TIP turns straight into a blocklist entry.

    Measured on this deployment: `192.168.122.1` — the operator's own libvirt
    bridge — was exported as a malicious indicator by 4 of the first 25
    malicious samples checked. Acting on that bundle blocks the analyst's own
    virtualisation host, and the value is not evidence about the sample in any
    case: it is evidence about where the sample was detonated.

    Suppressed for the whole RFC 1918 / loopback / link-local space rather than
    for a list of this host's addresses, because the sandbox network is private
    by construction and a public address is the only kind that can be an IOC
    about someone else's infrastructure. Kept in `job.iocs` — an analyst reading
    the report should still see what the sample contacted; what changes is that
    this deployment no longer publishes it to the world as malicious.
    """
    host = value.strip()
    # A bare address, or the host part of a URL — the only two shapes an
    # address-like IOC arrives in here.
    if "//" in host:
        host = host.split("//", 1)[1]
    host = host.split("/", 1)[0].split("@")[-1]
    if host.startswith("["):
        # `[fd00::1]:8080` — an IPv6 literal with a port. Taking everything up
        # to the bracket is the only way to tell the port's colon from the
        # address's; stripping brackets first leaves `fd00::1]:8080`.
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _ip_type(value: str) -> str:
    """`ipv6-addr` or `ipv4-addr` — the STIX type this address actually is.

    Defaults to v4 for anything unparseable rather than raising: the caller has
    already accepted the string as an IOC, and a report must not fail to export
    because one extracted value was malformed.
    """
    try:
        return "ipv6-addr" if ipaddress.ip_address(value).version == 6 else "ipv4-addr"
    except ValueError:
        return "ipv4-addr"


def _observable(stix, kind: str, value: str):
    """The SCO for an IOC — the fact that the sample contained this value.

    An SCO carries no assessment, which is the point: it is what we publish for
    a sample we did not call malicious.
    """
    if kind == "url":
        return stix.URL(value=value)
    if kind == "domain-name":
        return stix.DomainName(value=value)
    if kind in ("ip", "ipv4-addr", "ipv6-addr"):
        return (
            stix.IPv6Address(value=value)
            if _ip_type(value) == "ipv6-addr"
            else stix.IPv4Address(value=value)
        )
    if kind == "email-addr":
        return stix.EmailAddress(value=value)
    if kind == "file":
        algo = "SHA-256" if len(value) == 64 else "MD5" if len(value) == 32 else "SHA-1"
        return stix.File(hashes={algo: value})
    return None


def as_stix(job) -> dict:
    """A STIX 2.1 bundle: file observable, indicators, malware, relationships.

    Built with the `stix2` library so the spec is enforced for us — an invalid
    pattern or a malformed object raises here rather than shipping a bundle that
    only looks like STIX.
    """
    import stix2

    sha256 = getattr(job, "sha256", "") or ""
    md5 = getattr(job, "md5", "") or ""
    risk = getattr(job, "risk_level", "low") or "low"
    score = _num(getattr(job, "final_score", 0.0))
    filename = str(getattr(job, "original_name", "") or "sample")[:STR_LIMIT]

    objects: list[Any] = []

    # --- file observable (SCO) with hashes ---
    hashes: dict[str, str] = {}
    if sha256:
        hashes["SHA-256"] = sha256
    if md5:
        hashes["MD5"] = md5
    file_kwargs: dict[str, Any] = {"name": filename}
    if hashes:
        file_kwargs["hashes"] = hashes
    size = getattr(job, "size_bytes", 0)
    if isinstance(size, int) and size > 0:
        file_kwargs["size"] = size
    file_obs = stix2.File(**file_kwargs)
    objects.append(file_obs)

    # --- the impact rating, as a Note on the file ---
    # STIX has no field for a severity of our own, and putting the number in an
    # indicator or a malware description would make it look like a scored
    # vulnerability to whatever ingests the bundle. A Note is the object that
    # says "here is an assessment, attached to this file" without asserting
    # anything the spec would reinterpret, and it carries the disclaimer with it.
    impact = _impact(job)
    if impact.get("vector"):
        objects.append(
            stix2.Note(
                abstract=(
                    f"Cyclowareness Impact Rating (CIR v1): "
                    f"{_num(impact.get('base_score', 0.0)):.1f} "
                    f"({str(impact.get('severity', 'none') or 'none')})"
                )[:STR_LIMIT],
                content=f"{impact['vector']}\n\n{impact_mod.DISCLAIMER}"[:STR_LIMIT * 4],
                object_refs=[file_obs.id],
            )
        )

    # --- the tier record, as a Note on the file ---
    # A bundle is ingested by a machine and then read by a person deciding what
    # to act on, and neither could see that a tier had not run. The blind spot is
    # part of the assessment, so it travels with it.
    # SCRUBBED, like every other export. This one built the Note from a raw
    # `_tiers_summary`, so the detonation host's name travelled in the
    # export most likely to be handed to a third party.
    tier_lines = [
        f"{t['tier']}: {'ran' if t.get('ran') else 'did not run'}"
        + (f" - {t['detail']}" if t.get("detail") else "")
        for t in _without_infrastructure(
            _tiers_summary(job), _infrastructure_names(job),
            extra_keys=_DYNAMIC_ONLY_KEYS)
    ]
    objects.append(
        stix2.Note(
            abstract=f"Analysis tiers: {_tiers_phrase(job)}"[:STR_LIMIT],
            content="\n".join(tier_lines + _tier_caveats(job))[:STR_LIMIT * 4],
            object_refs=[file_obs.id],
        )
    )

    # --- malware SDO, only when the verdict warrants naming one ---
    # Naming malware is a claim, so it follows the engine's own verdict rather
    # than the risk band alone: a high score with no demonstrated capability is
    # "suspicious", and publishing a malware SDO for it asserts more than the
    # engine concluded.
    verdict = _verdict(job)
    malicious = _assessed_malicious(job)
    threat_name = str(verdict.get("threat_name", "") or "").strip()[:STR_LIMIT]
    malware = None
    if malicious:
        family = getattr(job, "family", "") or "unknown"
        ratio = str(verdict.get("detection_ratio", "") or "n/a")
        # WHICH TIERS ACTUALLY RAN. This said "static analysis" unconditionally,
        # in the one export designed to be machine-ingested and forwarded. Every
        # other format in this module carries the tier record verbatim, and the
        # module docstring says that is the claim it is most careful about — so
        # a bundle asserting a detonation-free assessment for a detonated sample,
        # or the reverse, was the exception nobody could see.
        malware = stix2.Malware(
            name=threat_name or f"Cyclowareness Sandbox-detected sample ({family})",
            is_family=False,
            description=(
                f"Sample assessed by Cyclowareness Sandbox {_tiers_phrase(job)} as {risk} risk "
                f"(score {score:.0f}/100), detection ratio {ratio}. Family: {family}."
            )[:STR_LIMIT],
        )
        objects.append(malware)
        # Tie the named malware to the observed file.
        objects.append(
            stix2.Relationship(
                relationship_type="consists-of",
                source_ref=malware.id,
                target_ref=file_obs.id,
            )
        )

    # --- ATT&CK techniques as attack-pattern SDOs ---
    # The mapped techniques are a statement about this sample's own evidence, so
    # they are exported whatever the verdict; only the link to a named malware
    # is gated. Without them the bundle dropped the entire ATT&CK mapping, which
    # is the part a SOC actually pivots on.
    for technique in _mitre(job)[:MAX_STIX_ATTACK_PATTERNS]:
        tid = str(technique.get("technique_id", "") or "").strip()
        if not tid:
            continue
        tactic = str(technique.get("tactic", "") or "").strip()
        evidence = [str(e) for e in (technique.get("evidence") or []) if e]
        kwargs: dict[str, Any] = {
            "name": str(technique.get("name") or tid)[:STR_LIMIT],
            "external_references": [
                stix2.ExternalReference(
                    source_name="mitre-attack",
                    external_id=tid,
                    url=_attack_url(tid),
                )
            ],
        }
        if evidence:
            kwargs["description"] = f"Mapped from signals: {', '.join(evidence)}"[:STR_LIMIT]
        if tactic:
            kwargs["kill_chain_phases"] = [
                stix2.KillChainPhase(
                    kill_chain_name="mitre-attack",
                    phase_name=tactic.lower().replace(" ", "-"),
                )
            ]
        try:
            attack_pattern = stix2.AttackPattern(**kwargs)
        except Exception:
            # A malformed mapping row is dropped rather than sinking the bundle.
            continue
        objects.append(attack_pattern)
        if malware is not None:
            objects.append(
                stix2.Relationship(
                    relationship_type="uses",
                    source_ref=malware.id,
                    target_ref=attack_pattern.id,
                )
            )

    # --- the extracted IOCs ---
    # An Indicator with indicator_types=["malicious-activity"] is an accusation,
    # and a TIP turns it straight into a blocklist entry. Emitting one per IOC
    # regardless of verdict meant analysing notepad.exe published
    # go.microsoft.com as malicious, and a benign JPEG published seven junk
    # domains. Accusations now require the sample itself to have been assessed
    # malicious; everything else ships as observed-data — the fact that the file
    # contained these values, with no claim attached.
    iocs = getattr(job, "iocs", None) or {}
    ioc_rows = _ioc_patterns(iocs)
    if malicious:
        for pattern, _kind, value in ioc_rows:
            try:
                indicator = stix2.Indicator(
                    name=f"Cyclowareness Sandbox IOC: {value}"[:STR_LIMIT],
                    pattern=pattern,
                    pattern_type="stix",
                    indicator_types=["malicious-activity"],
                )
            except Exception:
                # A pathological IOC that will not form a valid pattern is
                # dropped, not allowed to sink the whole bundle.
                continue
            objects.append(indicator)
            if malware is not None:
                objects.append(
                    stix2.Relationship(
                        relationship_type="indicates",
                        source_ref=indicator.id,
                        target_ref=malware.id,
                    )
                )
    # WHEN THIS WAS SEEN — for every verdict, not just the benign one.
    #
    # The ObservedData below used to live in an `elif`, so it was emitted only
    # when the sample was NOT malicious. A malicious bundle therefore carried no
    # observed-data object at all, and with it no timestamp of any kind: the one
    # export a SOC ingests, describing the one sample they care about most, with
    # nothing in it saying when. An Indicator is a claim and ObservedData is a
    # sighting; STIX expects both, and a TIP correlating this against its own
    # telemetry needs the sighting to have a time.
    #
    # The file itself is always observed. The IOC values are added as observables
    # only where they were before — when the sample is not malicious and so ships
    # as sightings rather than accusations; in the malicious bundle each value is
    # already carried by its Indicator's pattern, and duplicating it there would
    # grow the bundle without telling a reader anything new.
    #
    # SCO ids are deterministic, so the same value twice would put a duplicate
    # object in the bundle.
    observed_refs: list[str] = [file_obs.id]
    if not malicious:
        for _pattern, kind, value in ioc_rows:
            try:
                sco = _observable(stix2, kind, value)
            except Exception:
                continue
            if sco is None or sco.id in observed_refs:
                continue
            objects.append(sco)
            observed_refs.append(sco.id)

    seen = getattr(job, "created_at", None)
    if not isinstance(seen, datetime):
        seen = datetime.now(timezone.utc)
    elif seen.tzinfo is None:
        # The job row stores naive UTC; STIX timestamps must be offset-aware.
        seen = seen.replace(tzinfo=timezone.utc)
    objects.append(
        stix2.ObservedData(
            first_observed=seen,
            last_observed=seen,
            number_observed=1,
            object_refs=observed_refs,
        )
    )

    bundle = stix2.Bundle(objects=objects, allow_custom=False)
    # Serialize through the library and back so the return is a plain JSON dict,
    # exactly what round-trips through stix2.parse().
    import json as _json

    return _json.loads(bundle.serialize())


# ============================================================================
# PDF
# ============================================================================

_RISK_RGB = {
    "critical": (0.62, 0.10, 0.10),
    "high": (0.78, 0.35, 0.06),
    "medium": (0.70, 0.55, 0.05),
    "low": (0.20, 0.45, 0.25),
}


def _sev_color(severity: str):
    from reportlab.lib import colors

    r, g, b = _RISK_RGB.get(severity, (0.30, 0.30, 0.30))
    return colors.Color(r, g, b)


#: Which band's colour a verdict word borrows. The palette is indexed by
#: severity, and the verdict vocabulary is a different one — without this the
#: page-one box fell through to the default grey for every job.
_VERDICT_TONE = {"malicious": "critical", "suspicious": "medium", "clean": "low"}


def _band_text() -> str:
    """The risk bands, read from the table that defines them.

    Restated as a literal in the PDF, which is how a document ends up describing
    thresholds the engine no longer uses.
    """
    from .contracts import RISK_BANDS

    bands = sorted(RISK_BANDS)  # ascending by threshold
    parts = []
    for index, (low, label) in enumerate(bands):
        high = bands[index + 1][0] - 1 if index + 1 < len(bands) else 100
        parts.append(f"{low}–{high} {label}")
    return ", ".join(parts)


def _score_formula(job) -> str:
    """The formula THIS job was scored with, not the one in the source at build time.

    `assess()` stores it on the row from the live weights, which the admin API can
    change. Rows written before that field existed fall back to the shipped
    default, stated as such.
    """
    stored = (getattr(job, "score_breakdown", None) or {}).get("formula")
    if isinstance(stored, str) and stored.strip():
        return stored.strip()
    return "final = 0.6 x rule + 0.4 x model (deployment default)"


def as_pdf(job) -> bytes:
    """Executive summary on page one, technical annex after it."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Cyclowareness Sandbox Analysis Report",
        author="Cyclowareness Sandbox static analysis engine",
    )

    styles = getSampleStyleSheet()
    ink = colors.Color(0.12, 0.12, 0.14)
    muted = colors.Color(0.40, 0.40, 0.44)
    h1 = ParagraphStyle("z-h1", parent=styles["Heading1"], fontSize=20, textColor=ink, spaceAfter=2)
    h2 = ParagraphStyle("z-h2", parent=styles["Heading2"], fontSize=13, textColor=ink, spaceBefore=12, spaceAfter=4)
    body = ParagraphStyle("z-body", parent=styles["BodyText"], fontSize=9.5, leading=13, textColor=ink, alignment=TA_LEFT)
    small = ParagraphStyle("z-small", parent=body, fontSize=8, textColor=muted)
    mono = ParagraphStyle("z-mono", parent=body, fontName="Courier", fontSize=8)

    def esc(text: Any) -> str:
        s = str(text) if text is not None else ""
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    risk = getattr(job, "risk_level", "low") or "low"
    score = _num(getattr(job, "final_score", 0.0))
    rule_s = _num(getattr(job, "rule_score", 0.0))
    ai_s = _num(getattr(job, "ai_score", 0.0))

    flow: list[Any] = []

    # ---- Executive summary (page 1) ----
    flow.append(Paragraph("Cyclowareness Sandbox Analysis Report", h1))
    flow.append(Paragraph("Static analysis engine &mdash; executive summary", small))
    flow.append(Spacer(1, 6))
    flow.append(HRFlowable(width="100%", thickness=0.6, color=colors.Color(0.8, 0.8, 0.82)))
    flow.append(Spacer(1, 8))

    # THE BOX LABELLED "VERDICT" PRINTS THE VERDICT.
    #
    # It printed the risk band. Those are different statements and the product
    # says so everywhere else: the band is a number bucketed into four words,
    # the verdict is the engine's judgement after corroboration, publisher
    # verification and the ambient rules. A signed installer at 61 read "VERDICT:
    # HIGH" on page one of an exported PDF while the engine's verdict, printed
    # three pages later, was `clean`. Whichever is right, a document cannot say
    # both.
    #
    # A job that never reached a verdict still has a band, so the band is the
    # fallback — the same rule the UI applies.
    verdict_word = (_verdict(job).get("verdict") or "").strip()
    verdict_tbl = Table(
        [
            [
                Paragraph("VERDICT" if verdict_word else "RISK BAND", small),
                Paragraph("SCORE", small),
                Paragraph("RULE / AI", small),
            ],
            [
                Paragraph(
                    f"<b>{esc((verdict_word or risk).upper())}</b>",
                    ParagraphStyle("v", parent=body, fontSize=16,
                                   textColor=_sev_color(_VERDICT_TONE.get(verdict_word, risk))),
                ),
                Paragraph(f"<b>{score:.0f}</b> / 100", ParagraphStyle("s", parent=body, fontSize=16, textColor=ink)),
                Paragraph(f"{rule_s:.0f} / {ai_s:.0f}", ParagraphStyle("r", parent=body, fontSize=16, textColor=ink)),
            ],
        ],
        colWidths=[57 * mm, 57 * mm, 56 * mm],
    )
    verdict_tbl.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, colors.Color(0.8, 0.8, 0.82)),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.Color(0.88, 0.88, 0.9)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    flow.append(verdict_tbl)
    flow.append(Spacer(1, 4))
    flow.append(
        Paragraph(
            # THE WEIGHTS ARE TUNABLE AT RUNTIME. `assess()` already stores the
            # formula it actually used on the row, so print that rather than a
            # literal: an operator who moved the split via the admin API got a
            # PDF stating the old one, and a reader reproducing the arithmetic
            # from the printed formula got a different number than the printed
            # score. The literal is the fallback for rows written before the
            # field existed.
            f"Risk bands: {esc(_band_text())}. "
            f"Score: {esc(_score_formula(job))}. "
            f"The model is expert-weighted, not corpus-trained.",
            small,
        )
    )

    flow.append(Paragraph("What it is", h2))
    flow.append(Paragraph(esc(_what_it_is(job)), body))
    flow.append(Paragraph(f"SHA-256: {esc(getattr(job, 'sha256', ''))}", mono))
    flow.append(Paragraph(f"File name (as submitted): {esc(getattr(job, 'original_name', '') or '(none)')}", small))

    # The three analyst-facing outputs. The engine computed all of them and the
    # PDF showed none, so an exported case file carried no threat name, no impact
    # rating and no ATT&CK mapping — the report was strictly worse than the screen.
    verdict = _verdict(job)
    impact = _impact(job)
    techniques = _mitre(job)
    if verdict or impact or techniques:
        flow.append(Paragraph("Threat classification and severity", h2))
    if verdict:
        label = str(verdict.get("verdict", "unknown") or "unknown")
        label_color = _sev_color(
            {"malicious": "critical", "suspicious": "medium", "clean": "low"}.get(label, "info")
        )
        flow.append(
            Paragraph(
                f"<b>Verdict:</b> <b><font color='{label_color.hexval()}'>{esc(label.upper())}</font></b> "
                f"&mdash; {esc(verdict.get('threat_name') or 'unnamed')} "
                f"(detection ratio {esc(verdict.get('detection_ratio') or 'n/a')})",
                body,
            )
        )
    if impact:
        impact_score = _num(impact.get("base_score", 0.0))
        impact_sev = str(impact.get("severity", "none") or "none")
        flow.append(
            Paragraph(
                f"<b>Cyclowareness Impact Rating (CIR v1):</b> <b>{impact_score:.1f}</b> "
                f"({esc(impact_sev.upper())})",
                body,
            )
        )
        flow.append(Paragraph(esc(impact.get("vector", "")), mono))
        flow.append(
            Paragraph(
                esc(impact_mod.DISCLAIMER)
                + " The reason for each metric is carried in the JSON export, and the full "
                "rubric is published in docs/impact-rating.md.",
                small,
            )
        )
    if techniques:
        flow.append(Paragraph("<b>MITRE ATT&amp;CK techniques</b>", body))
        for technique in techniques[:MAX_PDF_TECHNIQUES]:
            flow.append(
                Paragraph(
                    f"&bull; <b>{esc(technique.get('technique_id', ''))}</b> "
                    f"{esc(technique.get('name', ''))} &mdash; {esc(technique.get('tactic', ''))}",
                    small,
                )
            )
        if len(techniques) > MAX_PDF_TECHNIQUES:
            flow.append(Paragraph(f"&hellip; and {len(techniques) - MAX_PDF_TECHNIQUES} more", small))

    flow.append(Paragraph("Top reasons for this verdict", h2))
    reasons = _top_reasons(job)
    if reasons:
        for i, reason in enumerate(reasons[:3], 1):
            sev = reason.get("severity") or "info"
            title = esc(reason.get("title") or reason.get("id") or "")
            detail = esc(reason.get("detail") or "")
            flow.append(
                Paragraph(
                    f"<b>{i}. <font color='{_sev_color(sev).hexval()}'>{esc(sev.upper())}</font></b> &mdash; {title}",
                    body,
                )
            )
            if detail:
                flow.append(Paragraph(detail, small))
            flow.append(Spacer(1, 2))
    else:
        flow.append(Paragraph("No signals fired. Nothing was found &mdash; which is not the same as a guarantee of safety.", body))

    # The tiers claim — stated plainly on page one.
    flow.append(Paragraph("What was and was not analysed", h2))
    for tier in _tiers_summary(job):
        state = "ran" if tier["ran"] else "DID NOT RUN"
        color = _sev_color("low") if tier["ran"] else _sev_color("high")
        flow.append(
            Paragraph(
                f"<b><font color='{color.hexval()}'>{esc(tier['tier'].capitalize())} analysis: {state}.</font></b> "
                f"{esc(tier.get('detail', ''))}",
                body,
            )
        )
    flow.append(Spacer(1, 4))
    flow.append(
        Paragraph(
            "This verdict rests on static analysis only unless the dynamic tier is marked as run above. "
            "A static verdict has a stated blind spot: it did not observe the sample execute.",
            small,
        )
    )

    # ---- Technical annex (page 2+) ----
    flow.append(PageBreak())
    flow.append(Paragraph("Technical annex", h1))
    flow.append(Paragraph("Complete findings for an analyst.", small))
    flow.append(Spacer(1, 6))

    # File identity table
    flow.append(Paragraph("File identity", h2))
    ident_rows = [
        ["Job id", esc(getattr(job, "public_id", ""))],
        ["SHA-256", esc(getattr(job, "sha256", ""))],
        ["MD5", esc(getattr(job, "md5", ""))],
        ["Size (bytes)", esc(getattr(job, "size_bytes", 0))],
        ["MIME", esc(getattr(job, "mime", ""))],
        ["Magic", esc(getattr(job, "magic", ""))],
        ["Family", esc(getattr(job, "family", ""))],
        ["Extension mismatch", "yes" if getattr(job, "extension_mismatch", 0) else "no"],
    ]
    flow.append(_kv_table(ident_rows, mono, body, colors))

    # Per-analyzer signals
    flow.append(Paragraph("Per-analyzer results", h2))
    analysis = _analysis(job)
    if not analysis:
        flow.append(Paragraph("No analyzer results recorded.", body))
    for name, payload in analysis.items():
        payload = payload if isinstance(payload, dict) else {}
        if payload.get("ran"):
            sigs = payload.get("signals", []) or []
            header = f"<b>{esc(name)}</b> &mdash; ran, {len(sigs)} signal(s)"
        else:
            header = f"<b>{esc(name)}</b> &mdash; <font color='{_sev_color('high').hexval()}'>did not run</font>: {esc(payload.get('unavailable_reason', 'no reason given'))}"
        flow.append(Paragraph(header, body))
        sigs = payload.get("signals", []) or [] if payload.get("ran") else []
        for signal in sigs[:MAX_PDF_SIGNALS]:
            if not isinstance(signal, dict):
                continue
            sev = signal.get("severity", "info")
            line = (
                f"&bull; <b><font color='{_sev_color(sev).hexval()}'>[{esc(sev)}]</font></b> "
                f"{esc(signal.get('title', ''))} <font face='Courier' size='7'>({esc(signal.get('id', ''))})</font>"
            )
            flow.append(Paragraph(line, small))
            detail = signal.get("detail")
            if detail:
                flow.append(Paragraph(esc(str(detail)[:STR_LIMIT]), ParagraphStyle("sd", parent=small, leftIndent=10)))
        flow.append(Spacer(1, 4))

    # YARA hits
    flow.append(Paragraph("YARA matches", h2))
    yara = _yara_hits(job)
    if yara:
        for rule in yara:
            flow.append(Paragraph(f"&bull; {esc(rule)}", mono))
    else:
        flow.append(Paragraph("No YARA rules matched (or the YARA tier did not run &mdash; see per-analyzer results).", small))

    # Macros
    macros = _macros(job)
    if macros:
        flow.append(Paragraph("Macros", h2))
        for macro in macros:
            flow.append(Paragraph(f"&bull; {esc(macro)}", mono))

    # Behaviors (static capabilities)
    behaviors = _behaviors(job)
    if behaviors:
        flow.append(Paragraph("Statically-inferred capabilities", h2))
        flow.append(Paragraph("Capability-class signals. Nothing was detonated; these are not observed runtime behaviors.", small))
        for b in behaviors:
            flow.append(
                Paragraph(
                    f"&bull; <b><font color='{_sev_color(b['severity']).hexval()}'>[{esc(b['severity'])}]</font></b> "
                    f"{esc(b['title'])} <font face='Courier' size='7'>({esc(b['id'])})</font>",
                    small,
                )
            )

    # IOCs
    flow.append(Paragraph("Indicators of compromise", h2))
    iocs = getattr(job, "iocs", None) or {}
    any_ioc = False
    for field_name in ("urls", "domains", "ips", "emails", "hashes", "file_paths", "registry_keys", "mutexes"):
        values = iocs.get(field_name, []) or []
        if not values:
            continue
        any_ioc = True
        flow.append(Paragraph(f"<b>{esc(field_name)}</b> ({len(values)})", small))
        for value in values[:MAX_PDF_IOCS_PER_KIND]:
            flow.append(Paragraph(esc(str(value)[:STR_LIMIT]), mono))
        if len(values) > MAX_PDF_IOCS_PER_KIND:
            flow.append(Paragraph(f"&hellip; and {len(values) - MAX_PDF_IOCS_PER_KIND} more", small))
    if not any_ioc:
        flow.append(Paragraph("No indicators were extracted.", small))

    # Archive tree
    tree = _archive_tree(job)
    if tree:
        flow.append(Paragraph("Archive contents", h2))
        rows = [["name", "size", "ratio", "enc", "sha256"]]
        for member in tree[:MAX_PDF_MEMBERS]:
            if not isinstance(member, dict):
                continue
            rows.append(
                [
                    esc(str(member.get("name", ""))[:60]),
                    esc(member.get("size", "")),
                    esc(member.get("ratio", "")),
                    "yes" if member.get("encrypted") else "no",
                    esc(str(member.get("sha256", "") or "")[:16]),
                ]
            )
        tbl = Table(rows, colWidths=[62 * mm, 20 * mm, 16 * mm, 12 * mm, 42 * mm])
        tbl.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), "Courier"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.93, 0.93, 0.95)),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.85, 0.85, 0.87)),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        flow.append(tbl)

    # ---- Regulatory annex (last page) ----
    # Built by engine/incident.py so the NIS2/DORA article citations stay next to
    # the code that derives each field; the styles are passed in so the annex
    # cannot drift typographically from the rest of the document.
    from . import incident as incident_mod

    flow.append(PageBreak())
    flow.extend(
        incident_mod.pdf_flowables(
            job, styles={"h1": h1, "h2": h2, "body": body, "small": small, "mono": mono, "esc": esc}
        )
    )

    doc.build(flow)
    return buf.getvalue()


def _kv_table(rows, mono_style, body_style, colors):
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Table, TableStyle

    data = [[Paragraph(f"<b>{k}</b>", body_style), Paragraph(str(v), mono_style)] for k, v in rows]
    tbl = Table(data, colWidths=[42 * mm, 128 * mm])
    tbl.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.88, 0.88, 0.9)),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("BACKGROUND", (0, 0), (0, -1), colors.Color(0.96, 0.96, 0.97)),
            ]
        )
    )
    return tbl
