"""The regulator-ready incident record.

Detonation is free. What a compliance-driven buyer cannot get free is the
*artifact* — a structured, timestamped, hash-anchored record of what was found,
laid out in the fields a supervisory authority actually asks for, produced
inside their own building. This module turns a completed ``SandboxJob`` into
that record.

Two regimes are covered, because they are the two that put a clock on a European
operator's desk the moment they become aware of an incident:

* **NIS2** — Directive (EU) 2022/2555. Article 23(4)(a) requires an *early
  warning* to the CSIRT or competent authority **without undue delay and in any
  event within 24 hours** of becoming aware of a significant incident, and it
  must, where applicable, indicate whether the incident is *suspected of being
  caused by unlawful or malicious acts* or *could have a cross-border impact*.
  Article 23(4)(b) then requires an incident notification within 72 hours
  carrying an initial assessment — severity, impact, and where available
  indicators of compromise. Article 23(4)(d) requires a final report within one
  month, including threat type / root cause.
* **DORA** — Regulation (EU) 2022/2554. Article 18(1) sets the classification
  criteria for an ICT-related incident; Article 19 requires major incidents to
  be reported to the competent authority in an initial / intermediate / final
  sequence; Article 17(3) requires root causes to be identified and addressed.

**What this module refuses to do.** It does not decide whether an incident is
"significant" under NIS2 Article 23(3) or "major" under DORA Article 18, it does
not compute DORA's reporting deadlines (those live in the regulatory technical
standards adopted under Article 20, not in the Level 1 text), and it offers no
legal advice. Those determinations depend on the entity's own service map,
client counts and economic exposure — facts a file analyser has no access to and
must not guess at. Every such field is emitted as ``null`` and named in an
explicit ``operator_input_required`` list, and the record labels itself as
evidence to be completed and filed by the operator's compliance function.

The article numbers are carried in the payload itself, not only in these
comments, so an auditor can trace each field back to the text that asks for it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import get_settings
from . import report as report_mod

SCHEMA = "cyclowareness-sandbox.incident/1"

#: The sentence that must appear on every surface this record reaches. It exists
#: because the single most damaging thing this product could do is let a
#: compliance officer believe a generated JSON file discharged a statutory
#: obligation on its own.
DISCLAIMER = (
    "This is a structured evidence record produced by an analysis tool. It is not "
    "a regulatory filing, not a determination that an incident is significant "
    "(NIS2 Article 23(3)) or major (DORA Article 18), and not legal advice. The "
    "operator's compliance function completes the fields marked as requiring "
    "operator input, makes the significance determination, and files with the "
    "competent authority or CSIRT."
)

#: NIS2 Article 23(4) reporting stages, with the deadlines stated in the
#: Directive itself. Only these are computed — anything whose deadline lives in
#: an implementing act is reported as "set by RTS", never invented.
_NIS2_STAGES = (
    ("early_warning", 24, "Article 23(4)(a)", "within 24 hours of becoming aware"),
    ("incident_notification", 72, "Article 23(4)(b)", "within 72 hours of becoming aware"),
    ("final_report", 24 * 30, "Article 23(4)(d)", "not later than one month after the incident notification"),
)

#: Signal-id prefixes that indicate the artifact reached the entity from outside
#: it, which is what makes cross-border impact a live question rather than a
#: box to tick. Deliberately narrow: an inference this record hands to a
#: regulator has to be defensible, so anything less direct is "undetermined".
_CROSS_BORDER_PREFIXES = ("generic.url", "generic.ip_literal_url", "generic.suspicious_tld",
                          "generic.punycode_or_lookalike_domain", "generic.many_urls")


def _iso(value: Any) -> str | None:
    """A job timestamp as an offset-aware ISO 8601 string.

    The job row stores naive UTC. A regulatory record with a bare local-looking
    timestamp is ambiguous exactly where it must not be, so the offset is made
    explicit rather than assumed by the reader.
    """
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _awareness(job) -> datetime | None:
    """When the entity became aware, in the sense the clock uses.

    Awareness is not submission: an analyst uploading a file does not yet know
    it is malicious. Awareness is the moment the analysis returned a verdict, so
    the completion timestamp is what starts the NIS2 Article 23(4)(a) clock. An
    unfinished job has no awareness time, and the record says so instead of
    substituting "now" and manufacturing a deadline.
    """
    # FIRST completion, not the latest one. `completed_at` is cleared and
    # rewritten by every re-analysis, so deriving the deadline from it meant a
    # re-scoring sweep silently moved the regulatory clock forward for every job
    # it touched. Awareness happened once.
    #
    # `first_completed_at` is backfilled from `completed_at` by migration 0007,
    # which is exact for any job never re-analysed and the best available answer
    # for the rest; the fallback keeps a row written before that migration
    # readable rather than claiming there is no awareness time.
    completed = getattr(job, "first_completed_at", None) or getattr(job, "completed_at", None)
    if isinstance(completed, datetime):
        return completed if completed.tzinfo else completed.replace(tzinfo=timezone.utc)
    return None


def _entity() -> dict[str, Any]:
    """The notifying entity, from configuration — never inferred."""
    settings = get_settings()
    fields = {
        "name": settings.entity_name.strip() or None,
        "country": settings.entity_country.strip() or None,
        "sector": settings.entity_sector.strip() or None,
        "contact": settings.entity_contact.strip() or None,
    }
    return {
        **fields,
        "source": "deployment configuration (ENTITY_NAME / ENTITY_COUNTRY / ENTITY_SECTOR / ENTITY_CONTACT)",
        "operator_input_required": sorted(k for k, v in fields.items() if v is None),
    }


def _malicious(job) -> bool:
    return report_mod._assessed_malicious(job)


def _suspicious_or_worse(job) -> bool:
    label = str(report_mod._verdict(job).get("verdict", "") or "").strip().lower()
    if label:
        return label in ("malicious", "suspicious")
    return (getattr(job, "risk_level", "low") or "low") in ("medium", "high", "critical")


def _unlawful_or_malicious_act(job) -> dict[str, Any]:
    """NIS2 Article 23(4)(a): is the incident suspected of being caused by an
    unlawful or malicious act?

    Three states, not two. "Suspected" is a real answer under the Directive and
    a suspicious verdict is exactly that; collapsing it to false would understate
    the filing, and collapsing it to true would overstate it.
    """
    verdict = report_mod._verdict(job)
    label = str(verdict.get("verdict", "") or "").strip().lower()
    threat = str(verdict.get("threat_name", "") or "").strip()
    ratio = str(verdict.get("detection_ratio", "") or "n/a")

    if _malicious(job):
        return {
            "answer": "yes",
            "basis": (
                f"The analysed artifact was assessed malicious ({threat or 'unnamed'}, "
                f"detection ratio {ratio}). Malware is by construction the product of a "
                "deliberate act."
            ),
        }
    if label == "suspicious":
        return {
            "answer": "suspected",
            "basis": (
                f"The analysed artifact was assessed suspicious (detection ratio {ratio}). "
                "Capability was observed but the evidence did not meet the engine's bar "
                "for a malicious verdict."
            ),
        }
    return {
        "answer": "not evidenced by this artifact",
        "basis": (
            "This artifact produced no evidence of a malicious act. That is a statement "
            "about this file only, not about the incident: other evidence held by the "
            "operator may support a different answer."
        ),
    }


def _points_inside(value: str) -> bool:
    """Is this indicator an address belonging to the sandbox itself?

    Loopback, link-local and RFC1918 are this deployment and its guest network.
    An indicator pointing at them is the sandbox observing itself, and it must
    not read as the artifact reaching another jurisdiction.

    Anything unparseable is treated as OUTWARD. A hostname we cannot resolve
    here could be anywhere, and the safe direction for a regulatory record is to
    keep it in the count rather than quietly drop it.
    """
    import ipaddress
    import re as _re
    from urllib.parse import urlsplit

    text = (value or "").strip()
    if not text:
        return False
    host = text
    if "://" in text:
        host = urlsplit(text).hostname or ""
    elif "@" in text:
        host = text.rsplit("@", 1)[-1]
    host = host.strip("[]").split(":")[0]
    if not host:
        return False
    if host in ("localhost", "localhost.localdomain"):
        return True
    if not _re.fullmatch(r"[0-9a-fA-F:.]+", host):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        address.is_loopback or address.is_private or address.is_link_local
        or address.is_unspecified
    )


def _cross_border(job) -> dict[str, Any]:
    """NIS2 Article 23(4)(a) / 23(6): could the incident have cross-border impact?

    A file analyser cannot answer this. It can say whether the artifact reaches
    outside the entity — a remote C2, a fetched URL, network indicators — which
    is the input the compliance function needs, and it can decline the rest.
    """
    iocs = getattr(job, "iocs", None) or {}
    external = []
    internal = []
    for kind in ("urls", "domains", "ips", "emails"):
        values = [str(v) for v in (iocs.get(kind) or [])]
        if not values:
            continue
        # OUR OWN ADDRESSES ARE NOT ANOTHER COUNTRY.
        #
        # The guest network is 192.168.122.x and the deployment answers on
        # loopback, so a detonation that talked only to our own sinkhole put
        # exactly those in the IOCs -- and this record then told a regulator that
        # cross-border impact "cannot be excluded on the evidence".
        #
        # `sovereignty.destination_is_internal` already draws this line on the
        # egress side, for the same reason.
        outward = [v for v in values if not _points_inside(v)]
        if outward:
            external.append({"kind": kind, "count": len(outward)})
        if len(outward) != len(values):
            internal.append({"kind": kind, "count": len(values) - len(outward)})

    signal_ids = {str(s.get("id", "")) for s in report_mod._all_signals(job)}
    reaches_out = bool(external) or any(
        sid.startswith(_CROSS_BORDER_PREFIXES) for sid in signal_ids
    ) or (getattr(job, "source", "") == "url")

    return {
        "answer": "undetermined",
        "indicators_of_external_reach": external,
        # Reported rather than dropped: the analysis saw them, and a record that
        # silently omits an indicator is its own kind of wrong. They simply do
        # not, on their own, assert that anything left the entity.
        "indicators_inside_this_deployment": internal,
        "artifact_reaches_outside_the_entity": reaches_out,
        "basis": (
            "The artifact carries indicators pointing outside the entity, so cross-border "
            "impact cannot be excluded on the evidence."
            if reaches_out
            else "The artifact carries no indicators pointing outside the entity."
        ),
        "operator_input_required": [
            "whether affected services are provided in, or depend on, more than one Member State",
            "whether other entities or Member States were or could be affected (Article 23(6))",
        ],
    }


def _severity_and_impact(job) -> dict[str, Any]:
    """NIS2 Article 23(4)(b): an initial assessment of severity and impact.

    The engine's own numbers, stated as what they are. The Cyclowareness Impact
    Rating describes what the artifact is *capable* of; operational and financial
    impact on the entity is a different measurement, and the record keeps them
    apart rather than letting a 9.1 read as a business impact figure.
    """
    impact = report_mod._impact(job)
    return {
        "engine_risk_level": getattr(job, "risk_level", "low") or "low",
        "engine_score": report_mod._num(getattr(job, "final_score", 0.0)),
        "engine_score_scale": "0-100, bands: 0-29 low, 30-59 medium, 60-79 high, 80-100 critical",
        "artifact_impact_rating": {
            "rating": impact.get("rating"),
            "vector": impact.get("vector"),
            "base_score": impact.get("base_score"),
            "severity": impact.get("severity"),
            "note": impact.get("disclaimer"),
        }
        if impact
        else None,
        "operational_impact_on_entity": None,
        "operator_input_required": [
            "severity and impact of the incident on the entity's own services (Article 23(4)(b))",
            "indicators of compromise, where available beyond those listed under 'evidence'",
        ],
    }


def _nis2(job) -> dict[str, Any]:
    awareness = _awareness(job)
    stages = []
    for name, hours, article, wording in _NIS2_STAGES:
        stages.append(
            {
                "stage": name,
                "article": f"Directive (EU) 2022/2555, {article}",
                "deadline": wording,
                # The one-month final report runs from the notification, not from
                # awareness; approximating it from awareness would put a wrong
                # date in a regulatory record, so it is left for the operator.
                "due_by": _iso(awareness + timedelta(hours=hours))
                if awareness is not None and name != "final_report"
                else None,
            }
        )

    return {
        "regulation": "Directive (EU) 2022/2555 (NIS2)",
        "record_type": "early warning input, Article 23(4)(a)",
        "significance_determination": {
            "decision": "operator",
            "article": "Article 23(3)",
            "criteria": [
                "has caused or is capable of causing severe operational disruption of the "
                "services or financial loss for the entity concerned",
                "has affected or is capable of affecting other natural or legal persons by "
                "causing considerable material or non-material damage",
            ],
            "note": (
                "Only the entity can apply these criteria; they depend on its own services "
                "and exposure, which this tool does not observe."
            ),
        },
        "entity": _entity(),
        "suspected_unlawful_or_malicious_act": _unlawful_or_malicious_act(job),
        "cross_border_impact": _cross_border(job),
        "severity_and_impact": _severity_and_impact(job),
        "timestamps": {
            "artifact_submitted_at": _iso(getattr(job, "created_at", None)),
            "analysis_started_at": _iso(getattr(job, "started_at", None)),
            "awareness_at": _iso(awareness),
            "awareness_basis": (
                "The moment analysis returned a verdict. Submission alone is not awareness: "
                "the submitter did not yet know what the file was."
            ),
            "record_generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "reporting_stages": stages,
    }


def _dora_classification(job) -> dict[str, Any]:
    """DORA Article 18(1) classification criteria, each answered or declined.

    Seven criteria, and this tool has evidence bearing on exactly two of them —
    data losses and (partly) criticality, via what the artifact can do. Filling
    the other five with plausible-looking values would be the most dangerous
    thing in this module, so they are ``null`` with the reason.
    """
    impact = report_mod._impact(job)
    metrics = impact.get("metrics", {}) if isinstance(impact, dict) else {}
    duration_ms = getattr(job, "duration_ms", None)

    def data_loss(metric: str, label: str) -> str:
        value = metrics.get(metric)
        if value == "H":
            return f"{label}: high impact indicated by the artifact's assessed capability"
        if value == "L":
            return f"{label}: low impact indicated by the artifact's assessed capability"
        return f"{label}: none demonstrated by the artifact"

    return {
        "article": "Regulation (EU) 2022/2554 (DORA), Article 18(1)",
        "criteria": {
            "clients_financial_counterparts_affected": None,
            "reputational_impact": None,
            "duration_and_service_downtime": None,
            "geographical_spread": None,
            "data_losses": {
                "assessed_from": "the artifact's demonstrated capability, not from observed loss",
                "confidentiality": data_loss("C", "confidentiality"),
                "integrity": data_loss("I", "integrity"),
                "availability": data_loss("A", "availability"),
                "authenticity": (
                    "authenticity: the artifact misrepresents what it is"
                    if getattr(job, "extension_mismatch", 0)
                    else "authenticity: no misrepresentation detected in the artifact"
                ),
            },
            "criticality_of_services_affected": None,
            "economic_impact": None,
        },
        "operator_input_required": [
            "clients_financial_counterparts_affected",
            "reputational_impact",
            "duration_and_service_downtime",
            "geographical_spread",
            "criticality_of_services_affected",
            "economic_impact",
        ],
        "note": (
            "Five of the seven criteria measure effects on the entity's own clients, "
            "services and finances. A file analyser observes none of them and this record "
            "leaves them empty rather than estimating them. Analysis wall time was "
            f"{duration_ms} ms and is the duration of the *analysis*, not of any incident."
        ),
    }


def _root_cause_indicators(job) -> list[dict[str, Any]]:
    """DORA Article 17(3) root causes / NIS2 Article 23(4)(d) threat type.

    Indicators, named as such. The root cause of an incident is how the artifact
    got in and what it then did on the entity's estate; what this tool holds is
    the artifact's own delivery vector, capabilities and ATT&CK mapping, which
    is evidence toward that answer rather than the answer.
    """
    out: list[dict[str, Any]] = []
    verdict = report_mod._verdict(job)
    if verdict.get("threat_name"):
        out.append(
            {
                "kind": "threat_classification",
                "value": verdict.get("threat_name"),
                "detail": f"Engine consensus {verdict.get('detection_ratio', 'n/a')}.",
            }
        )
    source = getattr(job, "source", "") or ""
    out.append(
        {
            "kind": "delivery_vector",
            "value": "URL retrieval" if source == "url" else
                     "archive member" if source == "archive_member" else "file submission",
            "detail": str(getattr(job, "submitted_url", "") or "")[:300]
            or "The artifact was submitted directly to the analysis service.",
        }
    )
    for technique in report_mod._mitre(job):
        out.append(
            {
                "kind": "attack_technique",
                "value": f"{technique.get('technique_id', '')} {technique.get('name', '')}".strip(),
                "detail": str(technique.get("tactic", "") or ""),
            }
        )
    for reason in report_mod._top_reasons(job)[:3]:
        out.append(
            {
                "kind": "detection_reason",
                "value": str(reason.get("title") or reason.get("id") or ""),
                "detail": str(reason.get("detail", ""))[:300],
            }
        )
    return out


def _dora(job) -> dict[str, Any]:
    return {
        "regulation": "Regulation (EU) 2022/2554 (DORA)",
        "record_type": "ICT-related incident report input, Articles 17-19",
        "entity": _entity(),
        "major_incident_determination": {
            "decision": "operator",
            "article": "Article 18",
            "note": (
                "Whether this is a major ICT-related incident is determined by the financial "
                "entity against the Article 18 criteria and the thresholds in the regulatory "
                "technical standards. This tool supplies evidence, not the determination."
            ),
        },
        "classification": _dora_classification(job),
        "affected_services": {
            "value": None,
            "note": (
                "The ICT services and functions affected are known to the entity, not to the "
                "analysis service. The artifact's own target platform is recorded under "
                "'artifact' as the starting point."
            ),
            "operator_input_required": ["affected ICT services", "affected business functions"],
        },
        "root_cause_indicators": _root_cause_indicators(job),
        "temporal": {
            "artifact_submitted_at": _iso(getattr(job, "created_at", None)),
            "analysis_started_at": _iso(getattr(job, "started_at", None)),
            "detection_at": _iso(_awareness(job)),
            "analysis_duration_ms": getattr(job, "duration_ms", None),
            "incident_occurrence_at": None,
            "incident_recovery_at": None,
            "operator_input_required": [
                "time of occurrence of the incident",
                "time of recovery / return to normal activities",
            ],
        },
        "reporting_stages": [
            {
                "stage": stage,
                "article": "Article 19(4)",
                "deadline": (
                    "Set by the regulatory technical standards adopted under Article 20; "
                    "not stated in the Regulation's own text and therefore not computed here."
                ),
                "due_by": None,
            }
            for stage in ("initial_notification", "intermediate_report", "final_report")
        ],
    }


def _retention_limitation(job) -> list[str]:
    """Say so when the artifact this record is about no longer exists.

    The `note` below tells the reader to recompute the SHA-256 over the original
    file. `retention.sweep` deletes that file on a schedule and stamps
    `sample_deleted_at` — and the only reader of that column anywhere in the
    application was the dynamic ingest. So a regulatory record could invite a
    verification step that this deployment had already made impossible, and say
    nothing about it.

    A limitation, not an error. Deleting the malware on a schedule is the
    correct behaviour and often a contractual requirement; what is not correct
    is a document that does not mention it.
    """
    deleted = getattr(job, "sample_deleted_at", None)
    if deleted is None:
        return []
    return [
        "The sample's bytes are no longer held by this deployment: they were "
        f"deleted under the data-retention policy on {deleted:%Y-%m-%d}. The "
        "SHA-256 below still identifies the artifact, but it cannot be "
        "recomputed here — verification requires a copy of the original file."
    ]


def _evidence(job) -> dict[str, Any]:
    """What the record rests on — so a reader can check it rather than trust it."""
    tiers = report_mod._tiers_summary(job)
    not_run = [t["tier"] for t in tiers if not t.get("ran")]
    iocs = getattr(job, "iocs", None) or {}
    return {
        "analysis_tiers": tiers,
        "limitations": (
            [
                f"The {tier} analysis tier did not run. Any finding that tier would have "
                "produced is absent from this record."
                for tier in not_run
            ]
            + _retention_limitation(job)
            or ["All configured analysis tiers ran."]
        ),
        "analyzers_that_ran": sorted(name for name, _ in report_mod._ran_results(job)),
        "indicators_of_compromise": {k: v for k, v in iocs.items() if v},
        "signal_count": len(report_mod._all_signals(job)),
        "attack_techniques": report_mod._mitre(job),
        "note": (
            "Artifact identity is anchored on the SHA-256 recorded under 'artifact'. "
            "Recomputing that hash over the original file reproduces this record's subject."
        ),
    }


def build(job) -> dict[str, Any]:
    """The full incident record for one completed job.

    Total by construction: a failed, queued or password-parked job still yields a
    record, with the fields it cannot support stated as unavailable. A compliance
    function that only gets a document when everything went well has no document
    on the day it matters.
    """
    from ..sovereignty import status as sovereignty_status

    status = getattr(job, "status", "") or ""
    complete = status == "completed"
    sovereignty = sovereignty_status()

    record = {
        "schema": SCHEMA,
        "record_status": "draft evidence record — not a regulatory filing",
        "disclaimer": DISCLAIMER,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": {
            "product": "Cyclowareness Sandbox",
            "analysis_complete": complete,
            "note": (
                ""
                if complete
                else f"Analysis did not complete (status '{status}'). The regulatory "
                "sections below rest on partial evidence and must not be filed as they stand."
            ),
        },
        "case_reference": getattr(job, "public_id", None),
        "artifact": {
            "filename_as_submitted": getattr(job, "original_name", "") or "",
            "sha256": getattr(job, "sha256", "") or "",
            "md5": getattr(job, "md5", "") or "",
            "size_bytes": getattr(job, "size_bytes", 0),
            "mime": getattr(job, "mime", "") or "",
            "magic": getattr(job, "magic", "") or "",
            "family": getattr(job, "family", "") or "",
            "target_platform": report_mod._verdict(job).get("platform"),
            "source": getattr(job, "source", "") or "",
            "submitted_url": getattr(job, "submitted_url", None),
            "submitted_by": getattr(job, "submitted_by", None),
        },
        "assessment": {
            "verdict": report_mod._verdict(job),
            "risk_level": getattr(job, "risk_level", "low") or "low",
            "score": report_mod._num(getattr(job, "final_score", 0.0)),
            "assessed_malicious": _malicious(job),
            "assessed_suspicious_or_worse": _suspicious_or_worse(job),
        },
        "nis2": _nis2(job),
        "dora": _dora(job),
        "evidence": _evidence(job),
        # The record states where it was produced. For a buyer whose whole reason
        # for owning this is that the file could not leave, the provenance of the
        # evidence is part of the evidence.
        "sovereignty": {
            "enabled": sovereignty["enabled"],
            "url_fetch_allowed": sovereignty["url_fetch_allowed"],
            "statement": sovereignty["statement"],
            "outbound_refusals_total": sovereignty["outbound_refusals"]["total"],
        },
    }
    # THE DOCUMENT THAT LEAVES THE BUILDING MOST DEFINITELY MUST NOT NAME THE
    # HOST THAT DETONATES LIVE MALWARE.
    #
    # `report.as_json` scrubs infrastructure names; this record — the one written
    # for a regulator under NIS2 Article 23 and DORA 17-19, and the one most
    # likely to be forwarded outside the organisation — did not, and it embeds
    # `_tiers_summary(job)` and the verdict block verbatim. So the detonation
    # host's name went to the national authority while the JSON export beside it
    # said "the attached worker".
    return report_mod._without_infrastructure(record, report_mod._infrastructure_names(job))


# ============================================================================
# PDF annex
# ============================================================================


def pdf_flowables(job, *, styles: dict) -> list:
    """The regulatory annex, as reportlab flowables.

    Built here rather than in report.py so the article citations live beside the
    code that derives them; ``styles`` carries the already-constructed paragraph
    styles and the escaper so the annex cannot drift typographically from the
    rest of the document.
    """
    from reportlab.platypus import Paragraph, Spacer

    h1, h2 = styles["h1"], styles["h2"]
    body, small, mono = styles["body"], styles["small"], styles["mono"]
    esc = styles["esc"]

    record = build(job)
    flow: list = [
        Paragraph("Regulatory annex", h1),
        Paragraph("NIS2 Article 23 and DORA Articles 17&ndash;19 evidence record", small),
        Spacer(1, 6),
        Paragraph(f"<b>{esc(DISCLAIMER)}</b>", small),
        Spacer(1, 6),
        Paragraph(f"Case reference: {esc(record['case_reference'] or '(none)')}", mono),
    ]

    entity = record["nis2"]["entity"]
    flow.append(Paragraph("Notifying entity", h2))
    flow.append(
        Paragraph(
            f"{esc(entity.get('name') or 'NOT CONFIGURED')} &mdash; "
            f"{esc(entity.get('sector') or 'sector not configured')}, "
            f"{esc(entity.get('country') or 'country not configured')}. "
            f"Contact: {esc(entity.get('contact') or 'not configured')}.",
            body,
        )
    )
    if entity["operator_input_required"]:
        flow.append(
            Paragraph(
                "Operator input required: " + esc(", ".join(entity["operator_input_required"]))
                + " (set ENTITY_NAME / ENTITY_COUNTRY / ENTITY_SECTOR / ENTITY_CONTACT).",
                small,
            )
        )

    nis2 = record["nis2"]
    flow.append(Paragraph("NIS2 &mdash; early warning input (Article 23(4)(a))", h2))
    act = nis2["suspected_unlawful_or_malicious_act"]
    flow.append(
        Paragraph(
            f"<b>Suspected of being caused by unlawful or malicious acts:</b> "
            f"{esc(act['answer'].upper())}. {esc(act['basis'])}",
            body,
        )
    )
    cross = nis2["cross_border_impact"]
    flow.append(
        Paragraph(
            f"<b>Could have cross-border impact:</b> {esc(cross['answer'].upper())}. "
            f"{esc(cross['basis'])}",
            body,
        )
    )
    sev = nis2["severity_and_impact"]
    flow.append(
        Paragraph(
            f"<b>Severity indication:</b> {esc(sev['engine_risk_level'].upper())} "
            f"(engine score {sev['engine_score']:.0f}/100). Operational impact on the entity "
            "is not observed by this tool and remains for the operator to state.",
            body,
        )
    )
    flow.append(Paragraph("<b>Timestamps and deadlines</b>", body))
    times = nis2["timestamps"]
    flow.append(
        Paragraph(
            f"Submitted {esc(times['artifact_submitted_at'] or 'n/a')} &middot; "
            f"awareness {esc(times['awareness_at'] or 'not established')}",
            mono,
        )
    )
    for stage in nis2["reporting_stages"]:
        flow.append(
            Paragraph(
                f"&bull; <b>{esc(stage['stage'].replace('_', ' '))}</b> &mdash; "
                f"{esc(stage['article'])}, {esc(stage['deadline'])}. "
                f"Due by: {esc(stage['due_by'] or 'operator to determine')}.",
                small,
            )
        )
    flow.append(
        Paragraph(
            "Whether the incident is significant under Article 23(3) is determined by the "
            "entity, not by this tool.",
            small,
        )
    )

    dora = record["dora"]
    flow.append(Paragraph("DORA &mdash; ICT-related incident record (Articles 17&ndash;19)", h2))
    flow.append(Paragraph("<b>Article 18(1) classification criteria</b>", body))
    for name, value in dora["classification"]["criteria"].items():
        if value is None:
            flow.append(
                Paragraph(
                    f"&bull; {esc(name.replace('_', ' '))}: <i>operator input required</i>", small
                )
            )
        elif isinstance(value, dict):
            parts = [str(v) for k, v in value.items() if k != "assessed_from"]
            flow.append(
                Paragraph(f"&bull; {esc(name.replace('_', ' '))}: {esc('; '.join(parts))}", small)
            )
    flow.append(Paragraph("<b>Root-cause indicators (Article 17(3))</b>", body))
    for indicator in dora["root_cause_indicators"][:20]:
        flow.append(
            Paragraph(
                f"&bull; <b>{esc(indicator['kind'].replace('_', ' '))}</b>: "
                f"{esc(indicator['value'])}",
                small,
            )
        )
    flow.append(
        Paragraph(
            "DORA reporting deadlines are set by the regulatory technical standards adopted "
            "under Article 20 and are deliberately not computed here.",
            small,
        )
    )

    flow.append(Paragraph("Evidence and limitations", h2))
    for limitation in record["evidence"]["limitations"]:
        flow.append(Paragraph(f"&bull; {esc(limitation)}", small))
    flow.append(
        Paragraph(
            f"Analyzers that ran: {esc(', '.join(record['evidence']['analyzers_that_ran']) or 'none')}. "
            f"Signals recorded: {record['evidence']['signal_count']}.",
            small,
        )
    )
    flow.append(Paragraph(f"SHA-256: {esc(record['artifact']['sha256'])}", mono))
    flow.append(Paragraph(esc(record["sovereignty"]["statement"]), small))

    return flow
