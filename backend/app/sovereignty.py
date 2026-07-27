"""The egress choke point: one place that decides whether anything may leave.

The product's promise is "your files never leave the building". A promise a buyer
cannot verify is worth nothing, and the buyers who need this one — hospitals,
defence primes, courts, regulated banks — are precisely the ones whose auditor
will ask to be *shown*, not told. So sovereignty is implemented as a switch that
refuses, counts and logs, rather than as a sentence in a datasheet.

Three properties make this auditable rather than decorative:

1. **One choke point.** Every module that would talk to a third party asks
   :func:`check` first. There is no second path, and a new enrichment that
   forgets to ask is refused anyway — :func:`check` denies destinations it does
   not recognise, so the failure mode of forgetting is "blocked", not "leaked".
2. **Refusal is loud.** A refusal raises :class:`OutboundRefused`, logs at
   WARNING and increments a counter. A silent skip would be indistinguishable
   from an integration that was never configured, which is exactly the
   ambiguity an auditor is trying to eliminate.
3. **The refusals are evidence.** :func:`status` reports the running count and
   the most recent refusals, so the operator can point at the number and say
   "here is what we stopped", instead of at an absence of log lines.

**Default: on.** A sovereignty guarantee an operator has to remember to switch
on is a guarantee that fails on the day someone forgets. The deployment that
wants enrichment opts out explicitly with ``SOVEREIGN_MODE=false``.

**The one exception.** Submitting a URL for analysis *is* a request to fetch it,
so the URL fetcher is not an exfiltration path — the operator chose the
destination. It is still separately controllable
(``SOVEREIGN_ALLOW_URL_FETCH=false``) because a fully air-gapped deployment must
be able to close it too, and ``/api/capabilities`` states both facts so the
distinction is never hidden behind a single green tick.
"""
from __future__ import annotations

import logging
import threading
from collections import Counter, deque
from datetime import datetime, timezone

from .config import get_settings

logger = logging.getLogger("sandbox.sovereignty")

#: Every destination the analysis path can be asked to reach, with the plain
#: statement of what would leave. Naming them here is half the point: an operator
#: reading /api/capabilities sees the exhaustive list of egress a deployment is
#: even capable of, not a reassurance.
DESTINATIONS: dict[str, str] = {
    "virustotal": "VirusTotal — sends the sample's SHA-256 to Google's service",
    "cuckoo": "Cuckoo Sandbox cluster — uploads the sample file for detonation",
    "capev2": "CAPEv2 cluster — uploads the sample file for detonation",
    "strelka": "Strelka cluster — uploads the sample file for scanning",
    "joesandbox": "Joe Sandbox — uploads the sample file to a hosted service",
    "misp": "MISP / abuse.ch — publishes indicators extracted from the sample",
    "llm": "LLM provider — sends analysis text to a third-party model API",
    "url_fetch": "The submitter's own URL — downloads the sample under analysis",
}

#: The deliberate exception, governed by its own setting rather than by the
#: master switch. Keeping it a named constant stops it from quietly growing.
URL_FETCH = "url_fetch"

#: How many refusals are kept for the operator to read back. Bounded because
#: this lives in process memory and a misconfigured integration in a retry loop
#: would otherwise grow it without limit.
_MAX_REMEMBERED = 50

_lock = threading.Lock()
_counts: Counter[str] = Counter()
_recent: deque[dict] = deque(maxlen=_MAX_REMEMBERED)


class OutboundRefused(RuntimeError):
    """Raised instead of making a network call that sovereign mode forbids.

    Carries the destination so a caller can report *which* enrichment was
    refused rather than degrading to a generic "unavailable".
    """

    def __init__(self, destination: str, reason: str) -> None:
        super().__init__(reason)
        self.destination = destination
        self.reason = reason


def enabled() -> bool:
    """True when no data may leave this deployment."""
    return bool(get_settings().sovereign_mode)


def url_fetch_allowed() -> bool:
    """True when the deliberate URL-fetch exception is open."""
    return bool(get_settings().sovereign_allow_url_fetch)


def allowed(destination: str) -> bool:
    """Whether ``destination`` may be reached, without recording an attempt.

    For rendering a capability matrix. Anything that is about to make the call
    must use :func:`check`, which records the refusal.
    """
    if not enabled():
        return True
    if destination == URL_FETCH:
        return url_fetch_allowed()
    return False


def check(destination: str, *, detail: str = "") -> None:
    """Permit the call, or refuse it loudly.

    Raises :class:`OutboundRefused` when sovereign mode forbids ``destination``.
    An unknown destination is refused too: a new integration that has not been
    added to :data:`DESTINATIONS` must fail closed, because the alternative is a
    data path nobody declared.
    """
    if allowed(destination):
        return

    known = DESTINATIONS.get(destination, "undeclared destination")
    reason = (
        f"Sovereign mode is on: refused an outbound call to '{destination}' "
        f"({known}). No analysis data left this deployment."
    )
    record(destination, reason=reason, detail=detail)
    raise OutboundRefused(destination, reason)


def record(destination: str, *, reason: str, detail: str = "") -> None:
    """Count and log one refusal. Called by :func:`check`; separate so a caller
    that refuses for its own reason can still land in the same evidence trail."""
    at = datetime.now(timezone.utc).isoformat()
    with _lock:
        _counts[destination] += 1
        _recent.append(
            {
                "at": at,
                "destination": destination,
                "reason": reason,
                "detail": detail[:300] or None,
            }
        )
    logger.warning("%s%s", reason, f" ({detail[:300]})" if detail else "")


def refusals() -> dict:
    """The running refusal tally — the operator's proof that nothing left."""
    with _lock:
        return {
            "total": sum(_counts.values()),
            "by_destination": dict(_counts),
            "recent": list(_recent),
        }


def reset() -> None:
    """Clear the tally. For tests only — a deployment's count is its evidence."""
    with _lock:
        _counts.clear()
        _recent.clear()


def status() -> dict:
    """The sovereignty block for ``/api/capabilities``.

    Deliberately states both halves of the promise. "Sovereign mode: ON" alone
    would be a half-truth on a deployment that still fetches submitted URLs, and
    a half-truth is what an auditor is paid to find.
    """
    on = enabled()
    fetch_on = url_fetch_allowed()
    if on:
        statement = "Sovereign mode: ON — no analysis data leaves this deployment."
        if fetch_on:
            statement += (
                " The single exception is the URL fetcher: when an analyst submits a "
                "URL, this deployment downloads it, because that is the analysis "
                "being requested. Nothing about the sample is sent anywhere."
            )
        else:
            statement += (
                " URL fetching is also disabled, so this deployment makes no outbound "
                "connection of any kind."
            )
    else:
        statement = (
            "Sovereign mode: OFF — configured enrichment integrations may send sample "
            "hashes or sample files to the third parties listed below."
        )

    return {
        "enabled": on,
        "url_fetch_allowed": fetch_on,
        "statement": statement,
        "destinations": [
            {
                "key": key,
                "what_would_leave": what,
                "allowed": allowed(key),
                "is_deliberate_exception": key == URL_FETCH,
            }
            for key, what in DESTINATIONS.items()
        ],
        "outbound_refusals": refusals(),
    }
