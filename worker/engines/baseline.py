"""Suppress the guest operating system's own network chatter from lifted IOCs.

A Windows guest talks to Azure AD, MSA sign-in, connectivity probes, Edge update,
Delivery Optimization and several CDNs before a sample runs at all. Left alone,
those endpoints are lifted as "IOCs" and land in a report next to real C2 — which
makes every report look busy and none of it trustworthy.

The obvious fix does not work. Subtracting the exact IPs seen in an idle run
fails, because the same service answers from a different pool member every time.
Measured on this deployment:

    idle baseline : 40.126.53.8/9/11/13/15/19    (login.microsoftonline.com)
    sample run    : 40.126.32.133/134/136/138    (login.microsoftonline.com)

Zero overlap, same service. Set subtraction "cleans" nothing while looking like
it did — worse than no filter, because the survivors read as findings.

So there are two layers, and the first one matters most:

1. **Silence the guest.** The golden image has telemetry, MSA sign-in, NCSI
   active probing, Edge update, Delivery Optimization and error reporting turned
   off. Measured effect on an idle run: 22 endpoints -> 12.
2. **Suppress what is left**, using keys that are stable across runs rather than
   individual addresses: a curated list of platform domain suffixes, and the /24
   networks actually observed across repeated idle runs of *our* golden image.

Both lists are deliberately narrow. Hiding a real command-and-control address is
far more damaging than showing a noisy one, so anything not positively matched is
kept. Nothing is ever dropped silently either: :func:`partition` returns what it
removed, and the caller records it on the report.

``baseline_networks.txt`` describes one specific golden image. Rebuild the guest,
rebuild that file — see the header inside it.
"""
from __future__ import annotations

import ipaddress
import os
from functools import lru_cache

_HERE = os.path.dirname(os.path.abspath(__file__))
_NETWORKS_FILE = os.path.join(_HERE, "baseline_networks.txt")

#: Names that belong to the platform rather than to any sample. Matched as
#: suffixes on a label boundary, so "evil-microsoft.com" is NOT suppressed.
#: Kept to specific services instead of whole vendor domains: a sample really can
#: abuse a broad Microsoft-owned host, and we would rather report noise than hide
#: that.
PLATFORM_DOMAIN_SUFFIXES: frozenset[str] = frozenset(
    {
        # Connectivity probes
        "msftconnecttest.com",
        "msftncsi.com",
        # Telemetry / feedback
        "events.data.microsoft.com",
        "settings-win.data.microsoft.com",
        "watson.telemetry.microsoft.com",
        # Sign-in, which idle Windows attempts on its own
        "login.microsoftonline.com",
        "login.live.com",
        "login.windows.net",
        # Update and content delivery
        "windowsupdate.com",
        "update.microsoft.com",
        "delivery.mp.microsoft.com",
        "tlu.dl.delivery.mp.microsoft.com",
        # Edge and bundled apps
        "edge.microsoft.com",
        "msedge.api.cdp.microsoft.com",
        "cdn.onenote.net",
        "officeapps.live.com",
        # Certificate status - every TLS client on earth does this
        "ocsp.digicert.com",
        "crl.microsoft.com",
        "ctldl.windowsupdate.com",
        # Clock
        "time.windows.com",
    }
)


@lru_cache(maxsize=1)
def baseline_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """The networks an idle golden image was observed to contact.

    Missing or unreadable file means "no network baseline" — an empty tuple, so
    every address is kept. Failing open is the right direction here: a worker
    shipped without the data file should over-report, never under-report.
    """
    try:
        with open(_NETWORKS_FILE, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return ()
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            out.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue  # a typo in the data file must not break detonation
    return tuple(out)


def _domain_is_platform(value: str) -> bool:
    host = value.strip().lower().rstrip(".")
    if not host:
        return False
    return any(host == s or host.endswith("." + s) for s in PLATFORM_DOMAIN_SUFFIXES)


def _ip_is_platform(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return any(addr in net for net in baseline_networks())


def noise_reason(field: str, value: str) -> str | None:
    """Why ``value`` is platform noise, or ``None`` to keep it.

    Only network fields are considered. Dropped files, registry keys and mutexes
    are never suppressed here: their baseline is enormous and the interesting
    ones are indistinguishable from the boring ones without far more context.
    """
    if field == "ips":
        return "guest-platform network" if _ip_is_platform(value) else None
    if field == "domains":
        return "guest-platform domain" if _domain_is_platform(value) else None
    if field == "urls":
        host = value.split("//", 1)[-1].split("/", 1)[0].split("@")[-1].split(":", 1)[0]
        if _domain_is_platform(host):
            return "guest-platform domain"
        return "guest-platform network" if _ip_is_platform(host) else None
    return None


def partition(iocs: dict[str, list[str]]) -> tuple[dict[str, list[str]], list[dict[str, str]]]:
    """Split IOCs into (kept, suppressed).

    The suppressed list is returned rather than discarded so the caller can put
    it on the report. An analyst who cannot see what a filter removed cannot
    trust the filter.
    """
    kept: dict[str, list[str]] = {}
    suppressed: list[dict[str, str]] = []
    for field, values in (iocs or {}).items():
        keep_field = []
        for value in values or []:
            reason = noise_reason(field, value)
            if reason:
                suppressed.append({"field": field, "value": value, "reason": reason})
            else:
                keep_field.append(value)
        kept[field] = keep_field
    return kept, suppressed
