"""Submission helpers for the attached open-source sandbox clusters.

These are the thin HTTP shims the operator or the off-host worker uses to hand a
sample to a *separate* open-source service. None of them run in the request path
of the web service by default, and none of them detonate anything in-process —
they push bytes to an external Cuckoo / CAPEv2 / Strelka deployment and return
whatever that service says.

They exist so the integration matrix is not a fiction: when
``CUCKOO_URL``/``CAPEV2_URL``/``STRELKA_URL`` are configured, this is the code
that actually talks to them. Each is deliberately small, typed, and total —
every failure mode collapses to ``{"ok": False, "error": ...}`` rather than an
exception, because a sandbox being unreachable is an expected operational state,
not a crash.

These three are the highest-stakes egress in the product: unlike a VirusTotal
hash lookup they send the customer's **file**. So each clears the sovereignty
choke point before touching the socket, and a refusal is returned as its own
error code rather than folded into "unreachable" — an operator must be able to
tell a cluster that is down from a cluster this deployment is not allowed to
reach.
"""
from __future__ import annotations

import httpx

from ... import sovereignty

# Sandbox submissions can take a moment to accept the upload; keep the connect
# timeout tight but allow the write/read to breathe.
_DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _refusal(destination: str, filename: str, base_url: str = "") -> dict | None:
    """``None`` when the call may proceed, else the refusal to return as-is.

    ``base_url`` is passed on so the choke point can see that a destination is
    inside this deployment. `CAPEV2_URL=http://127.0.0.1:8000` is CAPE on this
    very machine; refusing that as egress stopped nothing from leaving.
    """
    try:
        sovereignty.check(destination, detail=f"would upload {filename!r}", url=base_url)
    except sovereignty.OutboundRefused as refused:
        return {"ok": False, "error": "sovereign_mode_refused", "refusal": refused.reason}
    return None


def cuckoo_submit(base_url: str, token: str, file_bytes: bytes,
                  filename: str = "sample.bin",
                  timeout: httpx.Timeout | float = _DEFAULT_TIMEOUT) -> dict:
    """Submit a sample to a Cuckoo Sandbox instance for dynamic analysis.

    Posts the file to Cuckoo's ``POST /tasks/create/file`` REST endpoint using a
    Bearer token. On success Cuckoo returns a ``task_id`` that the worker later
    polls for the finished report.

    Returns ``{"ok": True, "task_id": <int>, "raw": <json>}`` or
    ``{"ok": False, "error": <reason>}``. Never raises.
    """
    if not base_url or not token:
        return {"ok": False, "error": "cuckoo not configured"}
    refused = _refusal("cuckoo", filename, base_url)
    if refused:
        return refused

    url = base_url.rstrip("/") + "/tasks/create/file"
    headers = {"Authorization": f"Bearer {token}"}
    files = {"file": (filename, file_bytes, "application/octet-stream")}
    try:
        resp = httpx.post(url, headers=headers, files=files, timeout=timeout)
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"transport: {type(exc).__name__}"}

    if resp.status_code not in (200, 201):
        return {"ok": False, "error": f"http_{resp.status_code}"}
    try:
        data = resp.json()
    except ValueError:
        return {"ok": False, "error": "malformed_response"}
    return {"ok": True, "task_id": data.get("task_id"), "raw": data}


def capev2_submit(base_url: str, token: str, file_bytes: bytes,
                  filename: str = "sample.bin",
                  timeout: httpx.Timeout | float = _DEFAULT_TIMEOUT) -> dict:
    """Submit a sample to a CAPEv2 instance for dynamic analysis.

    CAPEv2 keeps Cuckoo's REST shape: ``POST /apiv2/tasks/create/file/`` with a
    ``Token <token>`` Authorization header, returning a task id (CAPE nests it
    under ``data.task_ids``). The worker later pulls the config/payload-
    extraction report.

    Returns ``{"ok": True, "task_id": <int|None>, "raw": <json>}`` or
    ``{"ok": False, "error": <reason>}``. Never raises.
    """
    if not base_url or not token:
        return {"ok": False, "error": "capev2 not configured"}
    refused = _refusal("capev2", filename, base_url)
    if refused:
        return refused

    url = base_url.rstrip("/") + "/apiv2/tasks/create/file/"
    headers = {"Authorization": f"Token {token}"}
    files = {"file": (filename, file_bytes, "application/octet-stream")}
    try:
        resp = httpx.post(url, headers=headers, files=files, timeout=timeout)
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"transport: {type(exc).__name__}"}

    if resp.status_code not in (200, 201):
        return {"ok": False, "error": f"http_{resp.status_code}"}
    try:
        data = resp.json()
    except ValueError:
        return {"ok": False, "error": "malformed_response"}

    task_id = None
    ids = (data.get("data") or {}).get("task_ids")
    if isinstance(ids, list) and ids:
        task_id = ids[0]
    return {"ok": True, "task_id": task_id, "raw": data}


def strelka_scan(base_url: str, file_bytes: bytes,
                 filename: str = "sample.bin",
                 timeout: httpx.Timeout | float = _DEFAULT_TIMEOUT) -> dict:
    """Scan a file with a Strelka cluster (static enrichment, no execution).

    Streams the file to Strelka's frontend ``POST /scan`` endpoint. Strelka
    recursively unpacks and runs its scanners (YARA, metadata extractors, hash
    and entropy scanners) and returns a scan *tree* — it never executes the
    sample, which is why this is a static-tier integration.

    Returns ``{"ok": True, "scan": <json>}`` or
    ``{"ok": False, "error": <reason>}``. Never raises.
    """
    if not base_url:
        return {"ok": False, "error": "strelka not configured"}
    refused = _refusal("strelka", filename, base_url)
    if refused:
        return refused

    url = base_url.rstrip("/") + "/scan"
    files = {"file": (filename, file_bytes, "application/octet-stream")}
    try:
        resp = httpx.post(url, files=files, timeout=timeout)
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"transport: {type(exc).__name__}"}

    if resp.status_code != 200:
        return {"ok": False, "error": f"http_{resp.status_code}"}
    try:
        data = resp.json()
    except ValueError:
        # Strelka can return newline-delimited JSON; hand back the raw text so
        # the caller can decide how to parse it rather than losing the result.
        return {"ok": True, "scan": {"raw_text": resp.text}}
    return {"ok": True, "scan": data}
