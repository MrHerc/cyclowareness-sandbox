"""Clients for external open-source / commercial sandboxes.

These engines do not detonate anything on the worker host. They submit the
sample to a sandbox the operator already runs (Cuckoo, CAPEv2) or subscribes to
(Joe Sandbox), poll for the report, and normalise that sandbox's behavioural
JSON into our Report vocabulary. This is the "open-source sandbox integration"
axis of the brief's scoring: the same Signal shape whether behaviour came from
our native jail, from Qiling, or from a third-party detonation service.

Each client is ``available()`` only when its base URL is configured, so an
operator opts into exactly the integrations they run. All three share the same
normalisation idea: pull the list of behavioural indicators / signatures the
sandbox emitted, map each to a Signal with a severity, and lift network IOCs.

``requests`` is imported lazily inside the methods so this module imports on a
host without it (the native/qiling-only deployments do not need HTTP client
libs installed). If a submission or poll fails, the engine returns
``ran=False`` with the reason — a flaky external sandbox must not crash the loop.
"""
from __future__ import annotations

import os
import time
from typing import Any

from . import baseline
from .base import Engine, Report


def _submission_name(sample_path: str, sha256: str) -> str:
    """The file name to submit under: content hash + the real extension.

    The extension is not decoration. CAPEv2 (and Cuckoo) choose the analysis
    *package* from the file name, so a sample handed over as ``<hash>.sample``
    lands on the `generic` package. Measured against a live CAPE 2.5 with one
    PowerShell sample: correct name -> 229s, 4 processes, 38 signatures;
    ``.sample`` -> 28s, 1 process, 8 signatures. Neither run errored, which is
    exactly why this was worth pinning down.

    The stem stays the content hash, so nothing attacker-controlled reaches the
    sandbox's file system through this path.
    """
    ext = os.path.splitext(sample_path)[1]
    return f"{sha256}{ext}" if ext else f"{sha256}.sample"

# Map a coarse Cuckoo/CAPE signature severity (0..3+) to our severity words.
_CAPE_SEVERITY = {0: "info", 1: "low", 2: "medium", 3: "high"}


def _requests():
    """Import requests lazily; return None if it is not installed."""
    try:
        import requests  # type: ignore

        return requests
    except Exception:
        return None


def _severity_from_score(score: float) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    if score > 0:
        return "low"
    return "info"


class _HttpSandboxEngine(Engine):
    """Shared plumbing for submit/poll REST sandboxes."""

    def __init__(self, config) -> None:
        self.config = config

    def _base(self) -> str:
        raise NotImplementedError

    def available(self) -> bool:
        return bool(self._base()) and _requests() is not None

    def supports(self, family: str) -> bool:
        # External sandboxes handle the same detonatable families the seam offers.
        return family in {"pe", "elf", "script", "office", "pdf"}

    def _timeout_deadline(self) -> float:
        return time.monotonic() + self.config.engine_timeout_seconds


class CuckooEngine(_HttpSandboxEngine):
    """Cuckoo Sandbox REST API (v2 style): /tasks/create/file, /tasks/report/{id}."""

    name = "cuckoo"

    def _base(self) -> str:
        return self.config.cuckoo_url

    def _headers(self) -> dict:
        if self.config.cuckoo_token:
            return {"Authorization": f"Bearer {self.config.cuckoo_token}"}
        return {}

    def run(self, sample_path: str, sha256: str, family: str) -> Report:
        requests = _requests()
        if requests is None:
            return Report.unavailable(self.name, self.config.worker_name, "requests not installed")
        base = self._base()
        report = self._report(self.config.worker_name)
        started = time.monotonic()
        try:
            with open(sample_path, "rb") as fh:
                resp = requests.post(
                    f"{base}/tasks/create/file",
                    files={"file": (_submission_name(sample_path, sha256), fh)},
                    headers=self._headers(),
                    timeout=self.config.http_timeout_seconds,
                )
            resp.raise_for_status()
            task_id = resp.json().get("task_id")
            if task_id is None:
                return Report.unavailable(
                    self.name, self.config.worker_name, "Cuckoo did not return a task_id"
                )
            report.facts["task_id"] = task_id

            data = self._poll(requests, base, task_id)
            if data is None:
                report.duration_ms = int((time.monotonic() - started) * 1000)
                return Report.unavailable(
                    self.name,
                    self.config.worker_name,
                    f"Cuckoo task {task_id} did not finish within "
                    f"{self.config.engine_timeout_seconds}s",
                )
        except Exception as exc:  # network / HTTP / JSON
            return Report.unavailable(
                self.name, self.config.worker_name, f"Cuckoo error: {type(exc).__name__}: {exc}"
            )

        report.duration_ms = int((time.monotonic() - started) * 1000)
        report.ran = True
        _normalise_cuckoo(data, report)
        return report

    def _poll(self, requests, base: str, task_id) -> dict | None:
        deadline = self._timeout_deadline()
        while time.monotonic() < deadline:
            try:
                st = requests.get(
                    f"{base}/tasks/view/{task_id}",
                    headers=self._headers(),
                    timeout=self.config.http_timeout_seconds,
                )
                status = (st.json().get("task", {}) or {}).get("status")
            except Exception:
                status = None
            if status == "reported":
                rep = requests.get(
                    f"{base}/tasks/report/{task_id}",
                    headers=self._headers(),
                    timeout=self.config.http_timeout_seconds,
                )
                rep.raise_for_status()
                return rep.json()
            if status in ("failed_analysis", "failed_processing"):
                return None
            time.sleep(min(self.config.poll_interval_seconds, 10))
        return None


class CapeV2Engine(_HttpSandboxEngine):
    """CAPEv2's own REST surface — which is *not* Cuckoo's, despite the ancestry.

    This class used to subclass :class:`CuckooEngine` and inherit its request
    flow. Checked against a real CAPEv2 2.5 instance, every part of that flow was
    wrong, and each part failed in a way that would have been misread:

    * CAPE serves the API under ``/apiv2/``. ``/tasks/create/file`` is a 404.
    * Every route is declared ``r"^…/$"`` and the app runs with ``APPEND_SLASH``.
      A POST to the slashless path does not redirect — Django raises and returns
      **HTTP 500**, because it cannot replay a POST body to the slash URL. So the
      one call that matters failed hardest.
    * Submission answers ``{"data": {"task_ids": [1]}}``, not ``{"task_id": 1}``.
      Reading ``task_id`` yields ``None``, and the old code turned that into
      "CAPE did not return a task_id" — reporting a *successful* submission as an
      unavailable engine.
    * The report lives at ``tasks/get/report/{id}/json/``; ``tasks/report/{id}``
      does not exist.

    Status comes from ``tasks/status/{id}/`` (``{"data": "pending"}``) rather than
    the nested ``task.status`` of Cuckoo's ``tasks/view``.
    """

    name = "capev2"

    #: Terminal states. CAPE reports through several stages; only these two mean
    #: the JSON is on disk. ``completed`` means the machine finished but the
    #: processing/reporting pass has not, and asking for the report then returns
    #: ``{"error": true, "error_value": "Task is still being analyzed"}``.
    _DONE = {"reported"}
    _FAILED = {"failed_analysis", "failed_processing", "failed_reporting", "banned"}

    def _base(self) -> str:
        """The API root, tolerating a URL configured with or without /apiv2."""
        base = (self.config.capev2_url or "").rstrip("/")
        if not base:
            return ""
        return base if base.endswith("/apiv2") else f"{base}/apiv2"

    def _headers(self) -> dict:
        if self.config.capev2_token:
            return {"Authorization": f"Token {self.config.capev2_token}"}
        return {}

    @staticmethod
    def _unwrap(payload: dict) -> tuple[Any, str | None]:
        """CAPE wraps everything in ``{error, data}``; return ``(data, error)``.

        ``error`` is ``[]`` on success for create and ``False`` for reads, so it
        is truthiness — not presence — that signals a failure.
        """
        if not isinstance(payload, dict):
            return payload, None
        if payload.get("error"):
            return None, str(payload.get("error_value") or payload.get("error"))
        return payload.get("data", payload), None

    def run(self, sample_path: str, sha256: str, family: str) -> Report:
        requests = _requests()
        if requests is None:
            return Report.unavailable(self.name, self.config.worker_name, "requests not installed")
        base = self._base()
        report = self._report(self.config.worker_name)
        started = time.monotonic()

        try:
            with open(sample_path, "rb") as fh:
                resp = requests.post(
                    f"{base}/tasks/create/file/",
                    files={"file": (_submission_name(sample_path, sha256), fh)},
                    headers=self._headers(),
                    timeout=self.config.http_timeout_seconds,
                )
            resp.raise_for_status()
            data, err = self._unwrap(resp.json())
            if err:
                return Report.unavailable(self.name, self.config.worker_name, f"CAPE refused the sample: {err}")
            task_ids = (data or {}).get("task_ids") or []
            if not task_ids:
                return Report.unavailable(
                    self.name, self.config.worker_name, f"CAPE returned no task id: {data!r}"
                )
            task_id = task_ids[0]
            report.facts["task_id"] = task_id
            report.facts["external_engine"] = "capev2"

            data = self._poll(requests, base, task_id, report)
            if data is None:
                report.duration_ms = int((time.monotonic() - started) * 1000)
                return Report.unavailable(
                    self.name,
                    self.config.worker_name,
                    report.facts.get("cape_failure")
                    or f"CAPE task {task_id} did not report within "
                    f"{self.config.engine_timeout_seconds}s",
                )
        except Exception as exc:  # network / HTTP / JSON
            return Report.unavailable(
                self.name, self.config.worker_name, f"CAPE error: {type(exc).__name__}: {exc}"
            )

        report.duration_ms = int((time.monotonic() - started) * 1000)
        report.ran = True
        _normalise_cuckoo(data, report, prefix="capev2")
        return report

    def _poll(self, requests, base: str, task_id, report: Report) -> dict | None:
        deadline = self._timeout_deadline()
        while time.monotonic() < deadline:
            status = None
            try:
                st = requests.get(
                    f"{base}/tasks/status/{task_id}/",
                    headers=self._headers(),
                    timeout=self.config.http_timeout_seconds,
                )
                # The API is rate limited (api.conf defaults to 5/m). A 429 is a
                # "come back later", not a failed analysis - keep waiting.
                if st.status_code != 429:
                    status, _ = self._unwrap(st.json())
            except Exception:
                status = None

            if status in self._FAILED:
                report.facts["cape_failure"] = f"CAPE task {task_id} ended as {status}"
                return None
            if status in self._DONE:
                rep = requests.get(
                    f"{base}/tasks/get/report/{task_id}/json/",
                    headers=self._headers(),
                    timeout=self.config.http_timeout_seconds,
                )
                rep.raise_for_status()
                payload, err = self._unwrap(rep.json())
                if err:
                    # 'still being analyzed' races the status flip; retry.
                    time.sleep(min(self.config.poll_interval_seconds, 10))
                    continue
                return payload
            time.sleep(min(self.config.poll_interval_seconds, 10))
        return None


class JoeSandboxEngine(_HttpSandboxEngine):
    """Joe Sandbox Cloud/On-prem v2 API (jbxapi-style REST)."""

    name = "joe"

    def _base(self) -> str:
        return self.config.joe_url

    def available(self) -> bool:
        return bool(self.config.joe_url and self.config.joe_apikey) and _requests() is not None

    def run(self, sample_path: str, sha256: str, family: str) -> Report:
        requests = _requests()
        if requests is None:
            return Report.unavailable(self.name, self.config.worker_name, "requests not installed")
        base = self._base()
        report = self._report(self.config.worker_name)
        started = time.monotonic()
        try:
            with open(sample_path, "rb") as fh:
                resp = requests.post(
                    f"{base}/v2/submission/new",
                    data={"apikey": self.config.joe_apikey, "accept-tac": "1"},
                    files={"sample": (f"{sha256}.sample", fh)},
                    timeout=self.config.http_timeout_seconds,
                )
            resp.raise_for_status()
            submission_id = (resp.json().get("data", {}) or {}).get("submission_id")
            if submission_id is None:
                return Report.unavailable(
                    self.name, self.config.worker_name, "Joe Sandbox returned no submission_id"
                )
            report.facts["submission_id"] = submission_id

            info = self._poll(requests, base, submission_id)
            if info is None:
                report.duration_ms = int((time.monotonic() - started) * 1000)
                return Report.unavailable(
                    self.name,
                    self.config.worker_name,
                    f"Joe submission {submission_id} did not finish in time",
                )
        except Exception as exc:
            return Report.unavailable(
                self.name, self.config.worker_name, f"Joe Sandbox error: {type(exc).__name__}: {exc}"
            )

        report.duration_ms = int((time.monotonic() - started) * 1000)
        report.ran = True
        _normalise_joe(info, report)
        return report

    def _poll(self, requests, base: str, submission_id) -> dict | None:
        deadline = self._timeout_deadline()
        while time.monotonic() < deadline:
            try:
                st = requests.post(
                    f"{base}/v2/submission/info",
                    data={"apikey": self.config.joe_apikey, "submission_id": submission_id},
                    timeout=self.config.http_timeout_seconds,
                )
                data = (st.json().get("data", {}) or {})
                status = data.get("status")
            except Exception:
                data, status = {}, None
            if status == "finished":
                return data
            time.sleep(min(self.config.poll_interval_seconds, 10))
        return None


# --- normalisers -------------------------------------------------------------
def _normalise_cuckoo(data: dict, report: Report, prefix: str = "cuckoo") -> None:
    """Turn a Cuckoo/CAPE report JSON into Signals + IOCs.

    ``prefix`` names the engine that actually produced the finding, because the
    signal id is provenance: a CAPE detonation must not surface downstream as
    ``cuckoo.*``. The two report schemas genuinely do share ``signatures`` /
    ``network`` / ``behavior``, which is why one normaliser serves both.
    """
    info = data.get("info", {}) or {}
    report.facts["external_score"] = info.get("score")
    report.facts.setdefault("external_engine", "cuckoo/cape")

    # Behavioural signatures.
    for sig in data.get("signatures", []) or []:
        sev = _CAPE_SEVERITY.get(int(sig.get("severity", 1) or 1), "low")
        name = sig.get("name") or sig.get("description", "signature")
        report.add_signal(
            f"{prefix}.{_slug(name)}",
            sig.get("description", name)[:120],
            sev,
            detail=sig.get("description", ""),
            evidence={"marks": len(sig.get("marks", []) or [])},
        )

    # Network IOCs.
    #
    # `dead_hosts` is not an afterthought here, it is the main event. A sandbox
    # worth running is network-isolated, so a sample's command-and-control never
    # completes a handshake: the endpoint it *tried* to reach lands in
    # `dead_hosts` and only successfully-contacted addresses reach `hosts`.
    # Measured on this deployment with a probe dialling 203.0.113.77:443 and
    # 198.51.100.23:8080 — both appeared in `dead_hosts`, neither in `hosts`,
    # while `hosts` held nothing but two CDN addresses. Reading only `hosts`
    # therefore discards every real indicator and keeps the noise: exactly
    # backwards, and silent about it.
    #
    # A refused connection is still an indicator — arguably a cleaner one, since
    # it shows intent without the sample getting what it wanted. Both go into the
    # IOC buckets; which of the two it was is preserved in facts, because
    # "attempted" and "established" mean different things to an investigator.
    net = data.get("network", {}) or {}
    established: list[str] = []
    attempted: list[str] = []

    for host in net.get("hosts", []) or []:
        ip = host if isinstance(host, str) else host.get("ip")
        if ip:
            report.add_ioc("ips", ip)
            established.append(ip)

    for entry in net.get("dead_hosts", []) or []:
        if isinstance(entry, (list, tuple)):
            ip = entry[0] if entry else None
            port = entry[1] if len(entry) > 1 else None
        elif isinstance(entry, dict):
            ip, port = entry.get("ip"), entry.get("port")
        else:
            ip, port = entry, None
        if ip:
            report.add_ioc("ips", str(ip))
            attempted.append(f"{ip}:{port}" if port else str(ip))

    for dom in net.get("domains", []) or []:
        name = dom if isinstance(dom, str) else dom.get("domain")
        if name:
            report.add_ioc("domains", name)

    # DNS carries names the sample asked for even when nothing was reachable,
    # plus the addresses behind them. Both are indicators.
    for query in net.get("dns", []) or []:
        if not isinstance(query, dict):
            continue
        request = query.get("request")
        if request:
            report.add_ioc("domains", request)
        # A CNAME chain and its addresses are how one name resolved, not separate
        # indicators. If the name asked for is platform noise, its whole chain is
        # too — otherwise suppressing `cdn.onenote.net` still leaks
        # `cdn.onenote.net.edgekey.net` and `e1553.dspg.akamaiedge.net` into the
        # report, and the suffix list has to grow forever chasing CDN plumbing.
        # The request itself is still added above, so the filter records it and
        # the suppression stays auditable.
        if request and baseline.noise_reason("domains", request):
            continue
        for answer in query.get("answers", []) or []:
            if not isinstance(answer, dict):
                continue
            if answer.get("type") in ("A", "AAAA") and answer.get("data"):
                report.add_ioc("ips", answer["data"])
            elif answer.get("type") == "CNAME" and answer.get("data"):
                report.add_ioc("domains", answer["data"])

    for http in net.get("http", []) or []:
        uri = http.get("uri") if isinstance(http, dict) else None
        if uri:
            report.add_ioc("urls", uri)

    if established or attempted:
        report.facts["network_endpoints"] = {
            "established": established,
            "attempted": attempted,
        }

    # A timeline from process behaviour, if present.
    procs = (data.get("behavior", {}) or {}).get("processes", []) or []
    for i, proc in enumerate(procs[:50]):
        report.add_event(i, "process", proc.get("process_name", "process"))

    # Drop the guest OS's own chatter, and say so. An idle Windows guest reaches
    # ~12 endpoints before a sample does anything; reported as IOCs they make
    # every detonation look busy and none of it credible. What was removed is
    # recorded rather than discarded - a filter an analyst cannot inspect is a
    # filter they cannot trust.
    report.iocs, suppressed = baseline.partition(report.iocs)
    if suppressed:
        report.facts["iocs_suppressed"] = {
            "count": len(suppressed),
            "entries": suppressed[:50],
            "basis": "idle-guest baseline: see worker/engines/baseline.py",
        }

    if not report.signals:
        score = info.get("score")
        report.add_signal(
            f"{prefix}.completed",
            "External sandbox completed with no flagged signatures",
            _severity_from_score(float(score or 0)),
            detail=f"Cuckoo/CAPE score: {score}",
        )


def _normalise_joe(data: dict, report: Report) -> None:
    """Joe Sandbox submission info -> Signals. The rich behavioural JSON lives
    behind a separate report download; here we surface the classification and
    detection Joe already computed, which is what moves a verdict."""
    detection = data.get("detection") or data.get("classification")
    score = data.get("score")
    report.facts["external_score"] = score
    report.facts["external_engine"] = "joesandbox"
    report.facts["detection"] = detection

    if detection in ("malicious", "suspicious"):
        report.add_signal(
            f"joe.{detection}",
            f"Joe Sandbox classified the sample as {detection}",
            "critical" if detection == "malicious" else "high",
            detail=f"Joe Sandbox detection={detection}, score={score}.",
        )
    else:
        report.add_signal(
            "joe.completed",
            "Joe Sandbox analysis completed",
            _severity_from_score(float(score or 0)),
            detail=f"detection={detection}, score={score}",
        )

    for name in data.get("threatname", []) if isinstance(data.get("threatname"), list) else []:
        report.add_signal(
            f"joe.threat.{_slug(name)}",
            f"Threat name: {name}",
            "high",
            detail=name,
        )


def _slug(text: str) -> str:
    out = "".join(c.lower() if c.isalnum() else "_" for c in str(text))
    return "_".join(p for p in out.split("_") if p)[:48] or "signature"


# Convenient list for the agent to instantiate.
def build_external_engines(config) -> list[Engine]:
    return [CuckooEngine(config), CapeV2Engine(config), JoeSandboxEngine(config)]
