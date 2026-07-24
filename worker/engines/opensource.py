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

import time

from .base import Engine, Report

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
                    files={"file": (f"{sha256}.sample", fh)},
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


class CapeV2Engine(CuckooEngine):
    """CAPEv2 is Cuckoo-descended and speaks a compatible REST surface.

    We reuse the Cuckoo flow and the same report normaliser (CAPE reports carry
    a superset with the same ``signatures`` / ``network`` structure).
    """

    name = "capev2"

    def _base(self) -> str:
        return self.config.capev2_url

    def _headers(self) -> dict:
        if self.config.capev2_token:
            return {"Authorization": f"Token {self.config.capev2_token}"}
        return {}


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
def _normalise_cuckoo(data: dict, report: Report) -> None:
    """Turn a Cuckoo/CAPE report JSON into Signals + IOCs."""
    info = data.get("info", {}) or {}
    report.facts["external_score"] = info.get("score")
    report.facts["external_engine"] = "cuckoo/cape"

    # Behavioural signatures.
    for sig in data.get("signatures", []) or []:
        sev = _CAPE_SEVERITY.get(int(sig.get("severity", 1) or 1), "low")
        name = sig.get("name") or sig.get("description", "signature")
        report.add_signal(
            f"cuckoo.{_slug(name)}",
            sig.get("description", name)[:120],
            sev,
            detail=sig.get("description", ""),
            evidence={"marks": len(sig.get("marks", []) or [])},
        )

    # Network IOCs.
    net = data.get("network", {}) or {}
    for host in net.get("hosts", []) or []:
        ip = host if isinstance(host, str) else host.get("ip")
        if ip:
            report.add_ioc("ips", ip)
    for dom in net.get("domains", []) or []:
        name = dom if isinstance(dom, str) else dom.get("domain")
        if name:
            report.add_ioc("domains", name)
    for http in net.get("http", []) or []:
        uri = http.get("uri") if isinstance(http, dict) else None
        if uri:
            report.add_ioc("urls", uri)

    # A timeline from process behaviour, if present.
    procs = (data.get("behavior", {}) or {}).get("processes", []) or []
    for i, proc in enumerate(procs[:50]):
        report.add_event(i, "process", proc.get("process_name", "process"))

    if not report.signals:
        score = info.get("score")
        report.add_signal(
            "cuckoo.completed",
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
