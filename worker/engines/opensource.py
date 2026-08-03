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

**Every engine here uploads the sample file to another host, so every one of
them is governed by ``SOVEREIGN_MODE``.** The web service has an egress choke
point of its own and it cannot speak for this process: with sovereign mode on
and ``CAPEV2_URL`` set, ``/api/capabilities`` said "CAPEv2 — Blocked" while this
module uploaded every detonatable sample to it. The check lives in
:class:`_HttpSandboxEngine`, on both ``available()`` and ``run()``.

``requests`` is imported lazily inside the methods so this module imports on a
host without it (the native/qiling-only deployments do not need HTTP client
libs installed). If a submission or poll fails, the engine returns
``ran=False`` with the reason — a flaky external sandbox must not crash the loop.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

from . import baseline
from .base import Engine, Report

log = logging.getLogger("worker.opensource")


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


#: Hosts that are this machine by name. Not resolved — see `_is_internal`.
_LOCAL_NAMES = ("localhost",)


def _host_of(url: str) -> str:
    """The bare host of a URL, without scheme, userinfo, port or path."""
    host = (url or "").strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0]
    host = host.rsplit("@", 1)[-1]
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.strip().lower()


def _is_internal(url: str) -> bool:
    """Is this URL inside the deployment, so that reaching it is not egress?

    MUST match `app/sovereignty.destination_is_internal` exactly — the two
    processes share no code, and `test_the_worker_keeps_the_same_promise.py`
    asserts they agree on a table of cases.

    A hostname is NOT resolved: resolution is a network call, its answer can
    change between the check and the use, and a name that points somewhere
    private today can point anywhere tomorrow.
    """
    import ipaddress

    host = _host_of(url)
    if not host:
        return False
    if host in _LOCAL_NAMES or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(address.is_loopback or address.is_private or address.is_link_local)


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
    """Shared plumbing for submit/poll REST sandboxes.

    THIS IS THE WORKER'S EGRESS CHOKE POINT. Every engine in this module hands a
    whole sample file to a service on another host, and every one of them reaches
    the network through `available()` here. The backend has a choke point of its
    own (`app/sovereignty.py`) and it governs the backend's process; this is a
    separate program with a separate configuration, so sovereign mode meant
    nothing on this side until it was checked here.
    """

    #: The backend's `DESTINATIONS` key for this engine, so a refusal here names
    #: the same thing `/api/capabilities` shows the operator.
    destination = ""

    def __init__(self, config) -> None:
        self.config = config

    def _base(self) -> str:
        raise NotImplementedError

    @property
    def unavailable_reason(self) -> str | None:
        """Why this engine is not being used — printed once at startup.

        A silently-skipped engine and a refused one look identical in a log, and
        that ambiguity is exactly what the sovereignty design exists to remove.
        """
        if self._refused_by_sovereign_mode():
            return (
                f"SOVEREIGN_MODE is on, so this worker will not upload samples to "
                f"{self.name}. Nothing about a sample leaves this deployment. Set "
                f"SOVEREIGN_MODE=false on the worker AND the web service to use it."
            )
        if not self._base():
            return None  # simply not configured, which is the ordinary case
        if _requests() is None:
            return "requests is not installed"
        return None

    def _refused_by_sovereign_mode(self) -> bool:
        """Configured, forbidden, and actually off this machine.

        A destination inside the deployment is not egress. The reference
        deployment runs CAPE at `http://127.0.0.1:8000` — the same host — and
        blocking that stopped nothing from leaving while disabling the whole
        dynamic tier. `_is_internal` is the same rule the web service applies in
        `app/sovereignty.destination_is_internal`, and a test pins the two to the
        same answers.
        """
        base = self._base()
        if not base:
            return False
        if not bool(getattr(self.config, "sovereign_mode", True)):
            return False
        return not _is_internal(base)

    def available(self) -> bool:
        if self._refused_by_sovereign_mode():
            return False
        return bool(self._base()) and _requests() is not None

    def supports(self, family: str) -> bool:
        # External sandboxes handle the same detonatable families the seam
        # offers — and this set has to BE that set, not a copy of it that drifted.
        #
        # `rtf` and `lnk` were added to `_DYNAMIC_FAMILIES` when their analyzers
        # were written and not added here, so the backend offered nine jobs no
        # engine claimed. They are genuinely detonatable: CAPE ships
        # `analyzer/windows/modules/packages/lnk.py` and `doc.py`, and a
        # shortcut whose arguments are an encoded PowerShell is exactly the
        # thing worth running rather than reading.
        #
        # `test_the_worker_claims_every_family_the_backend_offers` compares the
        # two sets directly, so the next family to gain an analyzer cannot
        # silently arrive here missing.
        return family in {"pe", "elf", "script", "office", "pdf", "rtf", "lnk"}

    def _timeout_deadline(self) -> float:
        return time.monotonic() + self.config.engine_timeout_seconds

    def _sovereign_refusal(self) -> Report | None:
        """A Report refusing to upload, or None if egress is permitted.

        `available()` already keeps the agent from reaching this, so it is the
        second lock on the same door — and the one that holds if a future caller
        runs an engine it picked some other way. A door with one lock and a
        promise on it is not what a sovereign deployment is buying.
        """
        if not self._refused_by_sovereign_mode():
            return None
        return Report.refused_sample(
            self.name,
            self.config.worker_name,
            f"Sovereign mode is on: refused to upload this sample to {self.name} "
            f"({self.destination}). No analysis data left this deployment.",
        )


class CuckooEngine(_HttpSandboxEngine):
    """Cuckoo Sandbox REST API (v2 style): /tasks/create/file, /tasks/report/{id}."""

    name = "cuckoo"
    destination = "cuckoo"

    def _base(self) -> str:
        return self.config.cuckoo_url

    def _headers(self) -> dict:
        if self.config.cuckoo_token:
            return {"Authorization": f"Bearer {self.config.cuckoo_token}"}
        return {}

    def run(self, sample_path: str, sha256: str, family: str) -> Report:
        refusal = self._sovereign_refusal()
        if refusal is not None:
            return refusal
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
    destination = "capev2"

    #: Terminal states. CAPE reports through several stages; only these two mean
    #: the JSON is on disk. ``completed`` means the machine finished but the
    #: processing/reporting pass has not, and asking for the report then returns
    #: ``{"error": true, "error_value": "Task is still being analyzed"}``.
    _DONE = {"reported"}
    _FAILED = {"failed_analysis", "failed_processing", "failed_reporting", "banned"}
    #: Failures that are a property of the SAMPLE, so the next attempt produces
    #: exactly the same answer. `failed_analysis` is deliberately absent: it can
    #: also mean a guest crashed mid-run, which is worth retrying, and it is
    #: separated by whether a machine was ever assigned (see `_poll`).
    _TERMINAL = {"failed_processing", "failed_reporting", "banned"}

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

        ``error_value`` is generic on the submission path: every refusal reads
        "Error adding task to database", whatever the reason. The reason itself
        is in the sibling ``errors`` array, and dropping it cost a night. Eight
        corpus samples were refused and the only record anywhere said "Error
        adding task to database" — CAPE does not log this path either
        (``web_utils.py:916`` is a bare return). The real answer, present in the
        response all along, was "Linux binaries analysis isn't enabled".
        """
        if not isinstance(payload, dict):
            return payload, None
        if payload.get("error"):
            message = str(payload.get("error_value") or payload.get("error"))
            for entry in payload.get("errors") or []:
                # [{"<filename>": {"error": "<the actual reason>"}}]
                for value in (entry or {}).values() if isinstance(entry, dict) else ():
                    reason = value.get("error") if isinstance(value, dict) else value
                    if reason and str(reason) not in message:
                        message = f"{message}: {reason}"
            return None, message
        return payload.get("data", payload), None

    def run(self, sample_path: str, sha256: str, family: str) -> Report:
        refusal = self._sovereign_refusal()
        if refusal is not None:
            return refusal
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
                # The sandbox looked at this sample and said no. Retrying sends
                # the identical bytes under the identical name and gets the
                # identical answer, so this is terminal, not "not right now".
                return Report.refused_sample(
                    self.name, self.config.worker_name, f"CAPE refused the sample: {err}"
                )
            task_ids = (data or {}).get("task_ids") or []
            if not task_ids:
                return Report.refused_sample(
                    self.name, self.config.worker_name, f"CAPE returned no task id: {data!r}"
                )
            task_id = task_ids[0]
            report.facts["task_id"] = task_id
            report.facts["external_engine"] = "capev2"

            data = self._poll(requests, base, task_id, report)
            if data is None:
                report.duration_ms = int((time.monotonic() - started) * 1000)
                reason = (
                    report.facts.get("cape_failure")
                    or f"CAPE task {task_id} did not report within "
                    f"{self.config.engine_timeout_seconds}s"
                )
                # NEVER GOT A MACHINE => NEVER WILL. Re-offering it is the
                # infinite re-detonation loop the `refused` marker exists to
                # close; see `_task_never_started`.
                if report.facts.pop("cape_unserviceable", False):
                    return Report.refused_sample(self.name, self.config.worker_name, reason)
                return Report.unavailable(self.name, self.config.worker_name, reason)
        except Exception as exc:  # network / HTTP / JSON
            # THE TYPE, NOT THE MESSAGE.
            #
            # An httpx or requests exception carries the URL it was calling --
            # the detonation host's address and port. The backend copies this
            # string into tiers.dynamic.detail and renders it into the exported
            # PDF, which is the exact publication report._without_infrastructure
            # exists to prevent, from a path it cannot reach because the
            # sentence is composed here on the worker.
            #
            # The type says what went wrong; the address says where we are, and
            # the operator can read that in the worker log.
            log.warning("CAPE call failed: %s", exc)
            return Report.unavailable(
                self.name, self.config.worker_name,
                f"could not reach the external sandbox ({type(exc).__name__})",
            )

        report.duration_ms = int((time.monotonic() - started) * 1000)
        report.ran = True
        _normalise_cuckoo(data, report, prefix="capev2")
        return report

    def _task_never_started(self, requests, base: str, task_id) -> bool:
        """Did this task fail without ever being handed a machine?

        CAPE fails a task instantly when no guest matches its tags — the ARM64
        Sysinternals builds are tagged `arm` and this cluster has only Windows
        x64 guests. Its own record is unambiguous:

            unserviceable  machine=null   started_on=null
            really ran     machine=cape1  started_on=<timestamp>

        Errs toward FALSE: if the probe cannot answer, the failure stays
        transient and the job is retried, which is the harmless direction.
        """
        try:
            view = requests.get(
                f"{base}/tasks/view/{task_id}/",
                headers=self._headers(),
                timeout=self.config.http_timeout_seconds,
            )
            task, _err = self._unwrap(view.json())
        except Exception:
            return False
        if not isinstance(task, dict):
            return False
        return not task.get("machine") and not task.get("started_on")

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
                if self._task_never_started(requests, base, task_id):
                    # No guest could take it: architecture or platform mismatch.
                    # There is no behavioural evidence and there never will be.
                    report.facts["cape_unserviceable"] = True
                    report.facts["cape_failure"] = (
                        f"CAPE task {task_id} ended as {status} without ever being "
                        f"given an analysis machine — no guest on that cluster can "
                        f"run this sample (architecture or platform mismatch). "
                        f"Re-offering it would fail identically."
                    )
                elif status in self._TERMINAL:
                    # It DID run. The sandbox observed the sample and could not
                    # write the observation down — measured here as a process
                    # tree deep enough to exhaust Python's recursion limit in
                    # CAPE's own JSON reporter. That is the sample's shape, so it
                    # is the same on every attempt, and each attempt costs a
                    # five-minute guest slot.
                    report.facts["cape_unserviceable"] = True
                    report.facts["cape_failure"] = (
                        f"CAPE task {task_id} ran to completion on an analysis "
                        f"machine and then ended as {status}: the sandbox observed "
                        f"this sample but could not produce a report from it. That "
                        f"is a property of the sample, so re-offering it would fail "
                        f"identically. The behaviour was seen and is not recorded "
                        f"here — treat the dynamic tier as absent for this sample, "
                        f"not as having found nothing."
                    )
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
    destination = "joesandbox"

    def _base(self) -> str:
        return self.config.joe_url

    def available(self) -> bool:
        if self._refused_by_sovereign_mode():
            return False
        return bool(self.config.joe_url and self.config.joe_apikey) and _requests() is not None

    def run(self, sample_path: str, sha256: str, family: str) -> Report:
        refusal = self._sovereign_refusal()
        if refusal is not None:
            return refusal
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

    # --- identification, which is not behaviour --------------------------------
    # A family the sandbox named, or a configuration block it extracted, does not
    # say what the sample *did* - it says what it *is*. That belongs to the
    # verdict, not the capability model, so it is lifted separately.
    #
    # Only these two. An earlier version also treated any YARA hit as
    # identification, on a measurement over 8 malware and 3 signed installers
    # where it separated them 8/8 and 0/3. A wider benign corpus broke it: a
    # signed WinMerge release matched `embedded_macho` and was called malicious.
    # A rule matching is an observation about content; `detections` and
    # `CAPE.configs` are the sandbox saying it recognises the strain.
    families: list[str] = []
    for det in data.get("detections") or []:
        fam = det.get("family") if isinstance(det, dict) else det
        if fam and str(fam) not in families:
            families.append(str(fam))
    configs: list[str] = []
    cape = data.get("CAPE") or {}
    if isinstance(cape, dict):
        for cfg in cape.get("configs") or []:
            if isinstance(cfg, dict):
                configs.extend(k for k in cfg if not k.startswith("_"))
    if families:
        report.facts["sandbox_families"] = families
    if configs:
        report.facts["extracted_configs"] = sorted(set(configs))

    for fam in families:
        report.add_signal(
            f"{prefix}.detection.{_slug(fam)}",
            f"Identified as {fam} by the sandbox",
            "critical",
            detail=(
                f"The sandbox matched {fam} against its malware rules in process "
                "memory or on disk. This is an identification, not an observed "
                "behaviour."
            ),
            evidence={"family": fam, "categories": ["identification"]},
        )
    for cfg in sorted(set(configs)):
        report.add_signal(
            f"{prefix}.config.{_slug(cfg)}",
            f"{cfg} configuration extracted",
            "critical",
            detail=(
                f"The sandbox recovered a working {cfg} configuration block. "
                "Configuration extraction succeeds only against the real family."
            ),
            evidence={"family": cfg, "categories": ["identification"]},
        )

    # --- which YARA rules matched, and where -----------------------------------
    # CAPE collapses every YARA hit in the whole analysis into ONE signature,
    # `procmem_yara`, described as "Yara detections observed in process dumps,
    # payloads or dropped files". The rule name survives only inside a prose
    # string in its `data` array, and we were discarding it.
    #
    # That is how a signed release of WinMerge came to be called malicious. The
    # rule was `embedded_macho` — three 4-byte magics matched anywhere but offset
    # 0, a coincidence in any multi-megabyte dump — and it hit in a file the
    # installer had legitimately written to disk, not in process memory at all.
    # Nothing in the report said so, so nothing in the report could be argued
    # with. An analyst reading "a YARA rule matched" must be able to see which.
    yara_matches: dict[str, list[str]] = {}

    def _collect_yara(entries: Any, where: str) -> None:
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            for hit in entry.get("yara") or []:
                name = hit.get("name") if isinstance(hit, dict) else hit
                if not name:
                    continue
                seen = yara_matches.setdefault(where, [])
                if str(name) not in seen:
                    seen.append(str(name))

    # procmemory and procdump are both process memory; the rest is disk. The
    # distinction is the difference between "found running in the sample's own
    # address space" and "found in a file it wrote", and they are not equally
    # interesting.
    _collect_yara(data.get("procmemory"), "process_memory")
    _collect_yara(data.get("procdump"), "process_memory")
    _collect_yara(cape.get("payloads") if isinstance(cape, dict) else None, "payload")
    _collect_yara(data.get("dropped"), "dropped_file")
    _collect_yara([(data.get("target") or {}).get("file") or {}], "submitted_sample")
    if yara_matches:
        report.facts["yara_matches"] = {k: sorted(v) for k, v in yara_matches.items()}

    # Behavioural signatures.
    for sig in data.get("signatures", []) or []:
        sev = _CAPE_SEVERITY.get(int(sig.get("severity", 1) or 1), "low")
        name = sig.get("name") or sig.get("description", "signature")
        # Carry the sandbox's OWN classification. Every CAPE signature has a
        # `categories` field, and deriving a capability from it beats inferring
        # one from the signature name: name-matching missed 8 of WannaCry's 22
        # high-severity signals, because a sandbox writes
        # `unbacked_process_creation` where our key said `process_create`. The
        # category on that same signature says "execution", unambiguously.
        cats = sig.get("categories") or []
        if isinstance(cats, str):
            cats = [cats]
        # CAPE 2.5 puts a signature's supporting evidence in `data`, not `marks`.
        # Measured across every report on this host: 0 signatures carry `marks`,
        # 3605 carry `data`, and 2808 of those name the process that raised the
        # signature. So `marks` counted zero for every signal this product has
        # ever ingested, and the pid went with it.
        #
        # The pid matters because CAPE attributes a signature to the ANALYSIS,
        # not to a process. A signed WinMerge release was accused of destruction
        # by `suspicious_iocontrol_codes` whose only two calls came from
        # `mousocoreworker.exe` — Windows Update, in a different branch of the
        # process tree from the sample. Recorded, not acted on: malware
        # legitimately injects into other processes, and 29 malware jobs in this
        # corpus carry a high-severity signature marked only in a foreign
        # process, so discarding those would be a worse error than keeping them.
        # An analyst can now see which process did what; the scorer still does
        # not guess.
        marks = sig.get("marks") or sig.get("data") or []
        pids = sorted(
            {m["pid"] for m in marks if isinstance(m, dict) and isinstance(m.get("pid"), int)}
        )
        evidence: dict[str, Any] = {
            "marks": len(marks),
            "categories": [str(c) for c in cats],
            "confidence": sig.get("confidence"),
        }
        if pids:
            evidence["pids"] = pids
        detail = sig.get("description", "")
        if yara_matches and _slug(name) == "procmem_yara":
            evidence["yara_matches"] = {k: sorted(v) for k, v in yara_matches.items()}
            detail = "{} Matched: {}.".format(
                detail,
                "; ".join(
                    f"{', '.join(sorted(rules))} (in {place.replace('_', ' ')})"
                    for place, rules in sorted(yara_matches.items())
                ),
            ).strip()
        report.add_signal(
            f"{prefix}.{_slug(name)}",
            sig.get("description", name)[:120],
            sev,
            detail=detail,
            evidence=evidence,
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
    # AND `hosts` IS NOT THE SET OF ADDRESSES THAT ANSWERED.
    #
    # The paragraph above is right about `dead_hosts` and wrong about `hosts`,
    # and the wrong half is the one that made a claim. CAPE's
    # `modules/processing/network.py` calls `_add_hosts(connection)` once per
    # PACKET, unconditionally, outside the TCP/UDP/ICMP branches — so every
    # destination the guest ever addressed lands in `hosts`, answered or not.
    # `dead_hosts` is not its complement either: a host is only filed there
    # after >= 3 unanswered retransmissions, so `hosts` is a strict SUPERSET of
    # `dead_hosts` and a single unanswered SYN appears in `hosts` alone.
    #
    # Reading that as "established" produced, across the 293 stored detonations
    # on this deployment: 1344 established entries, of which exactly ONE has a
    # data-bearing flow behind it, and 1326 are simultaneously listed in the
    # SAME report's `attempted`. The report contradicted itself 1326 times.
    #
    # It cannot be otherwise here. The detonation host carries
    # `-A FORWARD -i virbr0 -o <wan> -j DROP`, so no guest can complete an
    # outbound handshake by construction, and "established" was asserted 1344
    # times on a network where it is impossible.
    #
    # `network.tcp` is the only evidence CAPE offers of a completed exchange:
    # `if tcp.data:` is the sole path that appends to `tcp_connections`. HTTP
    # entries count too — a parsed request means bytes moved.
    #
    # UDP is deliberately NOT evidence: CAPE appends a datagram whether or not
    # anything replied. A genuine UDP C2 that did answer will therefore read
    # `attempted`. That is the honest under-claim, and asserting the opposite is
    # the entire defect.
    net = data.get("network", {}) or {}
    established: list[str] = []
    attempted: list[str] = []

    exchanged: set[str] = {
        flow.get("dst") for flow in (net.get("tcp") or []) if isinstance(flow, dict)
    }
    for entry in net.get("http", []) or []:
        if isinstance(entry, dict):
            for key in ("dst", "host", "hostname"):
                value = entry.get(key)
                if isinstance(value, str) and value:
                    exchanged.add(value)
    exchanged.discard(None)

    # `dead_hosts` FIRST, so the `hosts` loop below can tell which addresses are
    # already accounted for. Ordered the other way the de-duplication does
    # nothing, which is how the same IP came to sit in both buckets.
    dead: set[str] = set()
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
            dead.add(str(ip))

    for host in net.get("hosts", []) or []:
        ip = host if isinstance(host, str) else host.get("ip")
        if not ip:
            continue
        # Unchanged: every address is still an indicator either way. This
        # decides what the report CALLS it, not whether it is reported.
        report.add_ioc("ips", ip)
        if ip in exchanged:
            established.append(ip)
        elif str(ip) not in dead:
            # Same `ip:port` shape `attempted` already uses, so an address does
            # not change format when it changes bucket.
            ports = (host.get("ports") or []) if isinstance(host, dict) else []
            attempted.append(f"{ip}:{ports[0]}" if ports else str(ip))

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

    # The endpoint facts are written BELOW the baseline filter now, not above
    # it. `baseline.partition` ran fifteen lines after this block and only over
    # `report.iocs`, so guest-platform noise was correctly stripped from the
    # indicators and left standing in the endpoints: `184.86.251.16` is inside
    # `184.86.251.0/24` in `baseline_networks.txt`, absent from `iocs` on all
    # 249 jobs that saw it, and present in `network_endpoints.established` on
    # all 249 of them. One filter, two lists, one of which quietly bypassed it.

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

    # The same filter, over the same addresses, in the other list. An entry is
    # `ip` or `ip:port`, so the address is split off before it is tested.
    def _not_baseline(entry: str) -> bool:
        return not baseline.noise_reason("ips", entry.rsplit(":", 1)[0])

    established = [e for e in established if _not_baseline(e)]
    attempted = [e for e in attempted if _not_baseline(e)]
    if established or attempted:
        report.facts["network_endpoints"] = {
            "established": established,
            "attempted": attempted,
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
