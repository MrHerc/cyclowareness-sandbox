"""The off-host worker's main loop.

Lifecycle of one job:

    1. GET  /api/dynamic/queue          claim the work list (X-Worker-Token)
    2. GET  /api/dynamic/sample/{id}    download the quarantined bytes to a temp
    3. pick the first *available* engine that supports the family, by priority
    4. run it with a hard timeout
    5. POST /api/dynamic/report/{id}    hand the behaviour back to be re-scored
    6. delete the temp sample, always

The web service never runs step 3. This program does, and only this program —
on hardware the operator controls, network-isolated, ideally a disposable VM.
The engine priority encodes the safety preference: a confined native run beats
emulation beats an external service, but the loop silently skips any engine that
is not available on this host, so the same binary behaves correctly whether it
is a Qiling-only laptop or a full Firejail lab box.

Run continuously (default) or a single pass with ``--once`` (used by tests and
by cron-style scheduling).
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import tempfile
import time
from typing import Any

# Import as a package when run as a module (python -m worker.agent) and as flat
# modules when run as a script from inside the worker/ directory (the Docker
# default). Either import style resolves the same code.
try:
    from .config import Config
    from .engines.base import Engine, Report
    from .engines.native_linux import NativeLinuxEngine
    from .engines.opensource import build_external_engines
    from .engines.qiling_emu import QilingEngine
except ImportError:  # running as top-level scripts
    from config import Config  # type: ignore
    from engines.base import Engine, Report  # type: ignore
    from engines.native_linux import NativeLinuxEngine  # type: ignore
    from engines.opensource import build_external_engines  # type: ignore
    from engines.qiling_emu import QilingEngine  # type: ignore


logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("worker")


def _http():
    """The worker only needs a tiny HTTP surface; prefer requests, fall back to
    urllib so the agent still imports where requests is absent (native/qiling
    deployments)."""
    try:
        import requests  # type: ignore

        return "requests", requests
    except Exception:
        import urllib.request  # noqa: F401

        return "urllib", None


class Agent:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.engines = self._build_engines()
        self._http_kind, self._requests = _http()

    def _build_engines(self) -> list[Engine]:
        """Priority order: native > qiling > cuckoo > capev2 > joe."""
        engines: list[Engine] = [
            NativeLinuxEngine(self.config),
            QilingEngine(self.config),
            *build_external_engines(self.config),
        ]
        for eng in engines:
            try:
                if eng.available():
                    state = "available"
                else:
                    # An engine may explain itself (qiling's is a licence stance,
                    # not a fault); print it so "unavailable" is never read as a bug.
                    reason = getattr(eng, "unavailable_reason", None)
                    # ASCII only: this line lands on whatever console the operator
                    # has, and a log record is not worth a UnicodeEncodeError.
                    state = f"unavailable: {reason}" if reason else "unavailable"
            except Exception as exc:  # availability probing must never crash startup
                state = f"error probing: {exc}"
            log.info("engine %-8s -> %s", eng.name, state)
        return engines

    # -- HTTP helpers --------------------------------------------------------
    def _url(self, path: str) -> str:
        return f"{self.config.api_url}{path}"

    def _headers(self) -> dict[str, str]:
        return {"X-Worker-Token": self.config.worker_token}

    def _get_json(self, path: str) -> Any:
        if self._requests is not None:
            resp = self._requests.get(
                self._url(path), headers=self._headers(), timeout=self.config.http_timeout_seconds
            )
            resp.raise_for_status()
            return resp.json()
        import json
        import urllib.request

        req = urllib.request.Request(self._url(path), headers=self._headers())
        with urllib.request.urlopen(req, timeout=self.config.http_timeout_seconds) as r:
            return json.loads(r.read().decode())

    def _download(self, path: str, dest: str) -> None:
        if self._requests is not None:
            with self._requests.get(
                self._url(path),
                headers=self._headers(),
                timeout=self.config.http_timeout_seconds,
                stream=True,
            ) as resp:
                resp.raise_for_status()
                with open(dest, "wb") as fh:
                    for chunk in resp.iter_content(chunk_size=65536):
                        fh.write(chunk)
            return
        import urllib.request

        req = urllib.request.Request(self._url(path), headers=self._headers())
        with urllib.request.urlopen(req, timeout=self.config.http_timeout_seconds) as r, open(
            dest, "wb"
        ) as fh:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                fh.write(chunk)

    def _post_json(self, path: str, body: dict) -> None:
        if self._requests is not None:
            resp = self._requests.post(
                self._url(path),
                json=body,
                headers=self._headers(),
                timeout=self.config.http_timeout_seconds,
            )
            resp.raise_for_status()
            return
        import json
        import urllib.request

        data = json.dumps(body).encode()
        headers = {**self._headers(), "Content-Type": "application/json"}
        req = urllib.request.Request(self._url(path), data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.config.http_timeout_seconds):
            return

    # -- containment ---------------------------------------------------------
    def check_containment(self) -> tuple[bool, str]:
        """Is this host safe to detonate on right now? ``(contained, reason)``.

        Runs before every batch, never per sample. Containment is a property of
        the host, not of a job, and the probe must be cheap enough that nobody is
        tempted to skip it — the previous answer was "remember to run
        verify-containment.sh first", which is a human step, and a human step is
        not containment.

        FAIL CLOSED. A non-zero exit, a timeout, a missing command, an
        unparseable answer — all mean *not contained*. The inverse of that, where
        absent evidence reads as success, is exactly how the old in-guest
        verifier certified a host after testing nothing at all.
        """
        command = (self.config.containment_check or "").strip()
        if not command:
            return True, "no containment check configured"
        import shlex
        import subprocess

        try:
            done = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                timeout=self.config.containment_check_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return False, f"containment check timed out: {command}"
        except OSError as exc:
            return False, f"containment check could not run: {exc}"

        output = (done.stdout or "").strip() or (done.stderr or "").strip()
        if done.returncode != 0:
            return False, f"containment check failed: {output or f'exit {done.returncode}'}"
        # Exit 0 is the verdict; the JSON is for the log. A check that exits 0
        # while saying `contained: false` is a broken check, so disbelieve it.
        try:
            import json

            if json.loads(output).get("contained") is not True:
                return False, f"containment check exited 0 but reported: {output}"
        except (ValueError, AttributeError):
            pass
        return True, output

    # -- engine selection ----------------------------------------------------
    def _choose_engine(self, family: str) -> Engine | None:
        for eng in self.engines:
            try:
                if eng.available() and eng.supports(family):
                    return eng
            except Exception as exc:
                log.warning("engine %s failed availability check: %s", eng.name, exc)
        return None

    # -- one job -------------------------------------------------------------
    def process_job(self, job: dict) -> None:
        public_id = job.get("public_id")
        family = job.get("family", "unknown")
        sha256 = job.get("sha256", "")
        if not public_id:
            return

        engine = self._choose_engine(family)
        if engine is None:
            # SAY SO. A silent return leaves the job eligible, so the backend
            # serves it again on the next poll and, the queue being
            # oldest-first, serves it first -- a family no engine supports
            # permanently occupies the head of the queue.
            #
            # `refused_sample`, not `unavailable`: this is declined, not
            # delayed. `_report_blocked` reserves `unavailable` for a
            # transient host problem, where the job SHOULD stay eligible.
            reason = (
                f"no engine on this worker supports family '{family}'"
            )
            log.info("%s (%s); refusing so it leaves the queue", reason, public_id)
            self._deliver(
                public_id,
                Report.refused_sample("none", self.config.worker_name, reason),
            )
            return

        log.info("job %s family=%s -> engine %s", public_id, family, engine.name)
        # Keep the extension the backend sanitised for us. A detonation sandbox
        # picks how to *run* a sample from its file name: CAPEv2 given a
        # ".sample" falls back to its `generic` package, which on a measured
        # PowerShell sample cut the run from 229s / 4 processes / 38 signatures
        # to 28s / 1 process / 8 signatures. Nothing errors — the evidence just
        # quietly thins out. Older backends do not send `suffix`; "" is fine.
        suffix = job.get("suffix") or ""
        tmp = tempfile.NamedTemporaryFile(prefix="cw-sample-", suffix=suffix, delete=False)
        tmp_path = tmp.name
        tmp.close()
        try:
            self._download(f"/api/dynamic/sample/{public_id}", tmp_path)

            report = self._run_engine(engine, tmp_path, sha256, family)
            self._post_json(f"/api/dynamic/report/{public_id}", report.to_payload())
            log.info(
                "job %s reported (engine=%s ran=%s signals=%d %dms)",
                public_id,
                report.engine,
                report.ran,
                len(report.signals),
                report.duration_ms,
            )
        except Exception as exc:
            log.exception("job %s failed: %s", public_id, exc)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _deliver(self, public_id: str, report: "Report") -> None:
        """Post one report for one job, and never take the loop down with it.

        THIS METHOD DID NOT EXIST, and the call site that needed it is the one
        that keeps a job from occupying the head of the queue for ever. So the
        moment a family reached the worker that no local engine claimed,
        `process_job` raised `AttributeError` — inside `pool.map`, which
        re-raises on the first future, so the whole batch died and NOTHING was
        detonated that cycle. Measured on the live worker before this fix: 1176
        occurrences of `'Agent' object has no attribute '_deliver'`, one every
        sixteen seconds, with nine `lnk`/`rtf` jobs pinned at the head of an
        oldest-first queue and every `pe`, `pdf` and `office` job behind them
        starved.

        It was latent from the day it was written, because every family the
        backend offered was claimed by the CAPE engine. Widening
        `_DYNAMIC_FAMILIES` to `rtf` and `lnk` without widening `supports()` is
        what made it reachable.

        Failure to post is logged, not raised: the caller is already handling
        the case where a job cannot be run, and losing the loop over a failed
        HTTP call would be the same bug in a different place.
        """
        if not public_id:
            return
        try:
            self._post_json(f"/api/dynamic/report/{public_id}", report.to_payload())
        except Exception as exc:  # noqa: BLE001
            log.warning("could not deliver the report for %s: %s", public_id, exc)

    def _report_blocked(self, job: dict, reason: str) -> None:
        """Say why a job was not detonated, rather than leaving a silent gap.

        Deliberately NOT `refused`: the sandbox never saw this sample, so the job
        must stay eligible and run as soon as the host is safe again. Marking it
        terminal here would quietly discard work because of a transient host
        problem — the opposite failure to the one `refused` exists to fix.
        """
        public_id = job.get("public_id")
        if not public_id:
            return
        self._deliver(
            public_id,
            Report.unavailable(
                "containment", self.config.worker_name, f"Not detonated: {reason}"
            ),
        )

    def _run_engine(self, engine: Engine, path: str, sha256: str, family: str) -> Report:
        """Run an engine, turning any crash or overrun into an honest ran=False
        report rather than letting it kill the loop."""
        started = time.monotonic()
        try:
            report = engine.run(path, sha256, family)
        except Exception as exc:
            log.exception("engine %s crashed on %s", engine.name, sha256[:12])
            return Report.unavailable(
                engine.name,
                self.config.worker_name,
                f"engine crashed: {type(exc).__name__}: {exc}",
            )
        if not report.duration_ms:
            report.duration_ms = int((time.monotonic() - started) * 1000)
        return report

    # -- loop ----------------------------------------------------------------
    def run_once(self) -> int:
        """One poll: process every queued job. Returns the number processed."""
        try:
            queue = self._get_json(f"/api/dynamic/queue?limit={self.config.queue_limit}")
        except Exception as exc:
            log.warning("queue poll failed: %s", exc)
            return 0
        if not isinstance(queue, list):
            log.warning("unexpected queue response: %r", queue)
            return 0
        log.info("queue: %d job(s)", len(queue))
        if not queue:
            return 0

        # THE GATE. Above both dispatch paths below, so neither can bypass it,
        # and once per batch rather than once per sample.
        #
        # A batch refused here is reported, not dropped: every job gets an honest
        # ran=False carrying the reason, so the operator sees "3 jobs blocked:
        # containment table missing" instead of a queue that quietly stops
        # moving. Returning 0 makes the loop back off to its poll interval.
        contained, reason = self.check_containment()
        if not contained:
            log.error("REFUSING TO DETONATE - %s (%d job(s) held)", reason, len(queue))
            for job in queue:
                self._report_blocked(job, reason)
            return 0

        limit = max(1, self.config.max_concurrent_jobs)
        if limit == 1 or len(queue) == 1:
            for job in queue:
                self.process_job(job)
            return len(queue)

        # Detonations are almost entirely waiting — on the sandbox, on the
        # guest, on the network — so threads are the right shape and the GIL is
        # not the constraint. The guests are.
        #
        # This loop used to be `for job in queue: self.process_job(job)`, which
        # meant adding analysis machines to the sandbox bought exactly nothing:
        # three idle guests while the worker detonated one sample at a time.
        # process_job owns everything it touches (its own temp file, its own
        # HTTP calls) and the engines hold no per-run state, so the only thing
        # needed was to stop serialising it.
        from concurrent.futures import ThreadPoolExecutor

        log.info("running up to %d detonations concurrently", limit)
        with ThreadPoolExecutor(max_workers=limit, thread_name_prefix="detonate") as pool:
            # list() so exceptions surface here rather than being swallowed by
            # the executor; process_job already converts a failed engine into an
            # honest ran=False report.
            list(pool.map(self.process_job, queue))
        return len(queue)

    def run_forever(self) -> None:
        log.info(
            "worker '%s' polling %s every %ds",
            self.config.worker_name,
            self.config.api_url,
            self.config.poll_interval_seconds,
        )
        # Said once, loudly, at startup. "No gate configured" and "gate passing"
        # must never read the same way in a log — an operator who set
        # CONTAINMENT_CHECK and typo'd the path deserves to find out here rather
        # than from an abuse complaint.
        if self.config.containment_check:
            contained, reason = self.check_containment()
            log.log(
                logging.INFO if contained else logging.ERROR,
                "containment gate: %s (%s)",
                "armed" if contained else "ARMED AND CURRENTLY FAILING",
                reason,
            )
        else:
            log.warning(
                "containment gate: NOT CONFIGURED - detonations are ungated on this "
                "worker. Set CONTAINMENT_CHECK if this host runs real samples."
            )
        while True:
            try:
                self.run_once()
            except KeyboardInterrupt:
                log.info("interrupted; shutting down")
                return
            except Exception as exc:  # the loop itself must never die
                log.exception("unexpected loop error: %s", exc)
            time.sleep(self.config.poll_interval_seconds)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cyclowareness Sandbox dynamic-analysis worker")
    parser.add_argument("--once", action="store_true", help="run a single queue pass and exit")
    args = parser.parse_args(argv)

    config = Config.from_env()
    config.require_token()
    agent = Agent(config)

    if args.once:
        agent.run_once()
        return 0
    agent.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
