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
            log.info("no available engine supports family '%s' for %s; skipping", family, public_id)
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
        for job in queue:
            self.process_job(job)
        return len(queue)

    def run_forever(self) -> None:
        log.info(
            "worker '%s' polling %s every %ds",
            self.config.worker_name,
            self.config.api_url,
            self.config.poll_interval_seconds,
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
