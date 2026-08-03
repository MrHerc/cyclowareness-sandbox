#!/usr/bin/env python3
"""Recompute `network_endpoints` on stored detonations, from the CAPE reports.

WHY THIS EXISTS AND A RE-ANALYSIS DOES NOT DO IT. `pipeline._result_from_stored`
copies a carried-forward analyzer's `facts` byte for byte, and `_needs_dynamic`
returns False for a job whose dynamic tier already ran — so the worker fix
reaches future detonations only. Tonight's sweep re-completed all 293 affected
rows and every one still carried the wrong list; that is the proof, not a guess.

The truth is still on disk: each job records its CAPE `task_id`, and every
report is under /cape/<task>/reports/. So the lists are rebuilt with exactly the
rule the fixed worker now applies:

  established  an address with a data-bearing TCP flow (`network.tcp`, which
               CAPE only fills when `tcp.data` is non-empty) or a parsed HTTP
               request. UDP is not evidence: CAPE records a datagram whether or
               not anything answered.
  attempted    everything else the guest addressed, `dead_hosts` first so an
               address cannot land in both lists.

  and both lists pass the idle-guest baseline, which previously ran after the
  facts were written and only over the indicators.

`--apply` writes. Without it this only reports what it would change.
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, "/app")
sys.path.insert(0, "/worker")

from sqlalchemy import select

from app.db import session_scope
from app.engine.models import SandboxJob

from engines import baseline  # noqa: E402  (worker package, mounted at /worker)

CAPE = Path(os.environ.get("CAPE_ANALYSES", "/cape"))


def _report_for(task_id) -> dict | None:
    """CAPE writes report.json under a couple of layouts across versions."""
    for candidate in (
        CAPE / str(task_id) / "reports" / "report.json",
        CAPE / str(task_id) / "reports" / "lite.json",
    ):
        if candidate.exists():
            try:
                return json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                return None
    return None


def _recompute(net: dict) -> tuple[list[str], list[str]]:
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

    attempted: list[str] = []
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
            attempted.append(f"{ip}:{port}" if port else str(ip))
            dead.add(str(ip))

    established: list[str] = []
    for host in net.get("hosts", []) or []:
        ip = host if isinstance(host, str) else host.get("ip")
        if not ip:
            continue
        if ip in exchanged:
            established.append(ip)
        elif str(ip) not in dead:
            ports = (host.get("ports") or []) if isinstance(host, dict) else []
            attempted.append(f"{ip}:{ports[0]}" if ports else str(ip))

    keep = lambda e: not baseline.noise_reason("ips", e.rsplit(":", 1)[0])  # noqa: E731
    return [e for e in established if keep(e)], [e for e in attempted if keep(e)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    db = session_scope()
    jobs = db.execute(select(SandboxJob)).scalars().all()

    looked = changed = no_report = 0
    before_est = after_est = 0
    for job in jobs:
        # COPY BEFORE MUTATING. `job.dynamic` is a plain `JSON` column, and
        # SQLAlchemy decides whether to emit an UPDATE by comparing the loaded
        # value with the assigned one using `==`. Mutating the loaded dict in
        # place and then assigning a shallow copy of it makes those two equal,
        # so the flush is a no-op: the first run of this script reported
        # "APPLIED" over 293 rows and wrote nothing. The read-back at the end is
        # what caught it.
        dyn = json.loads(json.dumps(job.dynamic or {}))
        facts = dyn.get("facts") or {}
        endpoints = facts.get("network_endpoints")
        if not isinstance(endpoints, dict):
            continue
        looked += 1
        before_est += len(endpoints.get("established") or [])

        task_id = facts.get("task_id") or dyn.get("task_id")
        report = _report_for(task_id) if task_id else None
        if report is None:
            no_report += 1
            continue

        established, attempted = _recompute(report.get("network", {}) or {})
        after_est += len(established)
        if established == (endpoints.get("established") or []) and attempted == (
            endpoints.get("attempted") or []
        ):
            continue
        changed += 1
        if args.apply:
            # The whole block goes when both lists are empty, matching the
            # worker's `if established or attempted:` guard — a report should
            # not carry an empty section asserting nothing.
            if established or attempted:
                facts["network_endpoints"] = {
                    "established": established,
                    "attempted": attempted,
                }
            else:
                facts.pop("network_endpoints", None)
            facts["network_endpoints_recomputed"] = (
                "Rebuilt from the stored CAPE report. The previous lists called every "
                "addressed host an established connection; CAPE fills that list from "
                "every packet destination, answered or not."
            )
            dyn["facts"] = facts
            job.dynamic = dyn
            # `analysis` carries the same payload and is what a re-analysis
            # reads back through `_result_from_stored`. Fixing only `dynamic`
            # would leave the next sweep to restore the wrong list from here.
            # Deep-copied for the same reason as above.
            analysis = json.loads(json.dumps(job.analysis or {}))
            for name, payload in analysis.items():
                if name.startswith("dynamic.") and isinstance(payload, dict):
                    payload["facts"] = facts
            job.analysis = analysis

    if args.apply:
        db.commit()
    db.close()

    if args.apply:
        # Read it back in a NEW session. "APPLIED" printed by the writer is not
        # evidence that anything was written.
        check = session_scope()
        left = sum(
            len((((j.dynamic or {}).get("facts") or {}).get("network_endpoints") or {}).get(
                "established") or [])
            for j in check.execute(select(SandboxJob)).scalars()
        )
        check.close()
        print("  established entries, re-read : %d" % left)

    print("jobs carrying network_endpoints : %d" % looked)
    print("  CAPE report missing on disk   : %d" % no_report)
    print("  would change / changed        : %d" % changed)
    print("  established entries  before   : %d" % before_est)
    print("  established entries  after    : %d" % after_est)
    print("APPLIED" if args.apply else "DRY RUN — nothing written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
