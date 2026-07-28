#!/usr/bin/env python3
"""Run the whole corpus through the product, the way a customer would.

    python3 run-corpus.py [--out /opt/samples/corpus_run.json]

Submitted through `/api/analyze` on the production deployment, not by calling the
engine directly. The worker claims each job, detonates it on a guest, and posts
behaviour back. What comes out is what a customer would see.

Benign controls are interleaved with the malware, so drift in the host or the
guests hits both halves equally rather than only whichever ran last.

THE COMPLETION CHECK IS THE HARD PART, and it has been wrong in both directions.

Wrong once: `if tiers.dynamic.ran` treated `ran: false` as "not finished yet".
But `ran: false` is a FINAL state for a sample nothing could detonate — an ELF
CAPE refused, or an archive whose children were detonated instead. Those jobs
never entered `done`, so the loop could never reach `len(submitted)` and spun
until it was killed. It appeared "stuck at 92/107" having actually resolved
everything.

Nearly wrong the other way: `if status in (completed, failed, awaiting_password)`
looks like the obvious fix and is far worse. `completed` marks the end of STATIC
analysis and is the PRECONDITION for detonation — `_needs_dynamic` will not offer
a job to the worker until it is `completed`, and `ingest_report` never touches
`status`. So every job is `completed` before it is detonated. Measured on the
107-sample run: submission finished at 20:06:03 and the first poll began four
seconds later, against roughly two hours of guest time. That predicate would have
declared all 107 done on the first pass and written a corpus report of
static-only verdicts, in under a minute, silently. A measurement that is wrong
and fast is worse than one that hangs.

What is actually being asked is "has the worker had its say about this job?", and
there are four ways that can be true. All four are checked below.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import random
import subprocess
import time

API = os.environ.get("CYCLO_API", "http://127.0.0.1:8080")
KEY_PATH = os.environ.get("CYCLO_API_KEY_FILE", "/etc/cyclowareness/api.key")

#: Families the backend will offer to a dynamic worker. A job outside this set is
#: never going to be detonated, so waiting for it is waiting forever. Keep in step
#: with backend/app/api/dynamic.py `_DYNAMIC_FAMILIES`.
DYNAMIC_FAMILIES = {"pe", "elf", "script", "office", "pdf"}
TERMINAL_STATUSES = {"failed", "awaiting_password"}


def curl(*args: str, timeout: str = "180") -> str:
    done = subprocess.run(
        ["curl", "-s", "--max-time", timeout, *args], capture_output=True, text=True
    )
    return done.stdout


def submit(key: str, path: str, name: str) -> str | None:
    out = curl("-H", f"X-API-Key: {key}", "-F", f"file=@{path};filename={name}",
               f"{API}/api/analyze")
    try:
        return json.loads(out).get("public_id")
    except Exception:
        return None


def result(key: str, public_id: str) -> dict:
    try:
        return json.loads(curl("-H", f"X-API-Key: {key}", f"{API}/api/result/{public_id}"))
    except Exception:
        return {}


def worker_has_answered(job: dict) -> bool:
    """Has the dynamic tier reached a state that will not change on its own?

    Four ways, and none of them can be true before the worker has actually taken
    the job — which is exactly what a `status`-based check gets wrong.
    """
    tier = (job.get("tiers") or {}).get("dynamic") or {}
    if tier.get("ran"):
        return True                       # it detonated
    if tier.get("refused"):
        return True                       # the sandbox declined it, terminally
    if tier.get("engine"):
        return True                       # a worker posted something about it
    if job.get("family") not in DYNAMIC_FAMILIES:
        return True                       # it was never going to be offered
    if job.get("status") in TERMINAL_STATUSES:
        return True                       # it will never reach the queue
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="/opt/samples/corpus_run.json")
    parser.add_argument("--malware-manifest", default="/opt/samples/wide/manifest.json")
    parser.add_argument("--benign-dir", default="/opt/samples/benign")
    parser.add_argument("--deadline-hours", type=float, default=6.0)
    parser.add_argument(
        "--sample-timeout-minutes", type=float, default=45.0,
        help="give up on an individual job. There was no per-sample limit at all, "
             "so one wedged guest held the entire run against the global deadline.",
    )
    args = parser.parse_args(argv)
    key = open(KEY_PATH).read().strip()

    targets: list[dict] = []
    for entry in json.load(open(args.malware_manifest)):
        if os.path.exists(entry["path"]):
            targets.append({"kind": "malware", "label": entry["family"],
                            "path": entry["path"], "sha256": entry["sha256"]})
    for path in sorted(glob.glob(os.path.join(args.benign_dir, "*"))):
        if os.path.isfile(path) and os.path.getsize(path) > 8192 \
                and not path.endswith(".json"):
            targets.append({"kind": "benign", "label": os.path.basename(path),
                            "path": path, "sha256": ""})

    random.seed(20260727)
    random.shuffle(targets)
    print(f"  {sum(t['kind'] == 'malware' for t in targets)} malware, "
          f"{sum(t['kind'] == 'benign' for t in targets)} benign", flush=True)

    submitted = []
    rejected = []
    for n, target in enumerate(targets, 1):
        # Real extension: the sandbox picks its analysis package from the file
        # name, which is the whole reason `suffix` exists.
        ext = os.path.splitext(target["path"])[1] or ".exe"
        public_id = submit(key, target["path"], f"sample_{n:03d}{ext}")
        if public_id:
            submitted.append({**target, "public_id": public_id})
        else:
            # Silence here cost real time: git.exe (68 MB) and vlc.exe (43 MB)
            # were REJECTED by the 32 MB ingest cap, not skipped, and their
            # absence from the results looked like a corpus-building mistake.
            rejected.append({**target, "size": os.path.getsize(target["path"])})
        if n % 20 == 0:
            print(f"  submitted {n}/{len(targets)}", flush=True)
        time.sleep(3.2)  # the API rate-limits to 20/minute by design

    print(f"  {len(submitted)} accepted, {len(rejected)} REJECTED at submission", flush=True)
    for entry in rejected:
        print(f"     rejected: {entry['label']} ({entry['size']} bytes) — "
              f"over max_sample_mb?", flush=True)

    start = time.time()
    done: dict[str, dict] = {}
    first_seen: dict[str, float] = {}
    abandoned: set[str] = set()
    deadline = args.deadline_hours * 3600
    per_sample = args.sample_timeout_minutes * 60

    while len(done) + len(abandoned) < len(submitted) and time.time() - start < deadline:
        for entry in submitted:
            public_id = entry["public_id"]
            if public_id in done or public_id in abandoned:
                continue
            first_seen.setdefault(public_id, time.time())
            job = result(key, public_id)
            if worker_has_answered(job):
                done[public_id] = job
            elif time.time() - first_seen[public_id] > per_sample:
                abandoned.add(public_id)
                print(f"     abandoned {entry['label']} after "
                      f"{args.sample_timeout_minutes:.0f}m", flush=True)
        print(f"  {len(done)}/{len(submitted)} resolved, {len(abandoned)} abandoned "
              f"({int((time.time() - start) / 60)}m elapsed)", flush=True)
        if len(done) + len(abandoned) < len(submitted):
            time.sleep(60)

    rows = []
    for entry in submitted:
        job = done.get(entry["public_id"]) or result(key, entry["public_id"])
        verdict = job.get("verdict") or {}
        impact = job.get("impact") or {}
        dynamic = (job.get("analysis") or {}).get("dynamic.capev2") or {}
        tier = (job.get("tiers") or {}).get("dynamic") or {}
        rows.append({
            "kind": entry["kind"], "label": entry["label"], "path": entry["path"],
            "sha256": entry["sha256"], "public_id": entry["public_id"],
            "verdict": verdict.get("verdict"), "threat_name": verdict.get("threat_name"),
            "detection_ratio": verdict.get("detection_ratio"),
            "score": job.get("final_score"), "cir": impact.get("base_score"),
            "severity": impact.get("severity"),
            "capabilities": impact.get("capabilities") or [],
            "dynamic_ran": tier.get("ran"),
            "dynamic_refused": bool(tier.get("refused")),
            "dynamic_detail": tier.get("detail"),
            "signals": len(dynamic.get("signals") or []),
            "families": (dynamic.get("facts") or {}).get("sandbox_families"),
            "iocs": {k: len(v) for k, v in (job.get("iocs") or {}).items() if v},
        })
    json.dump(rows, open(args.out, "w"), indent=2)

    malware = [r for r in rows if r["kind"] == "malware"]
    benign = [r for r in rows if r["kind"] == "benign"]
    caught = sum(1 for r in malware if r["verdict"] == "malicious")
    false_positives = [r["label"] for r in benign if r["verdict"] == "malicious"]
    detonated = [r for r in rows if r["dynamic_ran"]]
    not_detonated = [r for r in rows if not r["dynamic_ran"]]

    print()
    print(f"  detonated        : {len(detonated)}/{len(rows)}")
    print(f"  malware caught   : {caught}/{len(malware)}")
    print(f"  benign flagged   : {len(false_positives)}/{len(benign)}   <- must be 0")
    if false_positives:
        print(f"     {false_positives}")
    # Never let a gap be silent. A run that quietly detonated 80% of the corpus
    # reports a detection rate for a different corpus than the one you think.
    if not_detonated:
        print(f"\n  NOT DETONATED ({len(not_detonated)}) — these are not evidence:")
        for row in not_detonated:
            why = "refused" if row["dynamic_refused"] else (row["dynamic_detail"] or "?")
            print(f"     {row['label']:<22} {str(why)[:70]}")
    print(f"\n  results in {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
