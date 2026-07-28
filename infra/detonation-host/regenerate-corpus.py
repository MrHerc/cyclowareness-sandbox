#!/usr/bin/env python3
"""Rebuild backend/tests/data/detonation_corpus.json from real detonations.

    python3 regenerate-corpus.py --repo /root/cyclowareness-sandbox \
        --run /opt/samples/corpus_run.json --out /tmp/detonation_corpus.json

Run it on the detonation host, where the database and the sample files are. It
needs the backend's dependencies importable — the simplest way is the same
container the tests use:

    docker run --rm -v /root/cyclowareness-sandbox:/repo -v /root/testvenv:/venv \\
      -v /opt/samples:/opt/samples -v /tmp:/tmp -w /repo/backend \\
      python:3.12-slim /venv/v/bin/python /repo/infra/detonation-host/regenerate-corpus.py

TWO HALVES, FETCHED DIFFERENTLY, AND THAT IS THE POINT.

The DYNAMIC half is read back from stored job output. It cannot be recomputed —
it took a detonation on a real guest, and re-detonating produces different
signals: the same 7-Zip binary was called malicious on one run and suspicious the
next morning, because an unrelated Windows service acted during the first.

The STATIC half is recomputed from the sample file with the shipped analyzers.
Reading it back from storage instead bakes in whatever the analyzers emitted on
the day, which is how a fixture came to carry `pe.section_size_anomaly` signals
months after that signal was fixed — putting `SectionSizeAnomaly` into a threat
name the product would no longer produce.

The score is the one the full pipeline computed for that job. An earlier fixture
replayed dynamic signals alone and recomputed the score with `ioc_total=0`, which
reproduced verdicts the product never reached: 57 of 88 where the product gets
72. A fixture that does not replay the pipeline cannot regression-test it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def load_jobs(database: str) -> list[dict]:
    """Every job with stored analyzer output, straight from PostgreSQL."""
    sql = (
        "select json_agg(t) from (select public_id, final_score, analysis "
        "from sandbox_jobs where analysis is not null) t;"
    )
    done = subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-d", database, "-A", "-t", "-c", sql],
        capture_output=True, text=True,
    )
    if done.returncode != 0:
        raise SystemExit(f"psql failed: {done.stderr.strip()}")
    return json.loads(done.stdout)


def trim(signals: list[dict]) -> list[dict]:
    """Keep only what the verdict and capability models read."""
    out = []
    for signal in signals or []:
        evidence = signal.get("evidence") or {}
        kept = {"id": signal["id"], "severity": signal.get("severity", "info")}
        slim = {}
        if evidence.get("categories"):
            slim["categories"] = [str(c) for c in evidence["categories"]]
        if evidence.get("family"):
            slim["family"] = evidence["family"]
        if slim:
            kept["evidence"] = slim
        out.append(kept)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="/repo")
    parser.add_argument("--run", default="/opt/samples/corpus_run.json")
    parser.add_argument("--manifest", default="/opt/samples/wide/manifest.json")
    parser.add_argument("--database", default="cyclowareness")
    parser.add_argument("--jobs-json", help="skip psql and read jobs from this file")
    parser.add_argument("--out", default="/tmp/detonation_corpus.json")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(Path(args.repo) / "backend"))
    from app.engine import analyzers, identify as identify_mod, impact, verdict
    from app.engine.contracts import AnalyzerResult, IOCs, Sample, Signal

    truth = {r["label"]: r for r in json.load(open(args.run))}
    manifest = {}
    if os.path.isfile(args.manifest):
        for entry in json.load(open(args.manifest)):
            manifest[entry.get("sha256") or ""] = entry
    by_public_id = {r["public_id"]: r for r in json.load(open(args.run))}
    jobs = json.load(open(args.jobs_json)) if args.jobs_json else load_jobs(args.database)

    samples = []
    for job in jobs:
        entry = by_public_id.get(job.get("public_id"))
        if not entry:
            continue
        dynamic = (job.get("analysis") or {}).get("dynamic.capev2") or {}
        if not dynamic.get("ran"):
            continue  # a detonation corpus without a detonation is not evidence
        meta = manifest.get(entry.get("sha256"), {})
        samples.append({
            "task": (dynamic.get("facts") or {}).get("task_id"),
            "kind": entry["kind"],
            "name": entry["label"],
            "sha256": entry.get("sha256"),
            "family_label": meta.get("family") or meta.get("signature") or "",
            "source": "vendor download" if entry["kind"] == "benign" else "malwarebazaar/theZoo",
            "final_score": round(float(job.get("final_score") or 0), 1),
            "analyzers": {"dynamic.capev2": {"ran": True,
                                             "signals": trim(dynamic.get("signals") or [])}},
        })

    # --- refresh the static half from the files, with the shipped analyzers ---
    refreshed = stale = 0
    for sample in samples:
        path = (truth.get(sample["name"]) or {}).get("path")
        if not path or not os.path.isfile(path):
            sample["static_refreshed"] = False
            stale += 1
            continue
        try:
            data = open(path, "rb").read()
            ident = identify_mod.identify(path, sample["name"])
            built = Sample(
                path=path, size_bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                md5=hashlib.md5(data).hexdigest(),
                mime=ident.mime, magic=ident.magic,
                claimed_extension=ident.claimed_extension,
                original_name=sample["name"],
                extension_mismatch=ident.extension_mismatch, family=ident.family,
            )
            results = analyzers.run_all(built, built.family)
            try:
                from app.engine import yara_engine

                results.append(yara_engine.analyze(built))
            except Exception:
                pass
        except Exception as exc:
            print(f"  static refresh FAILED for {sample['name']}: "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
            sample["static_refreshed"] = False
            stale += 1
            continue
        dynamic = sample["analyzers"]["dynamic.capev2"]
        fresh = {}
        for result in results:
            as_dict = result.to_dict()
            fresh[as_dict["analyzer"]] = {"ran": bool(as_dict.get("ran")),
                                          "signals": trim(as_dict.get("signals"))}
        fresh["dynamic.capev2"] = dynamic
        sample["analyzers"] = fresh
        sample["static_refreshed"] = True
        refreshed += 1

    # --- replay, and record what the engine says today -----------------------
    malware = benign = caught = false_positives = 0
    for sample in samples:
        results = [
            AnalyzerResult(
                analyzer=name, ran=a["ran"],
                signals=[Signal(id=s["id"], title=s["id"], severity=s["severity"],
                                detail="", evidence=s.get("evidence") or {})
                         for s in a["signals"]],
                facts={}, iocs=IOCs())
            for name, a in sample["analyzers"].items()
        ]
        signals = [s for r in results if r.ran for s in r.signals]
        got = verdict.classify("pe", "application/x-dosexec", results, None,
                               sample["final_score"])
        sample["expected"] = {
            "verdict": got.verdict, "threat_name": got.threat_name,
            "detection_ratio": got.detection_ratio,
            "cir": impact.assess("pe", signals, None).to_dict()["base_score"],
        }
        if sample["kind"] == "malware":
            malware += 1
            caught += got.verdict == "malicious"
        else:
            benign += 1
            false_positives += got.verdict == "malicious"

    samples.sort(key=lambda s: (s["kind"], s["name"]))
    doc = {
        "_source": f"{len(samples)} real CAPEv2 detonations on the Cyclowareness host. "
                   "Dynamic signals read back from stored job output; static signals "
                   "recomputed from the sample files with the shipped analyzers.",
        "_guest": "Windows 10 22H2 Pro 19045.3803, BIOS, network-isolated, INetSim active.",
        "_measured": {"malware": malware, "malware_malicious": caught,
                      "benign": benign, "benign_malicious": false_positives},
        "_warning": "Do NOT tune a threshold to make a named sample pass. A sample that "
                    "moves is a reason to re-read its evidence, not to move a number.",
        "samples": samples,
    }
    Path(args.out).write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"  {len(samples)} samples ({malware} malware, {benign} benign)")
    print(f"  static refreshed {refreshed}, stale {stale}")
    print(f"  malware malicious {caught}/{malware}, benign flagged {false_positives}/{benign}")
    if false_positives:
        print("  ^ a benign false positive makes the product unusable; do not commit this")
    print(f"  written to {args.out}")
    return 1 if false_positives else 0


if __name__ == "__main__":
    raise SystemExit(main())
