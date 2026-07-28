#!/usr/bin/env python3
"""Read the current state of a corpus run out of the database. Changes nothing.

    python3 collect-corpus.py --run /opt/samples/corpus_run_full.json

Separate from run-corpus.py on purpose. Submission is expensive and one-way —
re-running it detonates everything again — while READING where a run has got to
is cheap and safe to do as often as you like. Keeping them in one program meant
that when a run was interrupted, the only way to see its results was to start
another one.

It also reports the archive children. A corpus of 152 files became 440 jobs
because 22 of the benign entries are .zip archives, and each member becomes its
own job. Those members are real benign binaries and worth measuring — but they
are not what was submitted, so they are counted separately rather than silently
inflating the denominator.
"""
from __future__ import annotations

import argparse
import collections
import json
import subprocess


def load_jobs(database: str) -> list[dict]:
    sql = (
        "select json_agg(t) from (select public_id, original_name, family, status, "
        "final_score, risk_level, parent_job_id, error, "
        "tiers->'dynamic'->>'ran' as dyn_ran, "
        "tiers->'dynamic'->>'refused' as dyn_refused, "
        "tiers->'dynamic'->>'detail' as dyn_detail, "
        "verdict->>'verdict' as verdict, verdict->>'threat_name' as threat, "
        "verdict->>'detection_ratio' as ratio, impact->>'base_score' as cir "
        "from sandbox_jobs) t;"
    )
    done = subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-d", database, "-A", "-t", "-c", sql],
        capture_output=True, text=True,
    )
    if done.returncode != 0:
        raise SystemExit(f"psql failed: {done.stderr.strip()}")
    return json.loads(done.stdout)


def rate(hit: int, total: int) -> str:
    return f"{hit}/{total} ({100.0 * hit / total:.0f}%)" if total else "0/0 (n/a)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", default="/opt/samples/corpus_run_full.json")
    parser.add_argument("--database", default="cyclowareness")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    # Ground truth comes from the run file's own `kind`, never from the file
    # name: the runner renames every sample to sample_NNN.ext, and a
    # filename-based label counts the benign controls as malware. That mistake
    # once turned a 2/5 false-positive rate into a reported 1/5.
    truth = {r["public_id"]: r for r in json.load(open(args.run))}
    jobs = {j["public_id"]: j for j in load_jobs(args.database)}
    by_id = {j["parent_job_id"]: j for j in jobs.values() if j.get("parent_job_id")}

    submitted, children = [], []
    parent_kind: dict[int, str] = {}
    for public_id, entry in truth.items():
        job = jobs.get(public_id)
        if not job:
            continue
        row = {**entry, **job, "detonated": job.get("dyn_ran") == "true"}
        submitted.append(row)
        parent_kind[job_id] = entry["kind"] if (job_id := job.get("parent_job_id")) else None

    submitted_ids = {j["public_id"] for j in submitted}
    # A child inherits its parent's label: a file inside a benign archive is benign.
    parent_of = {}
    for job in jobs.values():
        parent_of[job["public_id"]] = job.get("parent_job_id")
    id_to_kind: dict[str, str] = {r["public_id"]: r["kind"] for r in submitted}
    numeric_to_public = {}
    for row in submitted:
        numeric_to_public[row.get("parent_job_id")] = row["public_id"]

    for job in jobs.values():
        if job["public_id"] in submitted_ids or not job.get("parent_job_id"):
            continue
        children.append({**job, "detonated": job.get("dyn_ran") == "true", "kind": "child"})

    def report(rows: list[dict], title: str) -> None:
        mal = [r for r in rows if r.get("kind") == "malware"]
        ben = [r for r in rows if r.get("kind") == "benign"]
        det = [r for r in rows if r["detonated"]]
        mal_det = [r for r in mal if r["detonated"]]
        ben_det = [r for r in ben if r["detonated"]]
        caught = [r for r in mal_det if r["verdict"] == "malicious"]
        fps = [r for r in ben_det if r["verdict"] == "malicious"]

        print("=" * 72)
        print(title)
        print("=" * 72)
        print(f"  rows {len(rows)}   detonated {rate(len(det), len(rows))}")
        if mal or ben:
            print(f"  malware detonated {rate(len(mal_det), len(mal))}"
                  f"   benign detonated {rate(len(ben_det), len(ben))}")
            print("  --- over detonated samples only ---")
            print(f"  malware caught  : {rate(len(caught), len(mal_det))}")
            print(f"  benign flagged  : {rate(len(fps), len(ben_det))}   <- must be 0")
            if fps:
                print("     FALSE POSITIVES:")
                for r in sorted(fps, key=lambda x: -(float(x["final_score"] or 0))):
                    print(f"       {r['label']:<26} score {r['final_score']:<7} "
                          f"cir {r['cir']:<6} {r['threat']}")
            missed = [r for r in mal_det if r["verdict"] != "malicious"]
            if missed:
                print(f"     not caught ({len(missed)}), by family:")
                for fam, n in collections.Counter(r["label"] for r in missed).most_common(12):
                    print(f"       {fam:<26} {n}")
        print()

    report(submitted, "SUBMITTED CORPUS")

    if children:
        det = [c for c in children if c["detonated"]]
        flagged = [c for c in det if c["verdict"] == "malicious"]
        print("=" * 72)
        print("ARCHIVE MEMBERS (not submitted directly; extracted from the archives)")
        print("=" * 72)
        print(f"  rows {len(children)}   detonated {rate(len(det), len(children))}")
        print(f"  called malicious: {rate(len(flagged), len(det))}")
        for c in sorted(flagged, key=lambda x: -(float(x["final_score"] or 0)))[:15]:
            print(f"     {c['original_name']:<34} score {c['final_score']:<7} {c['threat']}")
        print()

    pending = [r for r in submitted if not r["detonated"] and not r.get("dyn_refused")]
    if pending:
        print(f"STILL PENDING: {len(pending)} submitted sample(s) not detonated yet.")
        print("  The numbers above are a snapshot, not a final measurement.")

    if args.out:
        json.dump({"submitted": submitted, "children": children}, open(args.out, "w"), indent=1)
        print(f"\nwritten to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
