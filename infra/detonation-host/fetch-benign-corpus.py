#!/usr/bin/env python3
"""Fetch the benign half of the detonation corpus, reproducibly.

    python3 fetch-benign-corpus.py [--dest /opt/samples/benign] [--include-over-cap]

Records a sha256 per file next to them, so a later run can prove it fetched the
same bytes, and so a corpus measurement can be tied to exact inputs.

Benign samples are the half that decides whether this product is usable. Five of
them cannot measure a false-positive rate: the same 7-Zip binary came out
malicious on one detonation and suspicious on a rerun the next morning, because
an unrelated Windows service acted during the first. Fifty samples across fifteen
toolchains can.

Nothing here is malware. Every URL is a vendor's own published release over
HTTPS, and the files are downloaded to be *detonated as controls* — the corpus
proves the product does NOT flag them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "benign-corpus.json"
UA = "cyclowareness-corpus-fetcher/1.0"


def fetch(url: str, dest: Path, timeout: int = 180) -> tuple[bool, str]:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    digest = hashlib.sha256()
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response, open(tmp, "wb") as fh:
            while True:
                chunk = response.read(1 << 16)
                if not chunk:
                    break
                digest.update(chunk)
                fh.write(chunk)
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        return False, f"{type(exc).__name__}: {exc}"
    tmp.replace(dest)
    return True, digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", default="/opt/samples/benign")
    parser.add_argument(
        "--include-over-cap",
        action="store_true",
        help="fetch entries larger than the API's max_sample_mb. They will be "
             "rejected with HTTP 413 on submission unless the cap is raised, "
             "which is why git.exe and vlc.exe are absent from earlier runs.",
    )
    parser.add_argument("--only", help="substring filter on the sample name")
    args = parser.parse_args(argv)

    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)

    wanted = [
        s for s in doc["samples"]
        if (args.include_over_cap or not s.get("over_cap"))
        and (not args.only or args.only in s["name"])
    ]
    print(f"{len(wanted)} sample(s) to fetch into {dest}")

    hashes: dict[str, str] = {}
    failed: list[tuple[str, str]] = []
    for i, sample in enumerate(wanted, 1):
        target = dest / sample["name"]
        if target.is_file():
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            hashes[sample["name"]] = digest
            print(f"  [{i:>2}/{len(wanted)}] {sample['name']:<28} present  {digest[:16]}")
            continue
        ok, result = fetch(sample["url"], target)
        if not ok:
            failed.append((sample["name"], result))
            print(f"  [{i:>2}/{len(wanted)}] {sample['name']:<28} FAILED   {result}", file=sys.stderr)
            continue
        hashes[sample["name"]] = result
        size = target.stat().st_size
        drift = ""
        if sample.get("bytes") and abs(size - sample["bytes"]) > 4096:
            # Not an error: vendors republish. It IS a reason to re-check the
            # sample is still what the manifest says it is before trusting a
            # measurement made with it.
            drift = f"  SIZE DRIFT (manifest {sample['bytes']})"
        print(f"  [{i:>2}/{len(wanted)}] {sample['name']:<28} {size:>10}  {result[:16]}{drift}")

    (dest / "sha256sums.json").write_text(json.dumps(hashes, indent=1), encoding="utf-8")
    print(f"\nfetched {len(hashes)}/{len(wanted)}; hashes in {dest / 'sha256sums.json'}")
    if failed:
        print("\nFAILED — a corpus with holes measures a different thing than it claims:")
        for name, why in failed:
            print(f"  {name}: {why}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
