"""Regenerate THIRD_PARTY_NOTICES.md and sbom.json from the installed environment.

Run this on every release and after any dependency change:

    APP_ENV=demo python scripts/generate_sbom.py

Why generated rather than maintained: a hand-written notices file is wrong within
one `pip install -U`, and being wrong in a procurement pack is worse than having
no pack at all. Reading the real distributions means the versions and licences we
hand a lawyer are the ones actually in the build.

Scope is the dependency *closure* of the declared requirements, resolved against
this interpreter — not "everything in site-packages". A shared virtualenv carries
packages belonging to other projects; including them would describe a developer's
machine rather than the product.

Licence strings are taken from PEP 639 ``License-Expression`` first, then the
legacy ``License`` field, then trove classifiers. Where a distribution's metadata
is free text ("BSD", "GPL"), SPDX_OVERRIDE pins the SPDX identifier — those
entries were each read off the upstream LICENSE file, not guessed from the blob.
"""
from __future__ import annotations

import importlib.metadata as md
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

CLASSIFIER = re.compile(r"^License :: (?:OSI Approved :: )?(.+)$")
REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

BACKEND_ROOTS = [
    "fastapi", "uvicorn", "sqlalchemy", "alembic", "pydantic", "pydantic-settings",
    "python-multipart", "httpx", "prometheus-client", "pefile", "oletools",
    "yara-python", "py7zr", "rarfile", "pdfminer-six", "reportlab", "stix2",
    "puremagic", "anthropic", "cryptography",
    # Runtime, not optional. config.py refuses to boot with APP_ENV=production
    # on anything but PostgreSQL, so an image without psycopg cannot run in
    # production at all — every deployment was silently confined to demo mode.
    # Calling it optional also understated what we distribute, and it is
    # LGPL-3.0: exactly what a procurement scanner must be told rather than
    # left to find.
    "psycopg", "psycopg-binary",
]
WORKER_ROOTS = ["requests"]
OPTIONAL_ROOTS: list[str] = []
DEV_ROOTS = ["pytest", "pytest-asyncio", "pytest-cov", "coverage"]

#: Never listed, whatever is installed. These are the toolchain that PUT the
#: dependencies there, not dependencies of the product: nothing we ship imports
#: them, and their versions move with any `pip install -U pip`, so including
#: them makes the SBOM disagree with itself between the build image and CI and
#: gives a procurement scanner advisories about an installer the customer never
#: runs.
TOOLCHAIN_EXCLUDED = {"pip", "setuptools", "wheel", "pkg-resources", "distribute"}

#: uvicorn[standard] extras that are genuinely installed and used in production.
UVICORN_EXTRAS = {
    "httptools", "watchfiles", "websockets", "python-dotenv", "pyyaml",
    "uvloop", "colorama",
}

#: SPDX identifiers for distributions whose metadata is a free-text blob.
SPDX_OVERRIDE = {
    "annotated-types": "MIT",
    "antlr4-python3-runtime": "BSD-3-Clause",
    "brotli": "MIT",
    "colorama": "BSD-3-Clause",
    "distro": "Apache-2.0",
    "easygui": "BSD-3-Clause",
    "multivolumefile": "LGPL-2.1-or-later",
    "olefile": "BSD-2-Clause",
    "oletools": "BSD-2-Clause",
    "passlib": "BSD-3-Clause",
    "pcodedmp": "GPL-3.0-or-later",
    "pycryptodomex": "BSD-2-Clause AND Unlicense",
    "reportlab": "BSD-3-Clause",
    "stix2": "BSD-3-Clause",
    "stix2-patterns": "BSD-3-Clause",
    "yara-python": "Apache-2.0",
}


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def spdx_for(key: str, meta) -> str:
    if key in SPDX_OVERRIDE:
        return SPDX_OVERRIDE[key]
    expr = meta.get("License-Expression")
    if expr:
        return expr.strip()
    raw = (meta.get("License") or "").strip()
    if raw and "\n" not in raw and len(raw) < 40:
        return raw
    cls = [m.group(1) for c in meta.get_all("Classifier") or [] if (m := CLASSIFIER.match(c))]
    if cls:
        return " / ".join(cls)
    return "UNKNOWN - see package metadata"


def copyleft_class(spdx: str) -> str | None:
    up = spdx.upper()
    if "LGPL" in up:
        return "weak-copyleft"
    if "GPL" in up:
        return "strong-copyleft"
    if "MPL" in up:
        return "file-level-copyleft"
    return None


DISTS: dict[str, md.Distribution] = {}
for _d in md.distributions():
    _name = _d.metadata["Name"]
    if _name:
        DISTS.setdefault(norm(_name), _d)


def requires(key: str) -> list[str]:
    """Direct dependencies, ignoring extras — except uvicorn's `standard`, which
    we do install and therefore do distribute."""
    dist = DISTS.get(key)
    if not dist:
        return []
    out = []
    for req in dist.metadata.get_all("Requires-Dist") or []:
        if "extra ==" in req:
            extra = re.search(r"extra\s*==\s*[\"']([^\"']+)[\"']", req.split(";", 1)[1])
            if extra and not (key == "uvicorn" and extra.group(1) == "standard"):
                continue
        m = REQ_NAME.match(req)
        if m:
            out.append(norm(m.group(1)))
    return out


def closure(roots: list[str]) -> set[str]:
    seen: set[str] = set()
    stack = [norm(r) for r in roots]
    while stack:
        cur = stack.pop()
        if cur in seen or cur not in DISTS:
            continue
        seen.add(cur)
        stack.extend(requires(cur))
    return seen


def collect() -> tuple[list[dict], list[str]]:
    runtime = (
        closure(BACKEND_ROOTS)
        | closure(WORKER_ROOTS)
        | {k for k in map(norm, UVICORN_EXTRAS) if k in DISTS}
    )
    optional = closure(OPTIONAL_ROOTS) - runtime
    dev = closure(DEV_ROOTS) - runtime - optional

    rows = []
    for key in sorted(DISTS):
        if key in TOOLCHAIN_EXCLUDED:
            continue  # the installer, not an ingredient — see TOOLCHAIN_EXCLUDED
        if key not in runtime and key not in optional and key not in dev:
            continue  # outside the declared closure: another project's package
        meta = DISTS[key].metadata
        urls = {}
        for entry in meta.get_all("Project-URL") or []:
            if "," in entry:
                k, v = entry.split(",", 1)
                urls[k.strip().lower()] = v.strip()
        home = (
            meta.get("Home-page")
            or urls.get("homepage")
            or urls.get("source")
            or urls.get("repository")
            or urls.get("documentation")
            or f"https://pypi.org/project/{meta['Name']}/"
        )
        spdx = spdx_for(key, meta)
        label = "runtime" if key in runtime else "optional" if key in optional else "build/test"
        rows.append(
            {
                "key": key,
                "name": meta["Name"],
                "version": DISTS[key].version,
                "spdx": spdx,
                "home": home,
                "summary": (meta.get("Summary") or "").strip(),
                "scope": "required" if label == "runtime" else "optional",
                "label": label,
                "copyleft": copyleft_class(spdx),
            }
        )
    absent = [r for r in BACKEND_ROOTS + WORKER_ROOTS if norm(r) not in DISTS]
    return rows, absent


def write_sbom(rows: list[dict], generated: str) -> None:
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:"
        + str(uuid.uuid5(uuid.NAMESPACE_URL, "https://cyclowareness.local/sandbox/sbom")),
        "version": 1,
        "metadata": {
            "timestamp": generated,
            "tools": [
                {
                    "vendor": "Cyclowareness",
                    "name": "importlib.metadata SBOM export",
                    "version": "1.0.0",
                }
            ],
            "authors": [{"name": "Safarali Safarli"}],
            # Which interpreter and platform resolved these versions. A
            # dependency closure is platform-specific, so an SBOM without this is
            # a document about whoever last ran the generator. It also lets the
            # regression test demand an exact version match in the environment
            # the SBOM describes, and only coverage elsewhere, instead of failing
            # on every machine that is not the author's.
            "properties": [
                {"name": "cyclowareness:generated_on_platform", "value": sys.platform},
                {
                    "name": "cyclowareness:generated_on_python",
                    "value": "%d.%d" % sys.version_info[:2],
                },
            ],
            "component": {
                "type": "application",
                "bom-ref": "pkg:generic/cyclowareness-sandbox",
                "name": "Cyclowareness Sandbox",
                "version": "1.0.0",
                "description": "Sovereign incident-evidence platform: on-premise file and URL threat analysis with a defensible evidence artifact.",
                "licenses": [
                    {
                        "license": {
                            "name": "BUSL-1.1 (Business Source License 1.1); converts to Apache-2.0 on 2030-07-27"
                        }
                    }
                ],
                "supplier": {"name": "Safarali Safarli"},
            },
        },
        "components": [],
    }
    for r in rows:
        # SPDX ids go in `id`; compound or non-SPDX strings must go in `name`,
        # because a validator rejects an unknown identifier in `id`.
        lic = (
            {"license": {"id": r["spdx"]}}
            if re.fullmatch(r"[A-Za-z0-9.+-]+", r["spdx"])
            else {"license": {"name": r["spdx"]}}
        )
        comp = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{r['key']}@{r['version']}",
            "name": r["name"],
            "version": r["version"],
            "purl": f"pkg:pypi/{r['key']}@{r['version']}",
            "scope": r["scope"],
            "licenses": [lic],
            "externalReferences": [{"type": "website", "url": r["home"]}],
        }
        if r["summary"]:
            comp["description"] = r["summary"]
        if r["copyleft"]:
            comp["properties"] = [{"name": "cyclowareness:copyleft", "value": r["copyleft"]}]
        sbom["components"].append(comp)

    with (REPO / "sbom.json").open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(sbom, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


NOTICES_TEMPLATE = (Path(__file__).parent / "third_party_notices.md.in").read_text(encoding="utf-8")


def table(subset: list[dict]) -> str:
    lines = ["| Package | Version | Licence (SPDX) | Project |", "|---|---|---|---|"]
    for r in subset:
        lines.append(f"| `{r['name']}` | {r['version']} | {r['spdx']} | <{r['home']}> |")
    return "\n".join(lines)


def write_notices(rows: list[dict], generated: str) -> None:
    body = NOTICES_TEMPLATE.format(
        generated=generated,
        n_total=len(rows),
        n_runtime=len([r for r in rows if r["label"] == "runtime"]),
        copyleft_table=table([r for r in rows if r["copyleft"]]),
        runtime_table=table([r for r in rows if r["label"] == "runtime"]),
        optional_table=table([r for r in rows if r["label"] == "optional"]),
        dev_table=table([r for r in rows if r["label"] == "build/test"]),
    )
    with (REPO / "THIRD_PARTY_NOTICES.md").open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)


def main() -> None:
    rows, absent = collect()
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    write_sbom(rows, generated)
    write_notices(rows, generated)
    print(f"wrote sbom.json and THIRD_PARTY_NOTICES.md: {len(rows)} distributions")
    if absent:
        # Not an error — optional deps legitimately go missing — but silence here
        # would let a genuinely uninstalled requirement vanish from the record.
        print("declared but not installed (excluded from both files):", ", ".join(absent))


if __name__ == "__main__":
    main()
