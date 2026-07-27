# Third-party notices

Cyclowareness Sandbox itself is licensed under the Business Source License 1.1
(see [`LICENSE`](LICENSE) and [`docs/licensing.md`](docs/licensing.md)). It
incorporates the third-party open-source packages listed below, each of which
remains under its own licence. Nothing here is relicensed by us.

This file is **generated from the installed distributions** of the reference
environment (`scripts/generate_sbom.py`, reading `importlib.metadata`), not
written by hand, so every version and licence below is the one actually present
in the build. The machine-readable equivalent is [`sbom.json`](sbom.json)
(CycloneDX 1.5).

- Generated: 2026-07-27T06:04:26Z
- Distributions recorded: 69 (69 in the runtime closure)
- Scope: the dependency closure declared by `backend/requirements.txt` and
  `worker/requirements.txt`, resolved against the reference environment.
  Packages present in that environment but outside the declared closure are
  excluded, so this file describes the product and not one developer's machine.
- `prometheus-client` is declared as an **optional** backend dependency and is
  absent from the reference environment (`/metrics` degrades to a no-op without
  it), so it has no row below. It is Apache-2.0.
- Regenerate on every release and on any dependency change:
  `python scripts/generate_sbom.py`. A stale notices file is a procurement
  finding.

## Copyleft and reciprocal licences — read this section first

These are the packages a procurement or licence review will ask about. Every one
is a **separately-installed PyPI wheel**, imported dynamically at runtime. None
is statically linked into, vendored inside, or modified by Cyclowareness
Sandbox, and no Cyclowareness source file is a derivative work of any of them.

| Package | Version | Licence (SPDX) | Project |
|---|---|---|---|
| `certifi` | 2026.7.22 | MPL-2.0 | <https://github.com/certifi/python-certifi> |
| `inflate64` | 1.0.4 | LGPL-2.1-or-later | <https://inflate64.readthedocs.io/> |
| `multivolumefile` | 0.2.3 | LGPL-2.1-or-later | <https://github.com/miurahr/multivolume> |
| `py7zr` | 1.1.3 | LGPL-2.1-or-later | <https://py7zr.readthedocs.io/> |
| `pybcj` | 1.0.8 | LGPL-2.1-or-later | <https://pypi.org/project/pybcj> |
| `pyppmd` | 1.3.1 | LGPL-2.1-or-later | <https://pyppmd.readthedocs.io/> |

Position on each class:

- **LGPL-2.1-or-later** (`py7zr` and its compression chain: `pybcj`, `pyppmd`,
  `inflate64`, `multivolumefile`) — used unmodified, as a dynamically-imported
  library. LGPL section 6 is satisfied: the packages are separately installable
  and replaceable by the user, we distribute them unmodified with their
  licences, and we impose no restriction on relinking or substituting them.
- **LGPL-3.0-only** (`psycopg`, `psycopg-binary`) — the optional PostgreSQL
  driver. Same position as above; it is not installed unless the operator
  chooses PostgreSQL.
- **MPL-2.0** (`certifi`) — file-level copyleft. Used unmodified; the obligation
  attaches only to modified MPL files, of which there are none.
- **GPL-3.0-or-later** (`pcodedmp`) — **flagged.** `pcodedmp` is a hard
  (non-extra) dependency of `oletools`, so `pip install -r requirements.txt`
  fetches it. Cyclowareness Sandbox **never imports it**: `olevba`'s only use of
  `pcodedmp` is inside `extract_pcode()`, which the Office analyzer does not
  call. Its presence in an image is mere aggregation, not linking. Operators who
  want it absent entirely can `pip uninstall -y pcodedmp` after install — the
  Office analyzer is unaffected. See [`docs/licensing.md`](docs/licensing.md).

## Not shipped, on purpose

- **Qiling Framework** (GPL-2.0) — the optional emulation engine adapter
  ([`worker/engines/qiling_emu.py`](worker/engines/qiling_emu.py)) is present in
  source, but `qiling` is **not** in any requirements file and **not** in any
  image we build, precisely because importing a GPL-2.0 library in-process would
  make the distributed worker a derivative work of it. An operator who installs
  `qiling` on their own worker makes that licence decision for themselves; we do
  not make it for them, and we do not distribute the result.

## Runtime dependencies

Packages in the closure of `backend/requirements.txt` and
`worker/requirements.txt` — the code that runs in production.

| Package | Version | Licence (SPDX) | Project |
|---|---|---|---|
| `alembic` | 1.18.5 | MIT | <https://alembic.sqlalchemy.org> |
| `annotated-doc` | 0.0.4 | MIT | <https://github.com/fastapi/annotated-doc> |
| `annotated-types` | 0.8.0 | MIT | <https://github.com/annotated-types/annotated-types> |
| `anthropic` | 0.120.0 | MIT | <https://github.com/anthropics/anthropic-sdk-python> |
| `antlr4-python3-runtime` | 4.13.2 | BSD-3-Clause | <http://www.antlr.org> |
| `anyio` | 4.14.2 | MIT | <https://anyio.readthedocs.io/en/latest/> |
| `backports.zstd` | 1.6.0 | PSF-2.0 | <https://github.com/rogdham/backports.zstd> |
| `brotli` | 1.2.0 | MIT | <https://github.com/google/brotli> |
| `certifi` | 2026.7.22 | MPL-2.0 | <https://github.com/certifi/python-certifi> |
| `cffi` | 2.1.0 | MIT-0 | <https://cffi.readthedocs.io/> |
| `charset-normalizer` | 3.4.9 | MIT | <https://charset-normalizer.readthedocs.io/> |
| `click` | 8.4.2 | BSD-3-Clause | <https://github.com/pallets/click/> |
| `colorclass` | 2.2.2 | MIT | <https://github.com/matthewdeanmartin/colorclass> |
| `cryptography` | 49.0.0 | Apache-2.0 OR BSD-3-Clause | <https://github.com/pyca/cryptography> |
| `distro` | 1.9.0 | Apache-2.0 | <https://github.com/python-distro/distro> |
| `docstring_parser` | 0.18.0 | MIT | <https://github.com/rr-/docstring_parser> |
| `easygui` | 0.98.3 | BSD-3-Clause | <https://github.com/robertlugg/easygui> |
| `fastapi` | 0.140.0 | MIT | <https://github.com/fastapi/fastapi> |
| `greenlet` | 3.5.4 | MIT AND PSF-2.0 | <https://greenlet.readthedocs.io> |
| `h11` | 0.16.0 | MIT | <https://github.com/python-hyper/h11> |
| `httpcore` | 1.0.9 | BSD-3-Clause | <https://www.encode.io/httpcore/> |
| `httptools` | 0.8.0 | MIT | <https://github.com/MagicStack/httptools> |
| `httpx` | 0.28.1 | BSD-3-Clause | <https://github.com/encode/httpx> |
| `idna` | 3.18 | BSD-3-Clause | <https://github.com/kjd/idna> |
| `inflate64` | 1.0.4 | LGPL-2.1-or-later | <https://inflate64.readthedocs.io/> |
| `jiter` | 0.16.0 | MIT | <https://github.com/pydantic/jiter/> |
| `Mako` | 1.3.12 | MIT | <https://www.makotemplates.org/> |
| `MarkupSafe` | 3.0.3 | BSD-3-Clause | <https://github.com/pallets/markupsafe/> |
| `msoffcrypto-tool` | 6.0.0 | MIT | <https://github.com/nolze/msoffcrypto-tool> |
| `multivolumefile` | 0.2.3 | LGPL-2.1-or-later | <https://github.com/miurahr/multivolume> |
| `olefile` | 0.47 | BSD-2-Clause | <https://www.decalage.info/python/olefileio> |
| `oletools` | 0.60.2 | BSD-2-Clause | <https://github.com/decalage2/oletools> |
| `pdfminer.six` | 20260107 | MIT | <https://github.com/pdfminer/pdfminer.six> |
| `pefile` | 2024.8.26 | MIT | <https://github.com/erocarrera/pefile> |
| `pillow` | 12.3.0 | MIT-CMU | <https://python-pillow.github.io> |
| `prometheus_client` | 0.26.0 | Apache-2.0 AND BSD-2-Clause | <https://github.com/prometheus/client_python> |
| `psutil` | 7.2.2 | BSD-3-Clause | <https://github.com/giampaolo/psutil> |
| `puremagic` | 2.2.0 | MIT | <https://github.com/cdgriffith/puremagic> |
| `py7zr` | 1.1.3 | LGPL-2.1-or-later | <https://py7zr.readthedocs.io/> |
| `pybcj` | 1.0.8 | LGPL-2.1-or-later | <https://pypi.org/project/pybcj> |
| `pycparser` | 3.0 | BSD-3-Clause | <https://github.com/eliben/pycparser> |
| `pycryptodomex` | 3.23.0 | BSD-2-Clause AND Unlicense | <https://www.pycryptodome.org> |
| `pydantic` | 2.13.4 | MIT | <https://github.com/pydantic/pydantic> |
| `pydantic_core` | 2.46.4 | MIT | <https://github.com/pydantic/pydantic> |
| `pydantic-settings` | 2.14.2 | MIT | <https://github.com/pydantic/pydantic-settings> |
| `pyparsing` | 3.3.2 | MIT | <https://github.com/pyparsing/pyparsing/> |
| `pyppmd` | 1.3.1 | LGPL-2.1-or-later | <https://pyppmd.readthedocs.io/> |
| `python-dotenv` | 1.2.2 | BSD-3-Clause | <https://github.com/theskumar/python-dotenv> |
| `python-multipart` | 0.0.32 | Apache-2.0 | <https://github.com/Kludex/python-multipart> |
| `pytz` | 2026.3.post1 | MIT | <http://pythonhosted.org/pytz> |
| `PyYAML` | 6.0.3 | MIT | <https://pyyaml.org/> |
| `rarfile` | 4.4 | ISC | <https://github.com/markokr/rarfile> |
| `reportlab` | 5.0.0 | BSD-3-Clause | <https://www.reportlab.com/> |
| `requests` | 2.34.2 | Apache-2.0 | <https://github.com/psf/requests> |
| `simplejson` | 4.1.1 | MIT OR AFL-2.1 | <https://github.com/simplejson/simplejson> |
| `sniffio` | 1.3.1 | MIT OR Apache-2.0 | <https://github.com/python-trio/sniffio> |
| `SQLAlchemy` | 2.0.51 | MIT | <https://www.sqlalchemy.org> |
| `starlette` | 1.3.1 | BSD-3-Clause | <https://github.com/Kludex/starlette> |
| `stix2` | 3.0.2 | BSD-3-Clause | <https://oasis-open.github.io/cti-documentation/> |
| `stix2-patterns` | 2.1.2 | BSD-3-Clause | <https://github.com/oasis-open/cti-pattern-validator> |
| `texttable` | 1.7.0 | MIT | <https://github.com/foutaise/texttable/> |
| `typing_extensions` | 4.16.0 | PSF-2.0 | <https://github.com/python/typing_extensions> |
| `typing-inspection` | 0.4.2 | MIT | <https://github.com/pydantic/typing-inspection> |
| `urllib3` | 2.7.0 | MIT | <https://urllib3.readthedocs.io> |
| `uvicorn` | 0.51.0 | BSD-3-Clause | <https://uvicorn.dev/> |
| `uvloop` | 0.22.1 | MIT License | <https://pypi.org/project/uvloop/> |
| `watchfiles` | 1.2.0 | MIT | <https://github.com/samuelcolvin/watchfiles> |
| `websockets` | 16.1.1 | BSD-3-Clause | <https://github.com/python-websockets/websockets> |
| `yara-python` | 4.5.4 | Apache-2.0 | <https://github.com/VirusTotal/yara-python> |

## Optional dependencies

Installed only for a specific deployment choice (e.g. PostgreSQL).

| Package | Version | Licence (SPDX) | Project |
|---|---|---|---|

## Build and test dependencies

Present in the development environment; not required to run the product.

| Package | Version | Licence (SPDX) | Project |
|---|---|---|---|

## Non-Python components

| Component | Licence | How it is used |
|---|---|---|
| `firejail` (worker image, apt) | GPL-2.0 | Invoked as a **separate process** by the native engine; never linked or imported. Distributed unmodified by the OS package manager. |
| `strace` (worker image, apt) | LGPL-2.1-or-later | Invoked as a separate process; output parsed as data. |
| `unrar` (optional, operator-supplied) | Non-free (RARLAB) | Not distributed. `rarfile` only lists RAR contents without it; the operator installs it themselves if they need extraction. |
| Frontend npm dependencies | see `frontend/package.json` | React/Vite/Tailwind toolchain, MIT/BSD/ISC. The compiled bundle carries the upstream banner comments. |
| YARA rules shipped in-repo | authored by Safarali Safarli | Covered by the Cyclowareness Sandbox licence, not a third-party licence. |

## Requesting sources

For any LGPL or MPL component above, the corresponding source is the unmodified
upstream release at the version recorded here, available from the project URL in
the table (and from PyPI). We have made no modifications to distribute.
