# Licensing

The page to read before signing anything. It states the licence on Cyclowareness
Sandbox, exactly what a customer may and may not do under it, and the position on
every third-party component in the build.

- Licence: **Business Source License 1.1** — [`../LICENSE`](../LICENSE)
- Licensor: Safarali Safarli
- Change Date: **2030-07-27**, on which the licence becomes **Apache-2.0**
- Third-party disclosure: [`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md)
- Machine-readable SBOM (CycloneDX 1.5): [`../sbom.json`](../sbom.json)

## Why BUSL, and not MIT or a closed licence

This product's claim is sovereignty: your files never leave your building, and
what comes out the other end is evidence you can defend to a regulator, an
auditor or a court. Two licence choices were available and both failed:

- **MIT** (what this repository used to carry) gives away the thing being sold.
  Any competitor can fork it, rebrand it, and resell it — including as the hosted
  service this product exists to make unnecessary. For a company whose asset is
  the product itself rather than a network effect, that is not a licence, it is a
  donation.
- **Fully closed source** protects the asset and destroys the reason to buy.
  A government or defence buyer purchasing "we do not exfiltrate your evidence"
  cannot verify that claim against a binary. Auditability is not a nice-to-have
  here; it is the deliverable. A security product that says "trust us" is asking
  for exactly the thing the buyer is forbidden to give.

BUSL-1.1 resolves the two. The source is published and auditable — read every
line, run it through your own SAST, verify what leaves the network. Competing
commercial use is prohibited. And the whole thing converts to Apache-2.0 on the
Change Date, so a buyer's long-term dependency is not hostage to one vendor's
survival: worst case, in 2030 it is Apache-2.0 software they can maintain.

**BUSL-1.1 is not an OSI open-source licence.** We say so plainly rather than
letting "source-available" be mistaken for "open source" in a procurement form.

## What a customer may do

Under the Additional Use Grant, without buying anything further:

- **Read, audit and analyse the source.** Compile it, decompile it, run static
  analysis and dependency scanners against it, review it in a cleared facility.
- **Run it in non-production**: development, testing, evaluation, POCs,
  benchmarking, training, teaching, academic and security research.
- **Run it in production inside one organisation, on that organisation's own
  files.** No volume cap, no time limit, no per-seat metering in the licence.
  Contractors and incident responders acting on that organisation's behalf are
  covered — a DFIR firm brought in for a breach can use the customer's
  deployment on the customer's evidence.
- **Modify it** for any of the above, including local patches, custom YARA
  rules, custom analyzers, and integration with your own SIEM/SOAR.
- **Publish security research about it**, including vulnerability disclosures.
  Nothing in this licence is a gag clause, and we will not treat one as such.

## What a customer may not do without a commercial licence

- **Offer it to third parties as a hosted, managed or multi-tenant service** —
  whether or not money changes hands. Running a sandbox-as-a-service for other
  organisations on this code needs a separate agreement.
- **Redistribute it as a competing product**, in whole or in part, under any
  name. That includes rebadging, embedding it in a product you sell, or
  distributing a derivative that does what this does.

If you need either, that is a conversation and not a refusal — contact the
Licensor for commercial terms.

## The notice

Each copy of the work carries this, and new source files may carry it as a
header comment:

```
Copyright (c) 2026 Safarali Safarli

Use of this software is governed by the Business Source License 1.1 included
in the LICENSE file. As of the Change Date specified in that file
(2030-07-27), in accordance with the Business Source License, use of this
software will be governed by the Apache License, Version 2.0.
```

## Third-party position

Every third-party package remains under its own licence; we relicense nothing.
The full enumeration — name, version, SPDX licence, project URL — is generated
from the installed distributions in
[`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md), with the same data as
CycloneDX 1.5 in [`../sbom.json`](../sbom.json). The bulk is MIT / BSD / Apache
and raises nothing. Four cases are worth a lawyer's attention:

### 1. LGPL — permitted, disclosed, mitigable

`py7zr` and its compression chain (`pybcj`, `pyppmd`, `inflate64`,
`multivolumefile`) are LGPL-2.1-or-later; the optional PostgreSQL driver
`psycopg` is LGPL-3.0-only. All are used **unmodified**, installed as separate
PyPI wheels and imported dynamically at runtime. That is the arrangement the
LGPL is written to permit: the user can replace or upgrade any of them without
touching our code, we distribute them with their licences intact, and we impose
no restriction on doing so. No Cyclowareness source file is a derivative work of
any of them, and no LGPL obligation propagates to this product.

### 2. MPL-2.0 — `certifi`

File-level copyleft on the CA bundle, used unmodified. The obligation attaches
only to modified MPL-licensed files; there are none.

### 3. GPL-3.0 — `pcodedmp`, present but never imported

**Flagged deliberately, because a scanner will find it and ask.**

`oletools` (BSD-2-Clause, our Office analyzer's parser) declares `pcodedmp` as a
hard, non-optional dependency, so `pip install -r requirements.txt` fetches it.
`pcodedmp` is GPL-3.0-or-later.

Our position:

- **Cyclowareness Sandbox never imports it.** `olevba`'s only use of `pcodedmp`
  is inside `extract_pcode()`, and `backend/app/engine/analyzers/office.py` does
  not call that method. Nothing in the pipeline reaches GPL code at runtime.
- Its presence in an image is **mere aggregation** — an unrelated program that
  happens to sit in the same `site-packages` — not linking, and it therefore
  carries no obligation onto this product.
- **If your policy forbids GPL bytes on disk at all**, the mitigation is one
  line and costs nothing: `pip uninstall -y pcodedmp` after installing
  requirements. The Office analyzer is unaffected; the suite stays green.

### 4. GPL-2.0 — `qiling`, deliberately not shipped

`worker/engines/qiling_emu.py` is an adapter for the Qiling emulation framework.
Qiling is GPL-2.0. Importing it in-process inside an image we distribute would
make that image a derivative work of a GPL-2.0 library, which cannot be
reconciled with BUSL-1.1. So the library is absent from
`worker/requirements.txt` and from the worker Dockerfile, and the engine's
guarded import reports `available() = False` with that reason stated in full.

What ships is our own adapter code against a public API. An operator who wants
emulation runs `pip install qiling` on their own worker and accepts Qiling's
GPL-2.0 terms for their own deployment. That is their decision about software
they install; we neither make it for them nor distribute the result.

### Non-Python components

`firejail` (GPL-2.0) and `strace` (LGPL-2.1-or-later) are installed into the
worker image by the OS package manager and invoked as **separate processes** —
the native engine shells out to them and parses their output as data. They are
never linked or imported, so no obligation reaches our code. `unrar` (non-free,
RARLAB) is **not distributed**: `rarfile` lists RAR contents without it, and an
operator who needs extraction installs it themselves.

## Keeping this accurate

`THIRD_PARTY_NOTICES.md` and `sbom.json` are generated by
[`../scripts/generate_sbom.py`](../scripts/generate_sbom.py) from
`importlib.metadata` over the reference environment, not maintained by hand,
because a hand-maintained notices file is wrong within one dependency bump — and
being wrong in a procurement pack is worse than being absent:

```bash
python scripts/generate_sbom.py
```

Regenerate on every release and on any dependency change.
`backend/tests/test_licensing_and_sbom.py` fails if the SBOM and the installed
environment disagree, so the drift is caught in CI rather than in a customer's
licence review. If the copyleft table gains a row, re-read section 3 above before
shipping — a new GPL entry is a decision, not a diff.
