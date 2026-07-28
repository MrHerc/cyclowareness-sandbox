# Security

Cyclowareness Sandbox accepts hostile input by design. Every file uploaded and
every URL fetched is assumed to be malware until analysis says otherwise. This
document states the threat model, the controls that back it, and — as honestly —
what is in scope versus explicitly deferred.

## The central invariant

> **The web service never executes a sample. Detonation is off-host only.**

Static analysis parses; it does not run. The only component that executes a
sample is the off-host worker ([`worker/`](worker/)), on hardware the operator
controls, inside isolation (firejail/seccomp/container) or emulation (Qiling, if
the operator installs it — it is not shipped; see
[`docs/licensing.md`](docs/licensing.md)).
Every report states plainly whether the sample was actually detonated. This
invariant is why "analyse this file for me" is a safe request to honour on shared
infrastructure.

---

## Threat model

The adversary is the submitter. They fully control:

- the **bytes** of the uploaded file,
- the **filename** and any claimed extension,
- the **URL** submitted for fetching, and every server it redirects to,
- the **contents and structure** of any archive, including passwords, nesting,
  and compression ratios.

Their goals, and what each is met with:

| Attacker goal | Vector | Control |
|---|---|---|
| Run code on the server | Get the web service to execute the sample | Web service never executes; detonation is off-host only. |
| Escape the quarantine path | Malicious filename (`../../etc/cron.d/x`, `report.pdf.exe`) | Samples are content-addressed by SHA-256; the filename is metadata, never a path. |
| Reach internal services | URL that resolves to a private / loopback / metadata address | SSRF guard resolves and validates every host and every redirect hop before connecting. |
| Exhaust disk or memory | Huge upload; zip bomb; deep nesting | Streaming size cap; total-expansion budget; per-entry ratio cap; depth and member limits. |
| Exhaust CPU / hold the server | Block a request for a full analysis | Analysis runs on a background pool; submission returns immediately. |
| Read another analyst's data / submit anonymously | Unauthenticated access to mutating routes | Every mutating route requires an authenticated analyst or a valid API key. |
| Poison the verdict | Post fabricated "behaviour" to the dynamic seam | Dynamic ingest requires a shared worker token; closed entirely when unset. |
| Read the built SPA's parent files | Path traversal in the static file route | Resolved path must stay inside the dist directory, else `index.html`. |

---

## Controls

### Content-addressed, non-executable quarantine
[`backend/app/engine/storage.py`](backend/app/engine/storage.py)

- The sample is written under its **SHA-256**, never under the submitted name. A
  filename is attacker-controlled data; treating it as a path is how traversal
  and double-extension tricks land somewhere they are read back from.
- Permissions are stripped to owner-read-only and the file is never marked
  executable. On a host that mounts the quarantine `noexec` this is belt and
  braces; on one that does not, it is the only brace.
- Two submissions of the same bytes are one file — de-duplication falls out of
  content addressing for free.

### Streaming size cap
[`backend/app/engine/storage.py`](backend/app/engine/storage.py)

The cap is enforced **while streaming to disk**, not after. A `Content-Length`
header is a claim by the sender; checking it after the write is a disk-fill away
from an outage. The temporary file is written inside the quarantine tree so an
interrupted upload cannot leave debris on an exec-mounted volume.

### SSRF-guarded fetcher
[`backend/app/engine/fetcher.py`](backend/app/engine/fetcher.py)

A server that fetches arbitrary user-supplied URLs is an SSRF primitive: on a
cloud host, `http://169.254.169.254/` hands out credentials. So:

- Only `http`/`https` and a small set of ports are fetched.
- Every host is **resolved** and every resulting address checked against private,
  loopback, link-local, reserved, multicast, and unspecified ranges — plus named
  cloud-metadata endpoints — **before** the socket opens. IPv4-mapped IPv6
  (`::ffff:127.0.0.1`) is handled explicitly.
- **Every redirect hop is re-validated.** Redirects are followed manually, not by
  the HTTP client, because a permitted host can 302 into a private address.
- All resolved addresses must be public (DNS-rebinding defence — checking only
  the first is a hole).

### Attacker-controlled filename treated as data, not a path
[`backend/app/engine/storage.py`](backend/app/engine/storage.py),
[`backend/app/engine/fetcher.py`](backend/app/engine/fetcher.py) `_suggested_name`

The submitted filename and any `Content-Disposition` filename are flattened and
carried as **metadata only**. Because samples are content-addressed, the name
never becomes a filesystem path anywhere in the pipeline.

### Path-traversal-guarded SPA serving
[`backend/app/main.py`](backend/app/main.py)

When the container serves the compiled SPA, the catch-all route resolves the
requested path and returns a file only if the resolved path stays inside the dist
directory; anything else falls through to `index.html`. `/api/*` routes are
registered first and never reach the catch-all.

### No brute-force on encrypted archives
[`backend/app/engine/archives.py`](backend/app/engine/archives.py)

An encrypted archive parks its job in `AWAITING_PASSWORD`. The engine never
guesses or brute-forces. The analyst supplying a password
([`POST /api/jobs/{id}/password`](docs/api.md)) is a deliberate act worth having
in the audit log; the password is used once and never stored. Zip bombs are
bounded independently by a total-expansion budget, a per-entry compression-ratio
cap, and depth and member limits.

### Auth on every mutating route
[`backend/app/auth.py`](backend/app/auth.py)

- Two credentials open the gate and nothing else does: an HMAC-signed, expiring
  **session token** (`Authorization: Bearer`) issued by `POST /api/auth/login`,
  and a static **API key** (`X-API-Key`) for programmatic `/api/analyze` access.
- Tokens are built from the standard library — no JWT dependency, so no chance to
  accept `alg: none`. Signature verification and password comparison are
  constant-time.
- Login returns one message for both wrong-user and wrong-password, so failures
  do not enumerate accounts.

### Deliberate production posture
[`backend/app/config.py`](backend/app/config.py)

`APP_ENV=production` **refuses to boot** on a placeholder secret key, a
default/guessable analyst password, or a SQLite database URL. A security product
that ships with `analyst/analyst` reachable from the internet is the
vulnerability, not the tool; failing at startup is cheaper than discovering the
default password in an access log.

### Dynamic-tier trust boundary
[`backend/app/api/dynamic.py`](backend/app/api/dynamic.py)

The `/api/dynamic/*` seam authenticates with a shared `X-Worker-Token`
(constant-time compared) — never an analyst session. With no token configured the
seam returns 503 and accepts nothing: ingesting externally-supplied behaviour
into a verdict is an opt-in trust decision.

### Supply-chain disclosure
[`sbom.json`](sbom.json), [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)

Every third-party package in the build is enumerated with its version and
licence, generated from the installed distributions rather than transcribed, so
a reviewer can diff the SBOM against a CVE feed instead of taking our word for
what is in the image. A dependency this product deliberately does **not** carry
is named as such: the GPL-2.0 `qiling` emulator is an operator-installed
adapter, never shipped ([`docs/licensing.md`](docs/licensing.md)).

### Failure containment
A hostile sample that crashes one parser is converted to an honest `unavailable`
result; the job keeps every other finding
([`analyzers/__init__.py`](backend/app/engine/analyzers/__init__.py)). A job that
fails outright is marked `FAILED` with its error and stays inspectable, never
silently dropped.

---

## In scope

- Safe ingest of hostile files and URLs (SSRF, size, bombs, filename handling).
- Non-executing static analysis and quarantine hygiene.
- Authentication and authorization on all mutating and export routes.
- Honest capability reporting: the product never implies a capability it lacks.
- The isolation boundary between the web service and the detonating worker.

## Explicitly deferred

These are named rather than hidden — a deferred control the operator knows about
is safer than one they assume exists.

- **Worker-side isolation hardening** (VM snapshotting, network sinkholing,
  seccomp profiles) is the **operator's** responsibility on their own hardware.
  This repository defines the seam and the worker interface; it does not, and on
  a managed host cannot, provision the isolated lab environment.
- **Signed, single-use sample-fetch URLs.** `GET /api/dynamic/sample/{id}` is
  currently gated by the worker token and a content-hash path. A production
  deployment should upgrade it to a signed, single-use URL (noted in
  [`native.py`](backend/app/engine/native.py) and the endpoint docstring).
- **Multi-tenant identity.** Auth is a single configured analyst account plus
  API keys, sufficient for the exhibition/operator model. Per-user accounts,
  roles, and rate limiting are out of scope for this build.
- **Encryption at rest and transport termination** are deployment concerns
  (disk encryption, TLS at the reverse proxy), not application concerns here.
- **SIEM export.** STIX 2.1 and the signed report can be exported on demand;
  pushing them to a SIEM on a schedule, and TAXII, are not built.

Two items were listed here as deferred and are not any more:

- **Tamper-evident audit trail** — [`app/audit.py`](backend/app/audit.py) records
  a hash-chained, append-only log (12 event types), served under `/api/audit`
  with an endpoint that re-walks the chain and reports the first break. It is
  what the chain-of-custody claim rests on.
- **Sample retention** — [`app/retention.py`](backend/app/retention.py) enforces
  two windows (bytes and report), refuses to delete bytes another in-window job
  shares by content hash, writes an audited receipt for every deletion, and is
  started by the application lifespan rather than left to the operator's cron.

## Containment of the detonation host

The machine that runs samples is separate from the web tier and is not covered
by the guarantees above; see
[`infra/detonation-host/README.md`](infra/detonation-host/README.md). Its
containment is a runnable gate, not a description:
`infra/detonation-host/verify-containment.sh` probes from inside the guest and
exits non-zero if the guest can reach the internet, outbound DNS, or any host
port other than the result server. Run it before every real-malware run — CAPE's
own rooter rewrites the host's firewall when it stops.

## Reporting a vulnerability

Report issues through the repository's issue tracker; do not attach live malware
samples to a report. Use the content hash and, where relevant, the MalwareBazaar
or VirusTotal reference instead.
