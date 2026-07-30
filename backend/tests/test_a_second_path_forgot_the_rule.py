"""Rules the pipeline enforces, and a second code path that did not.

`ingest_report` re-scores a job from scratch when a worker's report lands. It is
a mirror of the tail of `pipeline.run` and it had drifted: three arguments the
pipeline passes, it did not, so a detonation could overwrite a correct verdict
with the answer the pipeline had already rejected. Re-analysis had drifted the
same way, dropping a marker that exists to stop an infinite loop.

Also here: bounds that could be sat on exactly, an authenticated 500 reachable
without authenticating, and a job a restart made permanently unrecoverable.
"""
from __future__ import annotations

import io
import os
import zipfile

import pytest

from app.engine import archives
from app.engine.models import JobStatus


# --- the dynamic ingest scores the way the pipeline scores -------------------


def test_one_definition_of_whether_the_behaviour_is_the_samples() -> None:
    """`ingest_report` did not ask at all, so a detonation of an inert file
    re-scored the job on what the GUEST did — the exact thing the pipeline's
    `dynamic_attributable` was written to prevent."""
    from app.api.dynamic import _dynamic_is_attributable, _needs_dynamic

    class _J:
        family = "script"
        mime = "text/plain"
        original_name = "LICENSE"
        archive_path = None
        status = JobStatus.COMPLETED
        tiers: dict = {}

    inert = _J()
    assert not _dynamic_is_attributable(inert)
    assert not _needs_dynamic(inert), "the two must not disagree"

    runnable = _J()
    runnable.original_name = "update.ps1"
    runnable.mime = "text/x-powershell"
    assert _dynamic_is_attributable(runnable)
    assert _needs_dynamic(runnable)


@pytest.mark.parametrize("family", ["pe", "elf", "office", "pdf"])
def test_a_binary_format_always_has_an_execution_path(family) -> None:
    """Only `script` is gated; everything else can run by construction."""
    from app.api.dynamic import _dynamic_is_attributable

    class _J:
        pass

    job = _J()
    job.family = family
    job.mime = "application/octet-stream"
    job.original_name = "x"
    job.archive_path = None
    assert _dynamic_is_attributable(job)


def test_the_ingest_passes_the_three_arguments_the_pipeline_passes() -> None:
    """Blunt, and it is the check that would have caught all three.

    Each was a keyword the pipeline gives and this path did not, and each is
    invisible in a diff of one file. `from_url` decides Attack Vector; without
    it, DETONATING a URL-delivered sample LOWERED its impact rating.
    """
    import inspect

    from app.api import dynamic

    source = inspect.getsource(dynamic.ingest_report)
    assert "dynamic_attributable=attributable" in source
    assert "from_url=(job.source == JobSource.URL)" in source
    # And the "before" is read before anything is written to the row.
    body = source.split("def ingest_report", 1)[-1]
    assert body.index("score_before = job.final_score") < body.index(
        "job.final_score = assessment.final_score"
    ), "score_before is read after the score has already been replaced"


# --- a refusal survives re-analysis ------------------------------------------


def test_re_analysis_keeps_the_marker_that_stops_the_loop() -> None:
    """`_needs_dynamic` reads `refused` to stop re-offering a sample the sandbox
    has already declined. Re-analysis carried forward only tiers that RAN, and a
    refused tier by definition did not — so one re-analysis reopened the
    infinite re-detonation loop that marker was added to close."""
    import inspect

    from app.engine import pipeline

    source = inspect.getsource(pipeline.run)
    assert 'carried.get("refused")' in source, (
        "the refused marker is not carried across a re-analysis"
    )


def test_needs_dynamic_still_honours_the_marker() -> None:
    from app.api.dynamic import _needs_dynamic

    class _J:
        family = "elf"
        mime = "application/x-executable"
        original_name = "mirai"
        archive_path = None
        status = JobStatus.COMPLETED
        tiers = {"dynamic": {"ran": False, "refused": True, "detail": "Linux disabled"}}

    assert not _needs_dynamic(_J())


# --- a bound nobody can sit exactly on ---------------------------------------


def _zip_of(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    return buf.getvalue()


def test_a_member_of_exactly_one_mebibyte_is_still_a_bomb(tmp_path) -> None:
    """The guard was `size > 1024 * 1024` — a strict inequality on a round
    number the submitter picks. 1 MiB of zeros deflates to about a kilobyte, so
    a member of exactly that size at 1000:1 was neither skipped nor reported."""
    path = tmp_path / "exact.zip"
    path.write_bytes(_zip_of({"payload.bin": b"\0" * (1024 * 1024)}))

    result = archives.unpack(str(path), "application/zip")

    member = result.members[0]
    assert member.ratio > archives.MAX_RATIO, member.ratio
    assert member.skipped_reason == "compression ratio exceeds the bomb threshold"
    assert any(s.id == "archive.compression_bomb" for s in result.signals), result.signals


def test_a_small_noisy_member_is_not_called_a_bomb(tmp_path) -> None:
    """The size floor exists for a reason: a tiny repetitive file posts a wild
    ratio and expands to nothing."""
    path = tmp_path / "small.zip"
    path.write_bytes(_zip_of({"notes.txt": b"a" * 4096}))

    result = archives.unpack(str(path), "application/zip")
    assert result.members[0].skipped_reason is None
    assert not [s for s in result.signals if s.id == "archive.compression_bomb"]


def test_an_ordinary_member_is_extracted(tmp_path) -> None:
    path = tmp_path / "ok.zip"
    path.write_bytes(_zip_of({"real.bin": os.urandom(200_000)}))
    assert len(archives.unpack(str(path), "application/zip").extracted()) == 1


# --- a hostile header is not a 500 -------------------------------------------


@pytest.mark.parametrize("header,path", [
    ("x-worker-token", "/api/dynamic/queue"),
    ("x-api-key", "/api/jobs"),
    ("authorization", "/api/jobs"),
])
def test_a_non_ascii_credential_is_refused_not_a_crash(client, header, path) -> None:
    """`hmac.compare_digest` raises TypeError on a `str` holding a code point
    above U+007F, and the worker-token comparison runs in MIDDLEWARE — before
    any handler — so one header made an unauthenticated caller a 500."""
    # Sent as BYTES: an HTTP header is latin-1 on the wire, and Starlette decodes
    # it back to a str holding U+00E9 — which is exactly the value
    # `hmac.compare_digest` refuses. The client will not encode it from a str.
    response = client.get(path, headers={header: "é".encode("latin-1") * 8})
    assert response.status_code != 500, response.text


def test_an_azerbaijani_password_is_a_401_not_a_500(client) -> None:
    response = client.post(
        "/api/auth/login", json={"username": "analyst", "password": "şifrə-yanlış"}
    )
    assert response.status_code == 401, response.text


# --- the audit filters are bounded and printable -----------------------------


def test_a_nul_byte_in_an_audit_filter_is_a_422_not_a_500(client, auth) -> None:
    """On PostgreSQL a NUL byte in a text parameter is a driver ValueError, so
    `?actor=%00` was an authenticated 500 on the audit trail itself."""
    for field in ("actor", "action", "object_type", "object_id"):
        response = client.get("/api/audit", params={field: "a\x00b"}, headers=auth)
        assert response.status_code == 422, (field, response.status_code)


def test_an_unbounded_audit_filter_is_refused(client, auth) -> None:
    response = client.get("/api/audit", params={"actor": "x" * 4096}, headers=auth)
    assert response.status_code == 422, response.text


def test_each_audit_filter_still_filters_on_its_own_key(client, auth) -> None:
    """Sharing one `Query()` instance across four parameters gives them one
    alias, so every filter reads the same query key and `?actor=` is ignored."""
    listing = client.get(
        "/api/audit", params={"actor": "nobody-by-this-name"}, headers=auth
    )
    assert listing.status_code == 200, listing.text
    assert listing.json()["items"] == [], "the actor filter did not filter"


# --- a restart does not strand a job -----------------------------------------


def test_an_interrupted_job_is_re_queued_at_startup(db) -> None:
    """`running` is owned by an in-process thread pool. A restart takes the pool
    and leaves the row, and nothing reset it: the queue page showed the job
    working forever and every re-analysis answered 409."""
    from app.engine.models import SandboxJob
    from app.main import _recover_interrupted_jobs

    job = SandboxJob(
        public_id="stranded-1", tenant_id="default", source="upload",
        original_name="x.bin", sha256="c" * 64, md5="d" * 32, size_bytes=1,
        status=JobStatus.RUNNING, stage="analysing",
    )
    db.add(job)
    db.commit()

    _recover_interrupted_jobs()

    db.expire_all()
    refreshed = db.get(SandboxJob, job.id)
    assert refreshed.status == JobStatus.QUEUED
    assert "restart" in (refreshed.stage or "")


def test_a_recovered_job_can_be_re_analysed_immediately(client, db, auth) -> None:
    """Relabelling the row is not the same as making it reclaimable.

    `reanalyze` refuses an in-flight job unless it is older than `_STALE_AFTER`,
    so a process killed thirty seconds after a job started would leave that job
    409-ing for another ten minutes even after the startup sweep had seen it.
    Clearing `started_at` is what closes that window.
    """
    from app.engine.models import SandboxJob
    from app.main import _recover_interrupted_jobs
    from app.util import utcnow

    job = SandboxJob(
        public_id="stranded-2", tenant_id="default", source="upload",
        original_name="y.bin", sha256="e" * 64, md5="f" * 32, size_bytes=1,
        status=JobStatus.RUNNING, stage="analysing",
        # Started seconds ago: well inside the staleness window.
        started_at=utcnow().replace(tzinfo=None),
    )
    db.add(job)
    db.commit()

    _recover_interrupted_jobs()
    db.expire_all()
    assert db.get(SandboxJob, job.id).started_at is None

    response = client.post(f"/api/jobs/{job.public_id}/reanalyze", headers=auth)
    assert response.status_code == 200, response.text


def test_a_job_that_really_is_running_is_still_refused(client, db, auth) -> None:
    """The 409 exists for a reason, and the staleness escape must not remove it."""
    from app.engine.models import SandboxJob
    from app.util import utcnow

    job = SandboxJob(
        public_id="busy-1", tenant_id="default", source="upload",
        original_name="z.bin", sha256="1" * 64, md5="2" * 32, size_bytes=1,
        status=JobStatus.RUNNING, stage="analysing",
        started_at=utcnow().replace(tzinfo=None),
    )
    db.add(job)
    db.commit()

    response = client.post(f"/api/jobs/{job.public_id}/reanalyze", headers=auth)
    assert response.status_code == 409, response.text


def test_the_re_analysis_claim_is_one_statement(client) -> None:
    """Read-then-write let two clicks both pass, and on an archive that builds
    the whole child-job tree twice."""
    import inspect

    from app.api import sandbox

    source = inspect.getsource(sandbox.reanalyze)
    assert "update(SandboxJob)" in source, "the claim is not a single UPDATE"
    assert "rowcount" in source, "nothing checks whether this caller won"
    assert "_STALE_AFTER" in source, "a job stranded by a restart is still stuck"


# --- the integration matrix reports on what the engine needs -----------------


def test_joe_sandbox_needs_its_url_as_well_as_its_key() -> None:
    """`JoeSandboxEngine.available()` is `joe_url and joe_apikey`. The matrix
    checked only the key, so it read "configured / Enabled" while the worker
    skipped the engine every time."""
    from app.engine.integrations import ENGINES

    joe = next(e for e in ENGINES if e.key == "joesandbox")
    assert set(joe.env_keys) == {"JOE_URL", "JOE_API_KEY"}, joe.env_keys
    assert "JOE_URL" in joe.requires


@pytest.mark.parametrize("key", ["cuckoo", "capev2", "joesandbox"])
def test_a_worker_run_engine_says_whose_environment_it_read(key) -> None:
    """`configured()` reads THIS process's env; these three run in the worker
    from the worker's. On a split deployment — the normal one — the row reports
    on a machine that is not the one running the engine, and it now says so
    instead of presenting the reading as a fact."""
    from app.engine.integrations import ENGINES

    engine = next(e for e in ENGINES if e.key == key)
    assert engine.configured_on_worker is True
    assert "worker" in engine.describe()["configuration_caveat"].lower()


@pytest.mark.parametrize("key", ["native", "qiling", "virustotal", "strelka"])
def test_the_others_carry_no_caveat(key) -> None:
    """The caveat must mean something, so it goes only where it is true."""
    from app.engine.integrations import ENGINES

    engine = next(e for e in ENGINES if e.key == key)
    assert engine.describe()["configuration_caveat"] == ""


# --- a tenant that cannot read its own evidence ------------------------------


def test_a_tenant_name_too_long_to_match_refuses_to_boot() -> None:
    """`tenant_id` is String(64) and every writer stores `name[:64]`, while every
    reader compares the untrimmed configured value. A longer name writes rows it
    can never read back — its own evidence, invisible, with no error anywhere."""
    from app.config import Settings

    settings = Settings(analyst_tenant="t" * 65, database_url="postgresql://x/y")
    problems = settings.validate_production()
    assert any("tenant name" in p for p in problems), problems


def test_a_sane_tenant_name_is_not_a_problem() -> None:
    from app.config import Settings

    settings = Settings(analyst_tenant="acme-security", database_url="postgresql://x/y")
    assert not [p for p in settings.validate_production() if "tenant name" in p]


# --- the PDF name-escape pass is bounded -------------------------------------


def test_hex_escape_decoding_is_bounded() -> None:
    """It ran a Python callback per match over up to 16 MiB, twice: measured at
    15.9s for 5,592,405 substitutions. `re.sub` with a count stops at the Nth
    replacement, so the work is where that match is, not the buffer's size."""
    import time

    from app.engine.analyzers import pdf as pdf_mod

    hostile = b"#41" * (8 * 1024 * 1024 // 3)
    started = time.perf_counter()
    pdf_mod._decode_name_escapes(hostile)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"{elapsed:.2f}s to decode a hostile buffer"


def test_a_real_hidden_name_is_still_decoded() -> None:
    """The bound must not have cost the detection it exists for."""
    from app.engine.analyzers import pdf as pdf_mod

    assert b"/JavaScript" in pdf_mod._decode_name_escapes(b"<< /J#61vaScript (x) >>")
    assert b"/OpenAction" in pdf_mod._decode_name_escapes(b"<< /Open#41ction 1 0 R >>")
