"""A TypeScript type is an assertion about the API, not a reading of it.

The Integrations page was given a sovereignty panel that renders
`caps.sovereignty.outbound_refusals`. `types.ts` declared that field `number`.
It is an object — `{total, by_destination, recent}` — and React refuses to render
an object as a child, so the error propagated out of the render and **unmounted
the entire application**: `#root` empty, a white page, and no console output
where anyone would look for it.

`tsc` was happy throughout, because the type was something written by hand about
a server it never talks to. That is the same defect class the whole audit is
about, arriving from the direction nobody was watching.

So the shapes the interface renders DIRECTLY are asserted here, against the real
response, in the suite that runs in CI. Adding a field to this list is the cost
of rendering a new one; forgetting to is how the page goes blank again.
"""
from __future__ import annotations

import pytest

#: (dotted path, expected python type). Every one of these is interpolated into
#: JSX somewhere, which means it must be a primitive React can print.
RENDERED_SCALARS = [
    ("max_sample_mb", int),
    ("ai_provider", str),
    ("demo_mode", bool),
    ("scoring.model", str),
    ("scoring.weights.rule", float),
    ("scoring.weights.model", float),
    ("yara.loaded", int),
    ("sovereignty.enabled", bool),
    ("sovereignty.statement", str),
    ("sovereignty.outbound_refusals.total", int),
    ("retention.statement", str),
]


def _dig(payload, path):
    node = payload
    for part in path.split("."):
        assert isinstance(node, dict), f"{path}: {part} is not under an object"
        assert part in node, f"{path}: the API does not send {part}"
        node = node[part]
    return node


@pytest.fixture()
def caps(client, auth):
    """The full descriptor, which now needs a session.

    It was unauthenticated, and it is a map for getting a sample past this
    deployment: the exact upload ceiling, the exact extension allowlist, the
    analyzer inventory, the YARA rule count and which engines are configured.
    The one fact the SPA needs before login -- `demo_mode` -- moved to
    `/api/capabilities/public`.
    """
    response = client.get("/api/capabilities", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def test_the_full_descriptor_is_not_public(client) -> None:
    """Unauthenticated, it must not hand out the analysis posture."""
    assert client.get("/api/capabilities").status_code in (401, 403)


def test_the_login_screen_can_still_read_what_it_needs(client) -> None:
    """And the split must not break the pre-login banner, which is the reason
    the endpoint was public in the first place."""
    response = client.get("/api/capabilities/public")
    assert response.status_code == 200, response.text
    body = response.json()
    assert isinstance(body["demo_mode"], bool)
    # The sovereignty posture stays public on purpose -- a buyer reads it before
    # they have an account. What must NOT be here is the analysis posture.
    assert "sovereignty" in body
    for leaked in ("max_sample_mb", "supported_extensions", "static_analyzers",
                   "yara", "integrations"):
        assert leaked not in body, f"{leaked} is a map for getting a sample past us"


@pytest.mark.parametrize("path,kind", RENDERED_SCALARS)
def test_what_the_ui_prints_is_printable(caps, path, kind) -> None:
    value = _dig(caps, path)
    assert not isinstance(value, (dict, list)), (
        f"capabilities.{path} is a {type(value).__name__}; the UI interpolates it "
        "into JSX, and React unmounts the whole app rather than render it"
    )
    if kind is float:
        assert isinstance(value, (int, float)) and not isinstance(value, bool)
    else:
        assert isinstance(value, kind), f"capabilities.{path} is {type(value).__name__}, expected {kind.__name__}"


def test_the_lists_the_ui_maps_over_are_lists_of_objects(caps) -> None:
    for path, keys in (
        ("sovereignty.destinations", {"key", "what_would_leave", "allowed", "is_deliberate_exception"}),
        ("integrations", {"key", "name", "kind", "tier", "configured"}),
    ):
        rows = _dig(caps, path)
        assert isinstance(rows, list) and rows, f"capabilities.{path} is empty or not a list"
        for row in rows:
            assert isinstance(row, dict), f"{path} contains a {type(row).__name__}"
            missing = keys - set(row)
            assert not missing, f"{path} row is missing {sorted(missing)}"


def test_supported_extensions_is_a_list_of_strings(caps) -> None:
    values = caps["supported_extensions"]
    assert isinstance(values, list) and values
    assert all(isinstance(v, str) for v in values)


def test_the_published_limit_is_the_limit_that_is_enforced(client, auth, caps) -> None:
    """The submit page prints this number next to the file picker. If it is not
    the number the server enforces, the interface is lying in one direction or
    refusing on the analyst's behalf in the other."""
    from app.config import get_settings

    assert caps["max_sample_mb"] == get_settings().max_sample_mb
