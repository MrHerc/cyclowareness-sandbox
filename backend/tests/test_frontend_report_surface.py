"""The analyst-facing surface of the report, enforced from outside the browser.

The frontend has no test runner in this repo, and the five defects below were all
of a kind that a type-checker cannot see: the build was green the entire time the
interface was showing a green "Low risk" gauge for samples the engine had called
malicious. So the invariants are asserted here, against the source, next to the
engine whose output they are obliged to present honestly.

What is checked, and the failure each one is a scar from:

1. ``cvss``/``verdict``/``mitre`` are on every ``/api/result`` payload and were
   rendered nowhere. Five real droppers came back ``verdict=malicious`` with a
   CVSS vector and mapped ATT&CK techniques, and the report drew a green gauge
   reading 20-30 captioned "Low risk". The verdict — never the 0-100 score —
   drives the headline.
2. ``usePoll`` keeps the last payload when a request fails, and every page read
   ``error`` only inside its ``if (!data)`` branch, so an outage after the first
   load was invisible: the dashboard went on promising "Live".
3. The seven JobDetail action buttons used try/finally with no catch, so a 404,
   409 or 422 was swallowed in silence.
4. The queue's rows were ``<tr onClick>`` — not focusable, no role, no key
   handler — which put every report out of reach of a keyboard. WCAG 2.1.1 and
   4.1.2, Level A, and a procurement blocker under EN 301 549 / Section 508.
5. Measured contrast failures, including the primary CTA on every page.

The colour maths is the real WCAG 2.x relative-luminance formula rather than a
list of approved hex values, so the tokens can be re-tuned freely and the test
still means what it says.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent.parent / "frontend" / "src"
CSS = SRC / "index.css"


def _read(*parts: str) -> str:
    path = SRC.joinpath(*parts)
    assert path.exists(), f"expected frontend source at {path}"
    return path.read_text(encoding="utf-8")


def _code(source: str) -> str:
    """Source with comments removed.

    The comments in these files quote the wording and the thresholds they exist
    to have removed, so a check for "this string is gone" has to look at code.
    """
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"^\s*//.*$", "", source, flags=re.M)


# =============================================================================
# 1. Verdict, CVSS and ATT&CK are typed and rendered
# =============================================================================


def test_types_declare_verdict_cvss_and_mitre():
    types = _read("lib", "types.ts")
    for field in (
        "verdict",
        "threat_name",
        "detection_ratio",
        "detected",
        "total_engines",
        "platform",
        "category",
        "family",
        "engines",
    ):
        assert re.search(rf"^\s*{field}[?]?:", types, re.M), f"VerdictT is missing {field}"
    for field in ("vector", "base_score", "severity", "metrics", "rationale"):
        assert re.search(rf"^\s*{field}[?]?:", types, re.M), f"CvssT is missing {field}"
    for field in ("technique_id", "name", "tactic", "evidence"):
        assert re.search(rf"^\s*{field}[?]?:", types, re.M), f"MitreTechnique is missing {field}"

    # Absent on every job analysed before the verdict engine shipped, so the
    # types have to admit that rather than promise a value that is not there.
    assert re.search(r"cvss\?:", types), "cvss must be optional on the job detail type"
    assert re.search(r"mitre\?:", types), "mitre must be optional on the job detail type"
    assert re.search(r"verdict\?:", types), "verdict must be optional on the job type"


def test_job_detail_leads_with_the_threat_name_and_verdict():
    job = _read("pages", "JobDetail.tsx")
    assert "verdictHeadline(verdict)" in job, "the headline must be the verdict wording"
    assert "verdictTone(verdict)" in job, "the headline colour must come from the verdict"
    assert "threat_name" in job, "the threat name must lead the report"
    assert "detection_ratio" in job, "the detection ratio must be shown"
    assert "detection.engines" in job, "the per-engine detection panel must be rendered"


def test_job_detail_renders_cvss_and_attack():
    job = _read("pages", "JobDetail.tsx")
    for token in ("cvss.vector", "cvss.base_score", "cvss.severity", "cvss.metrics", "cvss.rationale"):
        assert token in job, f"the CVSS panel does not render {token}"
    assert "byTactic(mitre)" in job, "ATT&CK techniques must be grouped by tactic"
    assert "technique_id" in job, "ATT&CK technique IDs must be shown"


def test_verdict_outranks_the_score_band_on_the_gauge():
    """A malicious sample must never render green, whatever it scored."""
    gauge = _read("components", "ScoreGauge.tsx")
    assert re.search(
        r"verdict\s*\?\s*verdictTone\(verdict\)\s*:\s*riskTone\(riskLevel\)", gauge
    ), "ScoreGauge must prefer the verdict tone over the score band"
    assert "verdictHeadline(verdict)" in gauge, "the gauge caption must follow the verdict"


def test_verdict_is_only_read_when_the_engine_actually_decided():
    """The backend serialises a missing verdict as ``{}``; an object is not a
    decision, and treating one as ``clean`` would invent a verdict."""
    fmt = _read("lib", "format.ts")
    assert "job.verdict?.verdict" in fmt
    assert re.search(
        r"v === 'malicious' \|\| v === 'suspicious' \|\| v === 'clean' \? v : null", fmt
    ), "verdictOf must return null for anything that is not a recognised verdict"


def test_dashboard_buckets_by_verdict_not_by_score_band():
    dash = _code(_read("pages", "Dashboard.tsx"))
    assert "needsAttention" in dash, "'Needs attention' must be driven by the verdict"
    assert "Low / clean" not in dash, (
        "the legend must not file flagged samples under a row labelled clean"
    )
    assert not re.search(r"final_score >= 30", dash), (
        "the score threshold belongs in the verdict fallback (format.ts), not in the dashboard"
    )
    for bucket in ("malicious", "suspicious", "clean", "unclassified"):
        assert f"'{bucket}'" in dash, f"the verdict legend is missing the {bucket} bucket"


def test_needs_attention_prefers_the_verdict_and_never_invents_one():
    fmt = _read("lib", "format.ts")
    body = re.search(r"export function needsAttention\([^)]*\)[^{]*\{(.*?)\n\}", fmt, re.S)
    assert body, "needsAttention is missing"
    body = body.group(1)
    assert "verdictOf(job)" in body, "the verdict must be consulted first"
    assert "!== 'clean'" in body, "anything the engine flagged must be listed"
    assert "final_score >= 30" in body, "pre-verdict jobs still need the score fallback"


# =============================================================================
# 2. An outage is visible after the first load
# =============================================================================

#: The pages that poll. Each has to consume `stale`, because each of them
#: previously kept animating as though the backend were still answering.
POLLING_PAGES = ["Dashboard.tsx", "Queue.tsx", "JobDetail.tsx", "Integrations.tsx"]


def test_use_poll_exposes_a_stale_state():
    poll = _read("lib", "usePoll.ts")
    assert re.search(r"const stale = error !== null && data !== null", poll), (
        "usePoll must report 'showing data that is no longer being refreshed'"
    )
    assert re.search(r"return \{[^}]*\bstale\b", poll), "stale must be returned to callers"


@pytest.mark.parametrize("page", POLLING_PAGES)
def test_polling_page_surfaces_a_stale_indicator(page: str):
    src = _read("pages", page)
    assert re.search(r"\bstale\b[^=]*\}\s*=\s*usePoll", src, re.S), (
        f"{page} does not read `stale` off usePoll — an outage after first load is silent there"
    )
    assert "StaleNotice" in src, f"{page} renders no disconnected indicator"


def test_dashboard_stops_claiming_it_is_live_when_it_is_not():
    dash = _read("pages", "Dashboard.tsx")
    assert re.search(r"stale\s*\?[^:]*Not live", dash), (
        "the 'Live — updates every few seconds' caption must not survive an outage"
    )


def test_job_detail_stops_animating_progress_it_cannot_see():
    job = _read("pages", "JobDetail.tsx")
    assert re.search(r"!stale && 'scan'", job), (
        "the scan animation claims progress is being observed; it must stop when polling fails"
    )


# =============================================================================
# 3. Failed actions are shown
# =============================================================================


def test_job_detail_actions_report_their_failures():
    job = _read("pages", "JobDetail.tsx")
    body = re.search(r"async function action\(.*?\n  \}", job, re.S)
    assert body, "the JobDetail action helper is missing"
    body = body.group(0)
    assert "catch" in body, (
        "try/finally with no catch swallowed every 404/409/422 from the seven action buttons"
    )
    assert "setActionError" in body
    # And it has to reach the screen, not just state.
    assert re.search(r"\{actionError && \(", job), "the action error is never rendered"


# =============================================================================
# 4. Every report is reachable by keyboard
# =============================================================================


def test_queue_rows_are_keyboard_operable():
    queue = _read("pages", "Queue.tsx")
    assert re.search(r"<Link\s+to=\{`/job/\$\{job\.public_id\}`\}", queue), (
        "each queue row must contain a real link to its report — a <tr onClick> is "
        "invisible to the keyboard (WCAG 2.1.1) and has no role (4.1.2)"
    )
    # The row handler may only widen the link's hit area; it must stand down when
    # the click was already on the link, so the action is never handled twice.
    assert "closest('a')" in queue


# =============================================================================
# 5. Contrast
# =============================================================================


def _srgb_luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    channels = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(a: str, b: str) -> float:
    la, lb = _srgb_luminance(a), _srgb_luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _themes() -> tuple[dict[str, str], dict[str, str]]:
    """(light, dark) token maps. Dark inherits every token it does not override."""
    css = CSS.read_text(encoding="utf-8")
    theme = re.search(r"@theme\s*\{(.*?)\n\}", css, re.S)
    assert theme, "no @theme block in index.css"

    def colours(block: str) -> dict[str, str]:
        return {
            m.group(1): m.group(2)
            for m in re.finditer(r"--color-([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", block)
        }

    light = colours(theme.group(1))
    dark = dict(light)
    for block in re.findall(r':root\[data-theme="dark"\]\s*\{(.*?)\n\}', css, re.S):
        dark.update(colours(block))
    assert light and dark
    return light, dark


THEMES = dict(zip(("light", "dark"), _themes()))

#: WCAG 1.4.3 — body text and its background.
TEXT_ON_SURFACE = [
    (fg, bg)
    for fg in ("c1", "c2", "c3")
    for bg in ("canvas", "panel", "raised", "sunken")
]


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("fg,bg", TEXT_ON_SURFACE, ids=lambda v: v)
def test_content_tone_clears_aa_on_every_surface(theme: str, fg: str, bg: str):
    """c3 measured 4.31:1 on the canvas — captions sit outside panels, so it is
    not enough for a tone to pass on white."""
    tokens = THEMES[theme]
    ratio = contrast(tokens[fg], tokens[bg])
    assert ratio >= 4.5, f"{theme}: {fg} on {bg} is {ratio:.2f}:1, below the 4.5:1 AA minimum"


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("fill", ["brand", "brand-hover"])
def test_primary_cta_label_clears_aa(theme: str, fill: str):
    """text-white on the dark theme's brand was 3.16:1 — on the primary control
    of every page. The hover state counts too: fading the fill toward the surface
    dropped it to 3.98:1 in light mode."""
    tokens = THEMES[theme]
    ratio = contrast(tokens["on-brand"], tokens[fill])
    assert ratio >= 4.5, f"{theme}: on-brand on {fill} is {ratio:.2f}:1"


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("surface", ["canvas", "panel", "raised"])
def test_control_boundary_clears_the_non_text_minimum(theme: str, surface: str):
    """WCAG 1.4.11. An input's border was 1.34:1 on `raised` — the only thing
    marking the control was invisible to a low-vision analyst."""
    tokens = THEMES[theme]
    ratio = contrast(tokens["line"], tokens[surface])
    assert ratio >= 3.0, f"{theme}: line on {surface} is {ratio:.2f}:1, below the 3:1 minimum"


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_line_strong_is_stronger_than_line(theme: str):
    tokens = THEMES[theme]
    assert contrast(tokens["line-strong"], tokens["panel"]) > contrast(tokens["line"], tokens["panel"])


def test_no_colour_is_named_outside_index_css():
    """The design system's first rule. `text-white` on the primary button was the
    single exception, and it was also the accessibility failure."""
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.ts")) + sorted(SRC.rglob("*.tsx")):
        source = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(source.splitlines(), 1):
            if re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(", line) or re.search(
                r"\b(?:text|bg|border|stroke|fill)-white\b", line
            ):
                offenders.append(f"{path.name}:{line_no}: {line.strip()}")
    assert not offenders, "colours must live only in index.css:\n" + "\n".join(offenders)
