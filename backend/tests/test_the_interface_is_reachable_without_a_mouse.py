"""Four accessibility defects, asserted against the source that ships.

There is no browser in this suite, so these read the components. That is a real
limitation and worth naming: they prove the attribute, the role and the handler
are present, not that a screen reader speaks the right sentence. What they DO
catch is the whole class that was found here -- a control that was never wired
up at all -- and a regression that removes one.

The four:

  * SPA navigation left focus on `document.body`. React swapped the content and
    the browser announced nothing, so a screen reader kept reading the previous
    page and a keyboard user's next Tab restarted from the navigation, on every
    navigation.
  * Eight rail controls stood before the content with no way past them.
  * `Callout` carries every dynamically-rendered error in the product and had no
    role at all, so a wrong archive password, a 409 on re-analyse and a failed
    export were silent in six places -- the only feedback was a colour.
  * `Tabs` declared `role="radiogroup"` / `role="radio"` and implemented neither
    arrow-key movement nor a roving tabindex. Declaring a role is a promise
    about the keyboard, and announcing one contract while honouring another is
    worse than claiming no role: the user acts on what they were told.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "frontend" / "src"
LAYOUT = SRC / "components" / "Layout.tsx"
UI = SRC / "components" / "ui.tsx"
GRAPH = SRC / "components" / "BehaviorGraph.tsx"
DASHBOARD = SRC / "pages" / "Dashboard.tsx"


@pytest.fixture(scope="module")
def layout() -> str:
    return LAYOUT.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ui() -> str:
    return UI.read_text(encoding="utf-8")


def test_focus_moves_to_the_main_region_on_every_route_change(layout: str) -> None:
    assert "useLocation" in layout, "the layout does not observe the route"
    assert re.search(r"main\.current\?\.focus\(", layout), layout[:0] or "focus is never moved"
    # Keyed on the path, so it fires per navigation rather than once on mount.
    assert re.search(r"\[location\.pathname\]", layout), "the effect does not depend on the route"


def test_the_main_region_can_receive_focus_without_joining_the_tab_order(layout: str) -> None:
    """`tabIndex={-1}` is what makes the two compatible. Without it the region
    either cannot be focused or becomes one more stop on the way to the
    content."""
    assert re.search(r"<main[^>]*tabIndex=\{-1\}", layout, re.S), layout.count("<main")


def test_a_skip_link_is_first_in_the_tab_order(layout: str) -> None:
    assert 'href="#main"' in layout, "no skip link"
    assert re.search(r'<main[^>]*id="main"', layout, re.S), "the skip link points at nothing"
    # Hidden until focused: `sr-only` alone would leave it invisible even to the
    # keyboard user it exists for.
    assert "focus:not-sr-only" in layout, "the skip link never becomes visible"
    body_start = layout.index("<div className=\"min-h-screen")
    assert layout.index('href="#main"') - body_start < 600, (
        "the skip link is not the first focusable thing in the layout"
    )


def test_a_callout_announces_itself(ui: str) -> None:
    block = ui[ui.index("export function Callout") : ui.index("export function Spinner")]
    assert "role={role}" in block, "Callout renders no role"
    # `alert` interrupts, `status` waits for a pause. A failure is the first.
    assert "'alert'" in block and "'status'" in block, block[-400:]
    assert "danger" in block and "warning" in block


def test_a_callout_does_not_double_up_aria_live(ui: str) -> None:
    """`role="alert"` implies `aria-live="assertive"`. Setting both makes some
    screen readers read the region twice, which is its own defect."""
    block = ui[ui.index("export function Callout") : ui.index("export function Spinner")]
    # The ATTRIBUTE, not the word. The first version of this assertion searched
    # for `aria-live` anywhere in the block and matched the comment that explains
    # why it is deliberately absent -- a test failing on its own documentation.
    assert not re.search(r"aria-live\s*=", block), block


def test_tabs_implements_the_keyboard_contract_it_declares(ui: str) -> None:
    block = ui[ui.index("export function Tabs") :]
    assert 'role="radiogroup"' in block
    assert "onKeyDown" in block, "the group declares a radiogroup and ignores the keyboard"
    for key in ("ArrowRight", "ArrowLeft", "Home", "End"):
        assert key in block, f"{key} does not move between options"
    # A roving tabindex is what makes "Tab leaves the group" true.
    assert "tabIndex={value === t.key ? 0 : -1}" in block, block[:600]


def test_the_behaviour_timeline_is_readable_without_seeing_it() -> None:
    """`role="img"` collapses everything inside an SVG to its label, so the whole
    timeline announced as two words and every event was unreachable."""
    text = GRAPH.read_text(encoding="utf-8")
    assert 'className="sr-only"' in text, "the events are not exposed as text"
    assert "<ol" in text, "a timeline is ordered; a list of divs does not say so"
    assert "listed below this chart" in text, (
        "the chart's label does not point at the list that carries the data"
    )


def test_the_needs_attention_rule_is_visible_not_hovered() -> None:
    """It lived only in a `title` on a non-interactive div: unreachable by
    keyboard, unannounced, and invisible to anyone not hovering that tile."""
    text = DASHBOARD.read_text(encoding="utf-8")
    assert "attention floor without reaching a verdict" in text
    # Present as rendered text, not only inside the `hint` prop.
    assert text.count("attention floor without reaching a verdict") >= 2, (
        "the rule appears once, which means it is still only the tooltip"
    )


def test_the_two_charts_say_which_population_they_count() -> None:
    """They count different sets -- every job versus completed jobs -- and
    neither said so, which made two correct panels look like a contradiction."""
    text = DASHBOARD.read_text(encoding="utf-8")
    assert "in flight or completed" in text, "the family chart does not name its population"
    assert "completed sample" in text, "the verdict chart does not name its population"
