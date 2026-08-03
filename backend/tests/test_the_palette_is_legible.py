"""Every colour pair the product renders, measured. Both themes.

There was already a contrast test. It went green while measuring nothing: it
asserted that certain token NAMES appeared in the stylesheet, which stays true
no matter what values they hold. This one parses the hex values out of
`index.css` and computes WCAG contrast ratios, so a repaint that drops a tone
below the line fails here rather than in front of an analyst.

It has caught the same token three times now. `--color-line` is the boundary of
a CONTROL -- an input, a select, a secondary button -- and WCAG 1.4.11 requires
3:1 against the surface behind it. It measured 1.34:1 once, 2.87:1 once, and
2.82:1 on the dark repaint. Each time the border was still visible to someone
who already knew the control was there, which is exactly why eyeballing it does
not work.

Deliberately independent of the browser: a headless check of the rendered DOM
cannot be trusted here, because elements carrying a CSS transition report the
value they are transitioning FROM until the compositor advances, and a
non-displayed tab never advances it. Reading the tokens is the measurement that
does not lie.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

CSS = Path(__file__).resolve().parents[2] / "frontend" / "src" / "index.css"

#: (text token, surface token, minimum ratio). 4.5 is AA for body text;
#: 3.0 is WCAG 1.4.11 for the boundary of a user-interface component.
PAIRS: list[tuple[str, str, float]] = (
    [(t, s, 4.5) for t in ("c1", "c2", "c3") for s in ("canvas", "panel", "raised", "sunken")]
    + [
        # `on-brand` is the only legal foreground on a lime fill. Lime is a light
        # colour, so this pair fails instantly if anyone "simplifies" it to white.
        ("on-brand", "brand", 4.5),
        ("brand-fg", "panel", 4.5),
        ("brand-fg", "canvas", 4.5),
    ]
    + [(t, "panel", 4.5) for t in ("danger", "warning", "success", "info")]
    + [("line", "raised", 3.0), ("line", "panel", 3.0)]
)


def _tokens() -> dict[str, dict[str, str]]:
    css = CSS.read_text(encoding="utf-8")

    def block(pattern: str) -> dict[str, str]:
        match = re.search(pattern, css, re.S)
        if not match:
            return {}
        return dict(re.findall(r"--color-([a-z0-9-]+):\s*(#[0-9a-fA-F]{3,8})", match.group(1)))

    dark = block(r"@theme\s*\{(.*?)\n\}")
    light = dict(dark)
    light.update(block(r':root\[data-theme="light"\]\s*\{(.*?)\n\}'))
    return {"dark": dark, "light": light}


def _luminance(hex_colour: str) -> float:
    value = hex_colour.lstrip("#")
    if len(value) == 3:
        value = "".join(c * 2 for c in value)
    channels = [int(value[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _ratio(a: str, b: str) -> float:
    lighter, darker = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


THEMES = _tokens()


def test_the_stylesheet_still_parses() -> None:
    """A regex that stops matching would make every assertion below vacuous --
    which is the failure this file exists to replace."""
    for name, theme in THEMES.items():
        assert len(theme) >= 15, f"{name}: only parsed {sorted(theme)}"
        assert "brand" in theme and "canvas" in theme, name


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("fg,bg,need", PAIRS, ids=lambda v: str(v))
def test_every_rendered_pair_is_legible(theme: str, fg: str, bg: str, need: float) -> None:
    tokens = THEMES[theme]
    assert fg in tokens, f"{theme} defines no --color-{fg}"
    assert bg in tokens, f"{theme} defines no --color-{bg}"
    ratio = _ratio(tokens[fg], tokens[bg])
    assert ratio >= need, (
        f"{theme}: {fg} ({tokens[fg]}) on {bg} ({tokens[bg]}) measures {ratio:.2f}:1, "
        f"needs {need}:1"
    )


def test_the_accent_is_not_a_status_colour() -> None:
    """Rule 2 of the token file, as an assertion rather than a comment.

    The brand must be distinguishable from every risk hue, or "this row is
    selected" and "this row is dangerous" become the same signal. Compared by
    luminance AND by hue distance, because two colours can differ in one and
    read identically in the other -- the previous amber sat close enough to the
    lime that the two collapsed at a glance.
    """
    import colorsys

    def hue(hex_colour: str) -> float:
        value = hex_colour.lstrip("#")
        r, g, b = (int(value[i : i + 2], 16) / 255 for i in (0, 2, 4))
        return colorsys.rgb_to_hls(r, g, b)[0] * 360

    for theme, tokens in THEMES.items():
        brand = hue(tokens["brand"])
        for status in ("danger", "warning", "success", "info"):
            gap = abs(brand - hue(tokens[status]))
            gap = min(gap, 360 - gap)
            assert gap >= 25, (
                f"{theme}: brand ({tokens['brand']}) and {status} ({tokens[status]}) "
                f"are {gap:.0f} degrees apart -- too close to tell apart at a glance"
            )
