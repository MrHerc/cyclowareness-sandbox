"""The worker's real detonation timeout was 120 s, not the documented 600.

`worker/config.py` carries a fifteen-line comment explaining that 120 seconds is
shorter than a detonation -- CAPE's own defaults are `analysis = 200` plus
`vm_state = 300`, and a measured task took 315 s -- and the dataclass field says
`engine_timeout_seconds: int = 600`. `worker/README.md` documents 600 and says
"**Not 120**".

And `Config.from_env()`, the only constructor `main()` uses, passed 120. The 600
was dead code that no running worker could observe. `worker/Dockerfile` then
hard-coded `ENGINE_TIMEOUT_SECONDS=120` as a container ENV, which shadows the
code default anyway, so fixing one without the other changes nothing.

The consequence is not a slow analysis. `_poll` gives up at the deadline and
returns `Report.unavailable(... "did not finish within 120s")`, which the backend
records as `tiers.dynamic = {ran: False}` -- a false statement, because the
detonation did run and did finish. `Report.unavailable` leaves `refused=False`,
so `_needs_dynamic` offers the sample again on the next poll, and the same file
is re-detonated every two minutes forever, burning a guest each time.

The live deployment was not affected: `/etc/cyclo-worker.env` sets 600
explicitly. A fresh install had no such luck, which is the whole point of a
default.

This test reads the three places the number lives and requires them to agree.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "worker" / "config.py"
DOCKERFILE = REPO / "worker" / "Dockerfile"
README = REPO / "worker" / "README.md"

#: What a detonation actually needs: CAPE's `analysis = 200` plus `vm_state = 300`
#: for revert and boot, with headroom. A measured task took 315 s.
MINIMUM = 600


def _field_default() -> int:
    tree = ast.parse(CONFIG.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "engine_timeout_seconds":
            return ast.literal_eval(node.value)
    raise AssertionError("engine_timeout_seconds field not found")


def _from_env_default() -> int:
    source = CONFIG.read_text(encoding="utf-8")
    match = re.search(
        r'engine_timeout_seconds=_int\(\s*"ENGINE_TIMEOUT_SECONDS"\s*,\s*(\d+)\s*\)', source)
    assert match, "from_env no longer sets engine_timeout_seconds the same way"
    return int(match.group(1))


def _dockerfile_default() -> int | None:
    match = re.search(r"ENGINE_TIMEOUT_SECONDS=(\d+)", DOCKERFILE.read_text(encoding="utf-8"))
    return int(match.group(1)) if match else None


def test_the_field_default_is_long_enough() -> None:
    assert _field_default() >= MINIMUM


def test_from_env_agrees_with_the_field() -> None:
    """`from_env` is the only constructor main() uses; the field alone is dead."""
    assert _from_env_default() == _field_default(), (
        f"from_env passes {_from_env_default()} while the field says "
        f"{_field_default()} — every running worker sees from_env"
    )


def test_the_container_does_not_shadow_it_with_something_shorter() -> None:
    """A container ENV wins over the code default, so it has to agree too."""
    value = _dockerfile_default()
    if value is not None:
        assert value >= MINIMUM, (
            f"worker/Dockerfile pins ENGINE_TIMEOUT_SECONDS={value}, which shadows "
            f"the code default of {_field_default()}"
        )


def test_the_readme_is_not_left_documenting_a_different_number() -> None:
    text = README.read_text(encoding="utf-8")
    documented = re.findall(r"ENGINE_TIMEOUT_SECONDS[^\n]{0,80}?(\d{2,4})", text)
    assert documented, "README no longer documents ENGINE_TIMEOUT_SECONDS"
    assert any(int(v) == _from_env_default() for v in documented), (
        f"README documents {documented} but from_env uses {_from_env_default()}"
    )
