"""Whether behaviour can actually be observed here, and if not, what is missing.

TWO SWITCHES, AND THEY CAN DISAGREE. `SANDBOX_DYNAMIC_WORKER` is the engine's
declaration that an operator has attached isolated hardware.
`DYNAMIC_WORKER_TOKEN` is the credential that lets that hardware post its
findings back. Either one alone is a half-configured deployment.

`/api/capabilities` reported `native.dynamic_available()` — the flag alone —
and never consulted the token. So a deployment with `SANDBOX_DYNAMIC_WORKER=1`
and no token advertised a behavioural tier while `require_worker` answered

    503 Dynamic ingest is not enabled on this deployment (no worker token set)

to every queue, sample and report request. The capability endpoint is the page
this product deliberately leaves unauthenticated so a buyer can read the posture
before opening an account, and it was promising a tier that could not run.

The reason is returned alongside, because "no worker attached" and "a worker is
attached but cannot report" send an operator to two different places, and a bare
`false` says neither.

This is the same rule the portal reached independently after the inverse defect
bit it live there — a green panel reading "Samples are parsed and also executed
under supervision" beside a job record saying the sample was never run. One
definition now, in a module both an API handler and a test can import.
"""
from __future__ import annotations

from ..config import Settings
from ..engine import native


def dynamic_state(settings: Settings) -> tuple[bool, str | None]:
    """Return ``(available, reason_if_not)``."""
    declared = native.dynamic_available()
    ingest_open = bool((settings.dynamic_worker_token or "").strip())

    if declared and ingest_open:
        return True, None

    if declared and not ingest_open:
        return False, (
            "A dynamic worker is declared for this deployment, but no "
            "DYNAMIC_WORKER_TOKEN is configured — so the worker cannot post its "
            "findings back and the ingest endpoints refuse every request. "
            "Nothing has been detonated."
        )

    if ingest_open and not declared:
        # A TOKEN IS A CREDENTIAL, NOT HARDWARE. Both switches are required, and
        # treating the token alone as sufficient is the flattering reading —
        # which is precisely the one that produced two screens of the same
        # deployment making opposite claims about whether hostile code had run.
        return False, (
            "A DYNAMIC_WORKER_TOKEN is configured, but SANDBOX_DYNAMIC_WORKER is "
            "not set, so no worker has been declared for this deployment and none "
            "has claimed a job. Nothing has been detonated. Set both to open the "
            "tier — the token lets a worker post its findings back, the flag is "
            "the operator's statement that the isolated hardware really exists."
        )

    return False, native.unavailable_reason()
