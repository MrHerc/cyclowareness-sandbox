"""The shape of one integration in the capability matrix.

An ``Engine`` is a *descriptor*, not a runner. It answers one honest question
for ``/api/capabilities``: "is this thing wired up on *this* deployment, and if
not, what would it take to turn it on?" It never touches a sample. The actual
work — detonation, hash lookups, file scanning — lives elsewhere (in the
off-host worker, or in the sibling client modules) and only ever runs when the
descriptor reports ``configured() is True``.

Two kinds of "configured" exist, and the distinction is deliberate:

* Engines that this web service talks to directly (VirusTotal, Cuckoo, a
  Strelka cluster) are configured when *their own* credentials/URLs are in the
  environment.
* Engines that live inside the off-host worker (the native behaviour engine,
  the Qiling emulator, a firejail sandbox) have no env vars of their own here —
  the web service never reaches them. For those, "configured" means a worker
  *can attach at all*, i.e. ``DYNAMIC_WORKER_TOKEN`` is set. An engine with no
  ``env_keys`` therefore reads that token.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

from ... import sovereignty

Kind = Literal["native", "opensource-sandbox", "emulator", "threat-intel"]
Tier = Literal["static", "dynamic"]

#: The env var that lets an off-host worker authenticate to the dynamic seam.
#: Worker-resident engines (native/emulator/jail) are "reachable" exactly when a
#: worker can attach, which is exactly when this token is set.
WORKER_TOKEN_ENV = "DYNAMIC_WORKER_TOKEN"


@dataclass(frozen=True)
class Engine:
    """A single row in the integration matrix."""

    key: str
    name: str
    vendor: str
    kind: Kind
    tier: Tier
    #: Env vars that, when *all* set, enable this integration. Empty for
    #: worker-resident engines, which fall back to the worker token.
    env_keys: list[str] = field(default_factory=list)
    #: Plain-language statement of what an operator must provide to turn it on.
    requires: str = ""
    #: What it does and, crucially, what it does *not* do — so the matrix never
    #: overstates a capability.
    notes: str = ""
    docs_url: str = ""
    #: True when the credentials this row reports on live in the WORKER's
    #: environment, not this process's.
    #:
    #: `configured()` reads `os.environ` — the web service's. Cuckoo, CAPEv2 and
    #: Joe are run by the worker, from the worker's own environment, so on a
    #: split deployment (the normal one: the detonation host is a separate
    #: machine) this row reports on variables the process that runs the engine
    #: never sees. It can say "not configured" for a working integration and
    #: "configured" for one the worker has no credentials for.
    #:
    #: There is no way to fix that from here — the two processes share only the
    #: /api/dynamic/* seam — so the row SAYS SO rather than presenting a guess as
    #: a fact.
    configured_on_worker: bool = False
    #: The sovereignty choke-point destination this engine's client calls, when
    #: it leaves the building at all. Empty for worker-resident engines, which
    #: the web service never reaches over the network. Declared per engine rather
    #: than inferred from ``env_keys``, because "has credentials" and "sends data
    #: off-host" are different facts and conflating them is how a matrix ends up
    #: claiming an air-gapped deployment talks to Google.
    destination: str = ""

    def configured(self) -> bool:
        """True when this integration could actually run on this deployment.

        For engines with ``env_keys``, every one of those vars must be present
        and non-empty. For worker-resident engines (no ``env_keys``), a worker
        can only attach when ``DYNAMIC_WORKER_TOKEN`` is set — so that is the
        gate.
        """
        keys = self.env_keys or [WORKER_TOKEN_ENV]
        return all(bool(os.environ.get(k, "").strip()) for k in keys)

    def sends_data_off_host(self) -> bool:
        return bool(self.destination)

    def blocked_by_sovereign_mode(self) -> bool:
        """Credentials present, but the choke point will refuse the call."""
        return self.sends_data_off_host() and not sovereignty.allowed(self.destination)

    def describe(self) -> dict:
        """Serialisable row for ``/api/capabilities`` — no secrets, ever."""
        return {
            "key": self.key,
            "name": self.name,
            "vendor": self.vendor,
            "kind": self.kind,
            "tier": self.tier,
            "configured": self.configured(),
            # ``configured`` means "credentials are present", which is not the
            # same as "will run". A sovereign deployment that kept a VT key must
            # show the key AND the refusal, so nobody reads a green row as proof
            # the lookup happened.
            "sends_data_off_host": self.sends_data_off_host(),
            "blocked_by_sovereign_mode": self.blocked_by_sovereign_mode(),
            "requires": self.requires,
            # Which process's environment `configured` was read from. Without
            # this the matrix presents a reading of the wrong machine's
            # configuration as a fact about the integration.
            "configured_on_worker": self.configured_on_worker,
            "configuration_caveat": (
                "Read from this web service's environment. This engine runs in "
                "the off-host worker and uses the WORKER's environment, so on a "
                "split deployment this row may not reflect what the worker has."
                if self.configured_on_worker
                else ""
            ),
            "notes": self.notes,
            "docs_url": self.docs_url,
        }
