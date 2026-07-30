"""Runtime configuration.

One ``Settings`` object, read once, from the environment. Two postures:

* ``APP_ENV=demo`` (the default) — zero-setup: SQLite, a generated signing key,
  seeded demo credentials printed at boot. This is the exhibition/hackathon
  build a judge can run with one command.
* ``APP_ENV=production`` — refuses to boot on a placeholder secret or default
  credentials, because a security product that ships with ``analyst/analyst``
  reachable from the internet is the vulnerability, not the tool.

The refusal is deliberate and load-bearing: it is cheaper to fail at startup
than to discover the default password in an access log.
"""
from __future__ import annotations

import secrets
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    app_env: str = Field(default="demo")

    # --- persistence --------------------------------------------------------
    database_url: str = Field(default="sqlite:///./sandbox.db")

    # --- auth ---------------------------------------------------------------
    #: Signs the HMAC session tokens. MUST be overridden in production.
    secret_key: str = Field(default="dev-only-insecure-key-change-me")
    #: The single analyst account the login endpoint checks against.
    analyst_username: str = Field(default="analyst")
    analyst_password: str = Field(default="analyst")
    #: Static keys for programmatic access to /api/analyze (comma-separated).
    #: Empty in production unless set — API-key auth is opt-in.
    #:
    #: An entry may name the tenant it belongs to: ``acme:ck_live_x``. A bare key
    #: belongs to ``default_tenant``, so an existing deployment keeps working
    #: unchanged. A colon is therefore not valid inside a key itself.
    api_keys: str = Field(default="demo-key")
    token_ttl_hours: int = Field(default=12)

    # --- tenancy ------------------------------------------------------------
    #: Which tenant owns data that names no owner: the analyst session, bare API
    #: keys, and every job that existed before tenancy did.
    #:
    #: One tenant is the normal case — a sovereign deployment analysing its own
    #: organisation's samples, where this is invisible. The column exists so an
    #: MSSP can run one deployment for several client organisations without
    #: their evidence mixing, and because adding it later, to a database already
    #: holding a customer's data, is a migration nobody wants to run under load.
    default_tenant: str = Field(default="default")
    #: The tenant the interactive analyst account belongs to. Empty means
    #: ``default_tenant``, which is what a single-tenant deployment wants.
    analyst_tenant: str = Field(default="")

    # --- deployment topology ------------------------------------------------
    #: Whether `X-Forwarded-For` / `X-Real-IP` may be believed.
    #:
    #: Off by default, and the default is the safe one: a forwarding header is
    #: written by whoever is upstream, and upstream includes the caller unless a
    #: proxy you control overwrites it. Turn it on only when this process is
    #: reachable ONLY through such a proxy. It decides two things — the address
    #: written into the chain of custody, and the identity the rate limiter
    #: charges — so believing a forged one lets a caller both mislabel their own
    #: audit trail and mint themselves a fresh rate-limit budget per request.
    trust_proxy_headers: bool = Field(default=False)
    #: WHICH forwarding header this deployment's proxy actually writes.
    #:
    #: There is no safe default and picking one silently was the bug. Believing
    #: `X-Real-IP` first is correct behind an nginx that sets only it and passes
    #: `X-Forwarded-For` through verbatim — and wrong behind an append-only proxy
    #: (ALB, Cloudflare, Render, Heroku), which sets no `X-Real-IP` at all, so a
    #: client's own header survives and it picks its own rate-limit bucket and
    #: its own audit source address. Believing `X-Forwarded-For` first is wrong
    #: in the mirror case, for the same reason.
    #:
    #: So the operator names it. Left empty with `TRUST_PROXY_HEADERS=true`, no
    #: header is believed and the socket peer is used — the safe direction, with
    #: a log line saying what to set.
    proxy_client_header: str = Field(default="")

    # --- observability ------------------------------------------------------
    #: Bearer token a Prometheus scraper presents to read `/metrics`.
    #:
    #: The counters are business data — daily volume, malicious share, upload
    #: rejections, analysis latency — so an open endpoint publishes a customer's
    #: throughput and threat profile to anyone who asks, with no login and no
    #: trace. Unset and not public, `/metrics` answers 404: a deployment that has
    #: not decided is a deployment that does not expose it.
    metrics_token: str = Field(default="")
    #: Say out loud that this deployment intends `/metrics` to be world-readable
    #: (it is bound privately, or the numbers genuinely are not sensitive).
    metrics_public: bool = Field(default=False)

    # --- ingest limits ------------------------------------------------------
    max_sample_mb: int = Field(default=32)

    # --- data lifecycle -----------------------------------------------------
    #: Days before the quarantined bytes are deleted. The sample is live malware
    #: on the operator's disk: a hazard and a storage cost, needed after the
    #: analysis only for a re-run. 0 keeps it forever — an unset policy must
    #: never delete a customer's data, so retention is opt-in, not opt-out.
    sample_retention_days: int = Field(default=0)
    #: Days before the report row itself goes. This is the evidence the customer
    #: bought, so it normally outlives the sample by a long way. 0 keeps forever.
    report_retention_days: int = Field(default=0)
    retention_sweep_hours: float = Field(default=6.0)

    # --- AI -----------------------------------------------------------------
    #: When set, an LLM writes the human-readable triage narrative. Absent, a
    #: deterministic template does — the numeric verdict is identical either way,
    #: because the score comes from the engine's own model, never from the LLM.
    anthropic_api_key: str = Field(default="")

    # --- dynamic tier -------------------------------------------------------
    #: Shared secret an off-host worker presents to post a dynamic report.
    dynamic_worker_token: str = Field(default="")

    # --- report attestation -------------------------------------------------
    #: Base64-encoded 32-byte Ed25519 seed. Signs exported reports so a recipient
    #: can prove this deployment produced exactly those bytes.
    #:
    #: Deliberately NOT auto-generated when absent, unlike ``secret_key`` below.
    #: A per-boot key would sign reports that verify until the next restart and
    #: against nothing afterwards — evidence that expires silently is worse than
    #: a report that plainly says it is unsigned, which is what the export emits
    #: instead. Generate one with:
    #:   python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"
    signing_key: str = Field(default="")

    # --- sovereignty --------------------------------------------------------
    #: The core promise: no analysis data leaves this deployment. Enforced at a
    #: single choke point (app/sovereignty.py), not asserted in a datasheet.
    #: Defaults ON, because a guarantee an operator has to remember to enable is
    #: a guarantee that fails the first time someone forgets — and the buyer who
    #: needs it is the one legally forbidden from getting it wrong.
    sovereign_mode: bool = Field(default=True)
    #: The one deliberate exception. Submitting a URL for analysis IS a request
    #: to fetch it, so the fetcher is not an exfiltration path. Separately
    #: controllable because an air-gapped deployment must be able to close it.
    sovereign_allow_url_fetch: bool = Field(default=True)

    # --- notifying entity (regulatory records) ------------------------------
    #: A NIS2 Article 23 early warning and a DORA Article 19 notification both
    #: identify the notifying entity. The engine cannot know who is running it,
    #: so these are supplied here and copied verbatim into the incident record;
    #: left empty, the record names them as operator input still required rather
    #: than inventing an entity.
    entity_name: str = Field(default="")
    entity_country: str = Field(default="")
    entity_sector: str = Field(default="")
    entity_contact: str = Field(default="")

    # --- CORS (dev only; the Docker image serves API+SPA same-origin) -------
    cors_origins: str = Field(default="http://localhost:5173,http://127.0.0.1:5173")

    # --- derived ------------------------------------------------------------
    @property
    def is_demo(self) -> bool:
        return self.app_env.strip().lower() == "demo"

    @property
    def is_production(self) -> bool:
        return not self.is_demo

    @property
    def api_key_list(self) -> list[str]:
        """Just the keys, without any tenant prefix — for comparison and checks."""
        return [key for key, _tenant in self.api_key_tenants]

    @property
    def api_key_tenants(self) -> list[tuple[str, str]]:
        """``[(key, tenant), …]`` — the parsed form of ``API_KEYS``.

        ``acme:ck_live_x`` belongs to tenant ``acme``; a bare ``ck_live_y``
        belongs to ``default_tenant``. Split on the FIRST colon only, so a key
        containing one is still parsed the same way every time rather than
        landing in a different tenant depending on how many colons it has.
        """
        out: list[tuple[str, str]] = []
        fallback = self.default_tenant.strip() or "default"
        for raw in self.api_keys.split(","):
            entry = raw.strip()
            if not entry:
                continue
            tenant, sep, key = entry.partition(":")
            if sep and tenant.strip() and key.strip():
                out.append((key.strip(), tenant.strip()))
            else:
                out.append((entry, fallback))
        return out

    @property
    def analyst_tenant_name(self) -> str:
        return self.analyst_tenant.strip() or self.default_tenant.strip() or "default"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def ai_provider(self) -> str:
        # An LLM provider is an outbound destination like any other. Reporting
        # "anthropic" while sovereign mode refuses the call would advertise a
        # capability this deployment does not have, in the one place an operator
        # looks to find out what leaves the building.
        if self.sovereign_mode:
            return "template"
        return "anthropic" if self.anthropic_api_key.strip() else "template"

    def validate_production(self) -> list[str]:
        """Reasons this configuration is unsafe to expose. Empty ⇒ safe."""
        problems: list[str] = []
        if self.secret_key == "dev-only-insecure-key-change-me":
            problems.append("SECRET_KEY is the built-in placeholder")
        if self.analyst_password in ("analyst", "", "password", "changeme"):
            problems.append("ANALYST_PASSWORD is a default/guessable value")
        # An API key is a bearer credential like any other, and the built-in one
        # is printed in the README. A production deployment that kept it is
        # open to anyone who has read the docs.
        if any(k in ("demo-key", "changeme", "test") for k in self.api_key_list):
            problems.append("API_KEYS contains a built-in/guessable key")
        if self.database_url.startswith("sqlite"):
            problems.append("DATABASE_URL is SQLite; use PostgreSQL in production")
        return problems


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.is_production:
        problems = settings.validate_production()
        if problems:
            raise RuntimeError(
                "Refusing to boot in production with an unsafe configuration:\n  - "
                + "\n  - ".join(problems)
                + "\nSet APP_ENV=demo for the local/exhibition build, or fix the above."
            )
    return settings


def ensure_secret_key(settings: Settings) -> str:
    """A usable signing key even in demo, where none was supplied."""
    if settings.secret_key and settings.secret_key != "dev-only-insecure-key-change-me":
        return settings.secret_key
    # Demo: stable within the process, regenerated per boot. Tokens do not
    # survive a restart, which for a demo is a feature, not a bug.
    if not hasattr(ensure_secret_key, "_demo_key"):
        ensure_secret_key._demo_key = secrets.token_urlsafe(32)  # type: ignore[attr-defined]
    return ensure_secret_key._demo_key  # type: ignore[attr-defined]
