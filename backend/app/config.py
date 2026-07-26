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
    api_keys: str = Field(default="demo-key")
    token_ttl_hours: int = Field(default=12)

    # --- ingest limits ------------------------------------------------------
    max_sample_mb: int = Field(default=32)

    # --- AI -----------------------------------------------------------------
    #: When set, an LLM writes the human-readable triage narrative. Absent, a
    #: deterministic template does — the numeric verdict is identical either way,
    #: because the score comes from the engine's own model, never from the LLM.
    anthropic_api_key: str = Field(default="")

    # --- dynamic tier -------------------------------------------------------
    #: Shared secret an off-host worker presents to post a dynamic report.
    dynamic_worker_token: str = Field(default="")

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
        return [k.strip() for k in self.api_keys.split(",") if k.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def ai_provider(self) -> str:
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
