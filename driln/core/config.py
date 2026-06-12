"""Centralized configuration via Pydantic Settings.

All settings are loaded from environment variables prefixed with ``DRILN_``,
or from a ``.env`` file in the project root.  The singleton :func:`get_settings`
returns a cached instance so the file is only read once per process.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings.

    Every field maps to an env-var ``DRILN_<FIELD_NAME>`` (upper-cased).
    """

    model_config = SettingsConfigDict(
        env_prefix="DRILN_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ─────────────────────────────────────────────
    app_name: str = "driln"
    debug: bool = False
    log_level: str = "INFO"
    api_key: SecretStr | None = None
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    # ── Database ────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./driln.db"

    # ── AI Provider ─────────────────────────────────────────────
    ai_provider: str = "openai"
    ai_model: str = "gpt-4o"
    ai_api_key: SecretStr | None = None
    ai_base_url: str | None = None
    ai_provider_module: str | None = None  # e.g. "my_custom_ai" — auto-imported at startup
    ai_temperature: float = 0.2
    ai_max_tokens: int = 4096

    # ── Scanning ────────────────────────────────────────────────
    scan_timeout: int = 300
    scan_max_concurrent: int = 3
    scan_output_dir: Path = Path("./output")

    # ── Tools ───────────────────────────────────────────────────
    tools_enabled: list[str] = [
        "nmap",
        "subfinder",
        "httpx",
        "nuclei",
    ]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached global settings instance."""
    return Settings()  # type: ignore[call-arg]
