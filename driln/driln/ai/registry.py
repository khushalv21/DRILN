"""AI provider registry — discover and instantiate the configured provider."""

from __future__ import annotations

import structlog

from driln.ai.base import BaseAIProvider
from driln.core.config import get_settings
from driln.core.exceptions import ConfigError

logger = structlog.get_logger()

_provider: BaseAIProvider | None = None


def _create_provider(name: str) -> BaseAIProvider:
    """Instantiate a provider by name."""
    if name == "openai":
        from driln.ai.openai import OpenAIProvider

        return OpenAIProvider()
    else:
        raise ConfigError(f"Unknown AI provider: '{name}'. Supported: openai")


def get_ai_provider() -> BaseAIProvider:
    """Return the global AI provider instance, creating it if needed."""
    global _provider
    if _provider is None:
        settings = get_settings()
        _provider = _create_provider(settings.ai_provider)
        logger.info("ai_provider_initialized", provider=_provider.name, model=settings.ai_model)
    return _provider


def reset_provider() -> None:
    """Reset the cached provider (useful for testing or config reload)."""
    global _provider
    _provider = None
