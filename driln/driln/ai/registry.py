"""AI provider registry — discover, register, and instantiate providers.

Supports built-in providers (openai) and custom external providers
loaded via the ``DRILN_AI_PROVIDER_MODULE`` environment variable.

Custom provider workflow:
    1. Create a Python module with a class inheriting ``BaseAIProvider``.
    2. At module scope, call ``register_provider("myname", MyProvider)``.
    3. Set ``DRILN_AI_PROVIDER=myname`` and ``DRILN_AI_PROVIDER_MODULE=my_module``.
"""

from __future__ import annotations

import importlib

import structlog

from driln.ai.base import BaseAIProvider
from driln.core.config import get_settings
from driln.core.exceptions import ConfigError

logger = structlog.get_logger()

_provider: BaseAIProvider | None = None
_custom_providers: dict[str, type[BaseAIProvider]] = {}
_custom_loaded: bool = False


# ── Custom provider registration ────────────────────────────────


def register_provider(name: str, cls: type[BaseAIProvider]) -> None:
    """Register an external AI provider class.

    Call this from your custom provider module to make it available
    to Driln. The module is auto-loaded when ``DRILN_AI_PROVIDER_MODULE``
    is set.

    Args:
        name: Provider name (used in ``DRILN_AI_PROVIDER``).
        cls: Provider class inheriting ``BaseAIProvider``.

    Raises:
        TypeError: If ``cls`` doesn't inherit from ``BaseAIProvider``.
    """
    if not (isinstance(cls, type) and issubclass(cls, BaseAIProvider)):
        raise TypeError(
            f"Provider class must inherit from BaseAIProvider, got {cls}"
        )
    _custom_providers[name] = cls
    logger.info("custom_ai_provider_registered", name=name, cls=cls.__name__)


def _load_custom_provider() -> None:
    """Load the custom provider module if configured (once only)."""
    global _custom_loaded
    if _custom_loaded:
        return
    _custom_loaded = True

    settings = get_settings()
    module_name = settings.ai_provider_module
    if not module_name:
        return

    try:
        importlib.import_module(module_name)
        logger.info("custom_ai_module_loaded", module=module_name)
    except ImportError as e:
        raise ConfigError(
            f"Cannot load custom AI provider module '{module_name}': {e}. "
            f"Make sure the module is installed or on PYTHONPATH."
        ) from e
    except Exception as e:
        raise ConfigError(
            f"Error loading custom AI provider module '{module_name}': {e}"
        ) from e


# ── Provider instantiation ──────────────────────────────────────


def _create_provider(name: str) -> BaseAIProvider:
    """Instantiate a provider by name."""
    # Check custom providers first
    if name in _custom_providers:
        return _custom_providers[name]()

    # Built-in providers
    if name == "openai":
        from driln.ai.openai import OpenAIProvider

        return OpenAIProvider()

    available = ["openai"] + list(_custom_providers.keys())
    raise ConfigError(
        f"Unknown AI provider: '{name}'. Available: {', '.join(available)}"
    )


def get_ai_provider() -> BaseAIProvider:
    """Return the global AI provider instance, creating it if needed."""
    global _provider
    if _provider is None:
        # Load custom module before creating provider
        _load_custom_provider()

        settings = get_settings()
        _provider = _create_provider(settings.ai_provider)
        logger.info("ai_provider_initialized", provider=_provider.name, model=settings.ai_model)
    return _provider


def reset_provider() -> None:
    """Reset the cached provider (useful for testing or config reload)."""
    global _provider, _custom_loaded
    _provider = None
    _custom_loaded = False
