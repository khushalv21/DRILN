"""Application-wide exception hierarchy.

Every custom exception inherits from :class:`DrilnError` so callers can
catch the base class when they want a blanket handler, or catch a specific
subclass for fine-grained control.
"""

from __future__ import annotations


class DrilnError(Exception):
    """Root exception for all Driln errors."""

    def __init__(self, message: str = "", *, detail: str | None = None) -> None:
        self.detail = detail or message
        super().__init__(message)


# ── Tool errors ─────────────────────────────────────────────────


class ToolError(DrilnError):
    """Base for tool execution failures."""


class ToolNotFoundError(ToolError):
    """Raised when a tool binary is not found in PATH."""


class ToolTimeoutError(ToolError):
    """Raised when a tool execution exceeds the configured timeout."""


class ToolExecutionError(ToolError):
    """Raised when a tool returns a non-zero exit code or crashes."""


# ── AI provider errors ──────────────────────────────────────────


class AIProviderError(DrilnError):
    """Base for AI provider failures."""


class AIConnectionError(AIProviderError):
    """Cannot reach the AI provider endpoint."""


class AIResponseError(AIProviderError):
    """AI provider returned an unexpected or malformed response."""


# ── Scan errors ─────────────────────────────────────────────────


class ScanError(DrilnError):
    """Errors during scan lifecycle management."""


# ── Config errors ───────────────────────────────────────────────


class ConfigError(DrilnError):
    """Invalid or missing configuration."""
