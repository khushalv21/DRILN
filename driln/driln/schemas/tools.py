"""Tool-related Pydantic schemas."""

from __future__ import annotations

from pydantic import BaseModel


class ToolInfo(BaseModel):
    """Public info about a registered tool."""

    name: str
    description: str
    binary: str
    installed: bool


class ToolCheckResult(BaseModel):
    """Result of checking a single tool's availability."""

    name: str
    installed: bool
    path: str | None = None
    error: str | None = None
