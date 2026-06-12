"""Scan-related Pydantic schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    """Request body for creating a new scan."""

    target: str = Field(
        ...,
        min_length=1,
        max_length=512,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9.\-_:/]{0,510}[a-zA-Z0-9/]$",
        description="Target host or domain",
    )
    scan_type: str = Field(
        "full",
        pattern=r"^(recon|vuln|full)$",
        description="Pipeline type: recon, vuln, or full",
    )
    tools: list[str] | None = Field(
        None,
        description="Override default pipeline with specific tools",
    )
    allow_local: bool = Field(
        False,
        description="Allow scanning of internal/private IP addresses",
    )
    config: dict | None = Field(None, description="Additional per-tool options")

    @__import__("pydantic").field_validator("tools")
    @classmethod
    def validate_tools(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        allowed = {"nmap", "subfinder", "httpx", "nuclei"}
        for t in v:
            if t not in allowed:
                raise ValueError(f"Unknown tool: '{t}'. Allowed: {', '.join(sorted(allowed))}")
        return v

    @__import__("pydantic").field_validator("config")
    @classmethod
    def block_extra_args(cls, v: dict | None) -> dict | None:
        """Block extra_args in API config to prevent command injection."""
        if v is None:
            return v
        for tool_opts in v.values():
            if isinstance(tool_opts, dict) and "extra_args" in tool_opts:
                raise ValueError("extra_args is not allowed via the API")
        return v


class ScanStatus(BaseModel):
    """Scan status summary."""

    id: str
    target: str
    scan_type: str
    status: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


class ScanDetail(ScanStatus):
    """Full scan details including tool runs and findings."""

    config: dict | None = None
    tool_runs: list[ToolRunOut] = []
    findings: list[FindingOut] = []

    model_config = {"from_attributes": True}


class ToolRunOut(BaseModel):
    """Tool run output schema."""

    id: str
    tool_name: str
    status: str
    command: str | None = None
    exit_code: int | None = None
    duration_seconds: float | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    """Finding output schema."""

    id: str
    severity: str
    title: str
    description: str | None = None
    host: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    discovered_at: datetime

    model_config = {"from_attributes": True}


# Resolve forward references
ScanDetail.model_rebuild()
