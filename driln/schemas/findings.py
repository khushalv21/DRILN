"""Finding-related Pydantic schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class FindingCreate(BaseModel):
    """Schema for creating a finding programmatically."""

    scan_id: str
    tool_run_id: str | None = None
    severity: str = "info"
    title: str
    description: str | None = None
    host: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    metadata_: dict | None = None


class FindingOut(BaseModel):
    """Finding output schema."""

    id: str
    scan_id: str
    tool_run_id: str | None = None
    severity: str
    title: str
    description: str | None = None
    host: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    discovered_at: datetime

    model_config = {"from_attributes": True}
