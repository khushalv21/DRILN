"""Report-related Pydantic schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ReportRequest(BaseModel):
    """Request body for generating a report."""

    format: str = Field("markdown", pattern=r"^(markdown|html)$")
    include_ai_summary: bool = True


class ReportOut(BaseModel):
    """Report output schema."""

    id: str
    scan_id: str
    format: str
    filepath: str | None = None
    ai_summary: str | None = None
    generated_at: datetime

    model_config = {"from_attributes": True}
