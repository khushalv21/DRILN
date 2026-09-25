"""Scan-to-scan diff schema."""

from __future__ import annotations

from pydantic import BaseModel, Field

from driln.schemas.findings import FindingOut


class ScanDiff(BaseModel):
    """Comparison between a scan and the most recent prior completed scan
    of the same target."""

    scan_id: str
    target: str
    previous_scan_id: str | None = Field(
        None, description="The scan this one was compared against, or null if there was none"
    )
    new_findings: list[FindingOut] = Field(default_factory=list)
    fixed_findings: list[FindingOut] = Field(default_factory=list)
    persisted_findings: list[FindingOut] = Field(default_factory=list)

    model_config = {"from_attributes": True}
