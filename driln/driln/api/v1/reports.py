"""Report endpoints — generate and retrieve scan reports."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from driln.api.deps import get_report_generator
from driln.api.validators import validate_uuid
from driln.reports.generator import ReportGenerator
from driln.schemas.reports import ReportRequest

router = APIRouter()


@router.post("/{scan_id}", response_model=dict)
async def generate_report(
    scan_id: str,
    body: ReportRequest = ReportRequest(),
    generator: ReportGenerator = Depends(get_report_generator),
):
    """Generate a report for a completed scan."""
    validate_uuid(scan_id, "scan_id")
    try:
        result = await generator.generate(
            scan_id=scan_id,
            format=body.format,
            include_ai_summary=body.include_ai_summary,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to generate report. Ensure the scan exists and is completed.")

    return {
        "report_id": result["report_id"],
        "format": body.format,
        "has_ai_summary": result["ai_summary"] is not None,
    }
