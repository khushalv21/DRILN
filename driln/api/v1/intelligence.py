"""Intelligence API endpoints.

Provides access to scan intelligence: technology profiles, risk scores,
correlation groups, and recommendations with accept/dismiss workflow.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from driln.api.deps import (
    get_finding_repo,
    get_recommendation_repo,
    get_scan_repo,
)
from driln.api.validators import validate_uuid
from driln.db.repos import FindingRepository, RecommendationRepository, ScanRepository
from driln.intelligence.context import ScanContext
from driln.intelligence.service import IntelligenceService
from driln.schemas.intelligence import RecommendationOut, ScanIntelligence

router = APIRouter()


@router.get("/{scan_id}/intelligence", response_model=ScanIntelligence)
async def get_intelligence(
    scan_id: str,
    scan_repo: ScanRepository = Depends(get_scan_repo),
    finding_repo: FindingRepository = Depends(get_finding_repo),
):
    """Run the full intelligence pipeline on a completed scan."""
    validate_uuid(scan_id, "scan_id")
    scan = await scan_repo.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Build context from stored data
    context = ScanContext(
        scan_id=scan_id,
        target=scan.target,
        scan_type=scan.scan_type,
    )

    # Load findings into context
    findings = await finding_repo.list_by_scan(scan_id)
    for f in findings:
        context.findings.append({
            "id": f.id,
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "title": f.title,
            "description": f.description or "",
            "host": f.host or "",
            "port": f.port,
            "protocol": f.protocol or "",
            "service": f.service or "",
        })

    # Run intelligence
    service = IntelligenceService()
    intelligence = await service.analyze(context)
    return intelligence


@router.get("/{scan_id}/recommendations", response_model=list[RecommendationOut])
async def list_recommendations(
    scan_id: str,
    scan_repo: ScanRepository = Depends(get_scan_repo),
    rec_repo: RecommendationRepository = Depends(get_recommendation_repo),
):
    """List all recommendations for a scan."""
    validate_uuid(scan_id, "scan_id")
    scan = await scan_repo.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    recs = await rec_repo.list_by_scan(scan_id)
    return [
        RecommendationOut(
            id=r.id,
            priority=r.priority,
            category=r.category,
            title=r.title,
            rationale=r.rationale,
            tool_name=r.tool_name,
            tool_config=r.tool_config,
            source=r.source,
            accepted=r.accepted,
            triggered_by=r.triggered_by,
        )
        for r in recs
    ]


@router.post("/{scan_id}/recommendations/{rec_id}/accept", response_model=dict)
async def accept_recommendation(
    scan_id: str,
    rec_id: str,
    rec_repo: RecommendationRepository = Depends(get_recommendation_repo),
):
    """Accept a recommendation."""
    validate_uuid(scan_id, "scan_id")
    validate_uuid(rec_id, "rec_id")
    # Verify the recommendation belongs to this scan
    recs = await rec_repo.list_by_scan(scan_id)
    if not any(r.id == rec_id for r in recs):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Recommendation not found for this scan")
    await rec_repo.accept(rec_id)
    return {"status": "accepted", "recommendation_id": rec_id}


@router.post("/{scan_id}/recommendations/{rec_id}/dismiss", response_model=dict)
async def dismiss_recommendation(
    scan_id: str,
    rec_id: str,
    rec_repo: RecommendationRepository = Depends(get_recommendation_repo),
):
    """Dismiss a recommendation."""
    validate_uuid(scan_id, "scan_id")
    validate_uuid(rec_id, "rec_id")
    # Verify the recommendation belongs to this scan
    recs = await rec_repo.list_by_scan(scan_id)
    if not any(r.id == rec_id for r in recs):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Recommendation not found for this scan")
    await rec_repo.dismiss(rec_id)
    return {"status": "dismissed", "recommendation_id": rec_id}
