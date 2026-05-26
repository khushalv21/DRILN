"""Scan endpoints — create, list, get, cancel."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from driln.api.deps import get_scan_engine, get_scan_repo
from driln.db.repos import ScanRepository
from driln.engine.scanner import ScanEngine
from driln.schemas.scans import ScanCreate, ScanDetail, ScanStatus

router = APIRouter()


@router.post("", response_model=dict, status_code=201)
async def create_scan(
    body: ScanCreate,
    background_tasks: BackgroundTasks,
    engine: ScanEngine = Depends(get_scan_engine),
):
    """Create a new scan and start execution in the background."""
    scan_id = await engine.create_scan(
        target=body.target,
        scan_type=body.scan_type,
        tools=body.tools,
        config=body.config,
    )

    # Launch scan execution as a background task
    background_tasks.add_task(engine.run_scan, scan_id)

    return {"scan_id": scan_id, "status": "pending", "message": "Scan created and queued"}


@router.get("", response_model=list[ScanStatus])
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    repo: ScanRepository = Depends(get_scan_repo),
):
    """List all scans with pagination."""
    scans = await repo.list_all(limit=limit, offset=offset)
    return [
        ScanStatus(
            id=s.id,
            target=s.target,
            scan_type=s.scan_type,
            status=s.status.value if hasattr(s.status, "value") else s.status,
            created_at=s.created_at,
            started_at=s.started_at,
            completed_at=s.completed_at,
        )
        for s in scans
    ]


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repo),
):
    """Get full scan details including tool runs and findings."""
    scan = await repo.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/cancel", response_model=dict)
async def cancel_scan(
    scan_id: str,
    engine: ScanEngine = Depends(get_scan_engine),
):
    """Cancel a running scan."""
    await engine.cancel_scan(scan_id)
    return {"scan_id": scan_id, "status": "cancelled"}
