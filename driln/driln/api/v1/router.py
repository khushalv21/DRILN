"""V1 aggregate router — mounts all v1 sub-routers."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from driln.api.deps import verify_api_key
from driln.api.v1.intelligence import router as intelligence_router
from driln.api.v1.reports import router as reports_router
from driln.api.v1.scans import router as scans_router
from driln.api.v1.tools import router as tools_router

router = APIRouter(dependencies=[Depends(verify_api_key)])

router.include_router(scans_router, prefix="/scans", tags=["scans"])
router.include_router(tools_router, prefix="/tools", tags=["tools"])
router.include_router(reports_router, prefix="/reports", tags=["reports"])
router.include_router(intelligence_router, prefix="/scans", tags=["intelligence"])
