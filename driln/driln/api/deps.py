"""FastAPI dependency injection helpers."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from driln.core.config import get_settings
from driln.db.engine import get_session
from driln.db.repos import (
    FindingRepository,
    RecommendationRepository,
    ReportRepository,
    ScanRepository,
    ToolRunRepository,
)
from driln.engine.scanner import ScanEngine
from driln.reports.generator import ReportGenerator
from driln.tools.registry import ToolRegistry, get_registry

_scan_semaphore: asyncio.Semaphore | None = None


def get_scan_semaphore() -> asyncio.Semaphore:
    """Return a global semaphore bounded by scan_max_concurrent."""
    global _scan_semaphore
    if _scan_semaphore is None:
        settings = get_settings()
        _scan_semaphore = asyncio.Semaphore(settings.scan_max_concurrent)
    return _scan_semaphore


_security = HTTPBearer(auto_error=False)


def verify_api_key(credentials: HTTPAuthorizationCredentials | None = Security(_security)):
    """Enforce API key authentication."""
    settings = get_settings()
    if settings.api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Server is not configured with an API Key. Set DRILN_API_KEY.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not credentials or credentials.credentials != settings.api_key.get_secret_value():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


async def get_db(session: AsyncSession = Depends(get_session)) -> AsyncGenerator[AsyncSession, None]:
    """Alias for session dependency."""
    yield session


def get_tool_registry() -> ToolRegistry:
    """Return the global tool registry."""
    return get_registry()


def get_scan_engine() -> ScanEngine:
    """Return a scan engine instance."""
    return ScanEngine()


def get_report_generator() -> ReportGenerator:
    """Return a report generator instance."""
    return ReportGenerator()


def get_scan_repo(session: AsyncSession = Depends(get_session)) -> ScanRepository:
    return ScanRepository(session)


def get_run_repo(session: AsyncSession = Depends(get_session)) -> ToolRunRepository:
    return ToolRunRepository(session)


def get_finding_repo(session: AsyncSession = Depends(get_session)) -> FindingRepository:
    return FindingRepository(session)


def get_report_repo(session: AsyncSession = Depends(get_session)) -> ReportRepository:
    return ReportRepository(session)


def get_recommendation_repo(session: AsyncSession = Depends(get_session)) -> RecommendationRepository:
    return RecommendationRepository(session)
