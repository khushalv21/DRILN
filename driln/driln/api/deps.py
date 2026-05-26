"""FastAPI dependency injection helpers."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

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
