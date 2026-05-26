"""Thin repository layer over SQLAlchemy models.

Each repository provides async CRUD methods and encapsulates query logic so
that business-layer code never imports ``sqlalchemy`` directly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from driln.db.models import Finding, Recommendation, Report, Scan, ScanStatus, Severity, ToolRun


# ── Scan Repository ─────────────────────────────────────────────


class ScanRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def create(
        self,
        target: str,
        scan_type: str,
        config: dict | None = None,
    ) -> Scan:
        scan = Scan(target=target, scan_type=scan_type, config=config)
        self._s.add(scan)
        await self._s.flush()
        return scan

    async def get(self, scan_id: str) -> Scan | None:
        return await self._s.get(Scan, scan_id)

    async def list_all(self, limit: int = 50, offset: int = 0) -> Sequence[Scan]:
        stmt = (
            select(Scan)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._s.execute(stmt)
        return result.scalars().all()

    async def update_status(
        self,
        scan_id: str,
        status: ScanStatus,
        *,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> None:
        scan = await self.get(scan_id)
        if scan is None:
            return
        scan.status = status
        if started_at:
            scan.started_at = started_at
        if completed_at:
            scan.completed_at = completed_at
        await self._s.flush()


# ── ToolRun Repository ──────────────────────────────────────────


class ToolRunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def create(self, scan_id: str, tool_name: str, command: str) -> ToolRun:
        run = ToolRun(
            scan_id=scan_id,
            tool_name=tool_name,
            command=command,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        self._s.add(run)
        await self._s.flush()
        return run

    async def complete(
        self,
        run_id: str,
        *,
        raw_output: str,
        parsed_output: dict | None,
        exit_code: int,
        duration_seconds: float,
        status: ScanStatus = ScanStatus.COMPLETED,
    ) -> None:
        run = await self._s.get(ToolRun, run_id)
        if run is None:
            return
        run.raw_output = raw_output
        run.parsed_output = parsed_output
        run.exit_code = exit_code
        run.duration_seconds = duration_seconds
        run.status = status
        run.completed_at = datetime.now(timezone.utc)
        await self._s.flush()

    async def list_by_scan(self, scan_id: str) -> Sequence[ToolRun]:
        stmt = select(ToolRun).where(ToolRun.scan_id == scan_id).order_by(ToolRun.started_at)
        result = await self._s.execute(stmt)
        return result.scalars().all()


# ── Finding Repository ──────────────────────────────────────────


class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def bulk_create(self, findings: list[dict]) -> list[Finding]:
        """Create multiple findings from dicts.  Each dict must include at
        least ``scan_id``, ``title``, and ``severity``."""
        objs = [Finding(**f) for f in findings]
        self._s.add_all(objs)
        await self._s.flush()
        return objs

    async def list_by_scan(
        self,
        scan_id: str,
        severity: Severity | None = None,
    ) -> Sequence[Finding]:
        stmt = select(Finding).where(Finding.scan_id == scan_id)
        if severity is not None:
            stmt = stmt.where(Finding.severity == severity)
        stmt = stmt.order_by(Finding.discovered_at)
        result = await self._s.execute(stmt)
        return result.scalars().all()

    async def update_risk_score(self, finding_id: str, score: float) -> None:
        """Set the composite risk score on a finding."""
        finding = await self._s.get(Finding, finding_id)
        if finding is not None:
            finding.risk_score = score
            await self._s.flush()

    async def update_correlation(
        self, finding_id: str, group_id: str
    ) -> None:
        """Assign a finding to a correlation group."""
        finding = await self._s.get(Finding, finding_id)
        if finding is not None:
            finding.correlation_group = group_id
            await self._s.flush()

    async def mark_deduplicated(
        self, finding_id: str, source_tools: list[str]
    ) -> None:
        """Mark a finding as deduplicated and record all source tools."""
        finding = await self._s.get(Finding, finding_id)
        if finding is not None:
            finding.deduplicated = True
            finding.source_tools = source_tools
            await self._s.flush()


# ── Report Repository ───────────────────────────────────────────


class ReportRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def create(
        self,
        scan_id: str,
        format: str,
        filepath: str | None = None,
        ai_summary: str | None = None,
    ) -> Report:
        report = Report(
            scan_id=scan_id,
            format=format,
            filepath=filepath,
            ai_summary=ai_summary,
        )
        self._s.add(report)
        await self._s.flush()
        return report

    async def get_by_scan(self, scan_id: str) -> Sequence[Report]:
        stmt = select(Report).where(Report.scan_id == scan_id).order_by(Report.generated_at.desc())
        result = await self._s.execute(stmt)
        return result.scalars().all()


# ── Recommendation Repository ───────────────────────────────────


class RecommendationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def create(
        self,
        scan_id: str,
        priority: str,
        category: str,
        title: str,
        rationale: str,
        source: str,
        tool_name: str | None = None,
        tool_config: dict | None = None,
        triggered_by: list[str] | None = None,
    ) -> Recommendation:
        rec = Recommendation(
            scan_id=scan_id,
            priority=priority,
            category=category,
            title=title,
            rationale=rationale,
            source=source,
            tool_name=tool_name,
            tool_config=tool_config,
            triggered_by=triggered_by,
        )
        self._s.add(rec)
        await self._s.flush()
        return rec

    async def list_by_scan(self, scan_id: str) -> Sequence[Recommendation]:
        stmt = (
            select(Recommendation)
            .where(Recommendation.scan_id == scan_id)
            .order_by(Recommendation.created_at)
        )
        result = await self._s.execute(stmt)
        return result.scalars().all()

    async def accept(self, rec_id: str) -> None:
        """Mark a recommendation as accepted."""
        rec = await self._s.get(Recommendation, rec_id)
        if rec is not None:
            rec.accepted = True
            await self._s.flush()

    async def dismiss(self, rec_id: str) -> None:
        """Mark a recommendation as dismissed."""
        rec = await self._s.get(Recommendation, rec_id)
        if rec is not None:
            rec.accepted = False
            await self._s.flush()
