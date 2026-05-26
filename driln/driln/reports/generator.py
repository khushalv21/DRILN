"""Report generator.

Aggregates scan data, optionally enriches with AI analysis, and renders
reports using Jinja2 templates.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader

from driln.ai.registry import get_ai_provider
from driln.core.config import get_settings
from driln.core.exceptions import ScanError
from driln.db.engine import _get_session_factory
from driln.db.repos import (
    FindingRepository,
    RecommendationRepository,
    ReportRepository,
    ScanRepository,
    ToolRunRepository,
)
from driln.intelligence.context import ScanContext
from driln.intelligence.service import IntelligenceService

logger = structlog.get_logger()

_TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Build and persist scan reports."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    async def generate(
        self,
        scan_id: str,
        format: str = "markdown",
        include_ai_summary: bool = True,
    ) -> dict[str, Any]:
        """Generate a report for a completed scan.

        Args:
            scan_id: UUID of the scan.
            format: ``"markdown"`` or ``"html"``.
            include_ai_summary: Whether to call the AI provider for analysis.

        Returns:
            Dict with ``report_id``, ``filepath``, ``content``, ``ai_summary``.
        """
        settings = get_settings()
        factory = _get_session_factory()

        async with factory() as session:
            scan_repo = ScanRepository(session)
            run_repo = ToolRunRepository(session)
            finding_repo = FindingRepository(session)
            report_repo = ReportRepository(session)

            # Load scan data
            scan = await scan_repo.get(scan_id)
            if scan is None:
                raise ScanError(f"Scan {scan_id} not found")

            tool_runs = await run_repo.list_by_scan(scan_id)
            findings = await finding_repo.list_by_scan(scan_id)

            # Build context
            findings_dicts = [
                {
                    "id": f.id,
                    "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                    "title": f.title,
                    "description": f.description or "",
                    "host": f.host or "",
                    "port": f.port,
                    "protocol": f.protocol or "",
                    "service": f.service or "",
                }
                for f in findings
            ]

            tool_run_dicts = [
                {
                    "tool_name": tr.tool_name,
                    "status": tr.status.value if hasattr(tr.status, "value") else tr.status,
                    "exit_code": tr.exit_code,
                    "duration_seconds": tr.duration_seconds,
                    "finding_count": len([
                        f for f in findings if f.tool_run_id == tr.id
                    ]),
                }
                for tr in tool_runs
            ]

            # Severity counts
            severity_counts: dict[str, int] = {}
            for f in findings_dicts:
                sev = f["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Intelligence analysis
            intelligence = None
            try:
                context = ScanContext(
                    scan_id=scan_id,
                    target=scan.target,
                    scan_type=scan.scan_type,
                )
                for f in findings_dicts:
                    context.findings.append(f)
                intel_service = IntelligenceService()
                intelligence = await intel_service.analyze(context)
            except Exception as exc:
                logger.warning("report_intelligence_failed", error=str(exc))

            # AI summary
            ai_summary = None
            if include_ai_summary:
                try:
                    provider = get_ai_provider()
                    ai_summary = await provider.analyze_scan({
                        "target": scan.target,
                        "scan_type": scan.scan_type,
                        "tool_results": [
                            {
                                "tool_name": tr.tool_name,
                                "success": tr.status.value == "completed"
                                if hasattr(tr.status, "value")
                                else tr.status == "completed",
                                "exit_code": tr.exit_code,
                                "finding_count": len([
                                    f for f in findings if f.tool_run_id == tr.id
                                ]),
                                "duration": tr.duration_seconds or 0,
                            }
                            for tr in tool_runs
                        ],
                        "findings": findings_dicts,
                    })
                except Exception as exc:
                    logger.warning("ai_summary_failed", error=str(exc))
                    ai_summary = f"_AI analysis unavailable: {exc}_"

            # Render template
            template_name = f"{'markdown' if format == 'markdown' else 'html'}.{'md' if format == 'markdown' else 'html'}.j2"
            template = self._env.get_template(template_name)

            content = template.render(
                scan_id=scan.id,
                target=scan.target,
                scan_type=scan.scan_type,
                status=scan.status.value if hasattr(scan.status, "value") else scan.status,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                tool_runs=tool_run_dicts,
                findings=findings_dicts,
                severity_counts=severity_counts,
                ai_summary=ai_summary,
                generated_at=datetime.now(timezone.utc),
                total_findings=len(findings_dicts),
                # Intelligence data (Phase 2)
                intelligence=intelligence,
                tech_profile=intelligence.tech_profile if intelligence else None,
                risk_summary=intelligence.risk_summary if intelligence else None,
                recommendations=[
                    {"priority": r.priority, "title": r.title, "rationale": r.rationale,
                     "tool_name": r.tool_name, "category": r.category}
                    for r in intelligence.recommendations
                ] if intelligence else [],
                correlations=intelligence.correlation_groups if intelligence else [],
            )

            # Write to disk
            output_dir = settings.scan_output_dir / scan_id
            output_dir.mkdir(parents=True, exist_ok=True)
            ext = "md" if format == "markdown" else "html"
            filepath = output_dir / f"report.{ext}"
            filepath.write_text(content, encoding="utf-8")

            # Persist report record
            report = await report_repo.create(
                scan_id=scan_id,
                format=format,
                filepath=str(filepath),
                ai_summary=ai_summary,
            )
            await session.commit()

            logger.info("report_generated", scan_id=scan_id, format=format, path=str(filepath))

            return {
                "report_id": report.id,
                "filepath": str(filepath),
                "content": content,
                "ai_summary": ai_summary,
            }
