"""Scan lifecycle manager.

The :class:`ScanEngine` orchestrates the full scan lifecycle:

1. Create a scan record (``pending``).
2. Resolve the tool pipeline.
3. Execute each tool sequentially, persisting results.
4. Run intelligence analysis (correlation, dedup, risk scoring).
5. Evaluate workflow rules for scan expansion.
6. Optionally run AI analysis.
7. Mark scan as ``completed`` or ``failed``.

All execution happens asynchronously.  The engine is designed to be called
from both the API (as a background task) and the CLI.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from driln.core.config import get_settings
from driln.core.exceptions import ScanError, ToolError
from driln.db.engine import _get_session_factory
from driln.db.models import ScanStatus
from driln.db.repos import (
    FindingRepository,
    RecommendationRepository,
    ScanRepository,
    ToolRunRepository,
)
from driln.engine.pipeline import get_pipeline
from driln.intelligence.context import ScanContext
from driln.intelligence.service import IntelligenceService
from driln.tools.base import ToolResult
from driln.tools.registry import get_registry
from driln.workflow.engine import WorkflowEngine

logger = structlog.get_logger()


class ScanEngine:
    """Manages scan creation, execution, and completion."""

    async def create_scan(
        self,
        target: str,
        scan_type: str = "full",
        tools: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> str:
        """Create a new scan record and return its ID.

        Args:
            target: Target host, domain, or IP.
            scan_type: Pipeline type (``recon``, ``vuln``, ``full``).
            tools: Optional explicit tool list (overrides pipeline).
            config: Per-tool options dict.

        Returns:
            The scan UUID.
        """
        factory = _get_session_factory()
        async with factory() as session:
            repo = ScanRepository(session)
            scan = await repo.create(
                target=target,
                scan_type=scan_type,
                config={
                    "tools": tools,
                    **(config or {}),
                },
            )
            await session.commit()
            logger.info("scan_created", scan_id=scan.id, target=target, scan_type=scan_type)
            return scan.id

    async def run_scan(self, scan_id: str) -> None:
        """Execute a scan by running all tools in the pipeline.

        This is the main entry point for scan execution.  It should be
        called as a background task (FastAPI ``BackgroundTasks``) or
        directly from the CLI.
        """
        settings = get_settings()
        registry = get_registry()
        factory = _get_session_factory()

        async with factory() as session:
            scan_repo = ScanRepository(session)
            run_repo = ToolRunRepository(session)
            finding_repo = FindingRepository(session)

            # Load scan
            scan = await scan_repo.get(scan_id)
            if scan is None:
                raise ScanError(f"Scan {scan_id} not found")

            # Resolve tool pipeline
            scan_config = scan.config or {}
            explicit_tools = scan_config.get("tools")
            if explicit_tools:
                tool_names = explicit_tools
            else:
                tool_names = get_pipeline(scan.scan_type)

            # Mark as running
            await scan_repo.update_status(
                scan_id,
                ScanStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
            )
            await session.commit()

            logger.info("scan_started", scan_id=scan_id, tools=tool_names)

            all_results: list[ToolResult] = []
            all_findings: list[dict[str, Any]] = []
            failed = False

            # Build scan context for intelligence layer
            scan_context = ScanContext(
                scan_id=scan_id,
                target=scan.target,
                scan_type=scan.scan_type,
            )

            # Create temp dir for inter-tool data passing
            output_dir = settings.scan_output_dir / scan_id
            output_dir.mkdir(parents=True, exist_ok=True)

            for tool_name in tool_names:
                try:
                    tool = registry.get(tool_name)
                except Exception as exc:
                    logger.warning("tool_skip", tool=tool_name, reason=str(exc))
                    continue

                # Check installation
                installed, _ = await tool.check_installed()
                if not installed:
                    logger.warning("tool_not_installed", tool=tool_name)
                    continue

                # Build per-tool options
                tool_options = scan_config.get(tool_name, {})

                # Chain: if previous tool produced subdomains, feed them to httpx/nuclei
                tool_options = self._chain_outputs(
                    tool_name, tool_options, all_results, output_dir
                )

                # Create tool run record
                cmd_preview = " ".join(tool.build_command(scan.target, tool_options))
                run = await run_repo.create(scan_id, tool_name, cmd_preview)
                await session.commit()

                # Execute
                try:
                    result = await tool.run(
                        scan.target,
                        options=tool_options,
                        timeout=settings.scan_timeout,
                    )
                    all_results.append(result)

                    # Update scan context incrementally
                    scan_context.add_tool_result(result)

                    # Persist tool run result
                    await run_repo.complete(
                        run.id,
                        raw_output=result.raw_output[:50000],  # Cap at 50KB
                        parsed_output=result.parsed_data,
                        exit_code=result.exit_code,
                        duration_seconds=result.duration,
                        status=ScanStatus.COMPLETED if result.success else ScanStatus.FAILED,
                    )

                    # Persist findings
                    if result.findings:
                        finding_dicts = [
                            {
                                "scan_id": scan_id,
                                "tool_run_id": run.id,
                                **f,
                            }
                            for f in result.findings
                        ]
                        await finding_repo.bulk_create(finding_dicts)
                        all_findings.extend(result.findings)

                    await session.commit()

                except ToolError as exc:
                    logger.error("tool_failed", tool=tool_name, error=str(exc))
                    await run_repo.complete(
                        run.id,
                        raw_output=str(exc),
                        parsed_output=None,
                        exit_code=-1,
                        duration_seconds=0.0,
                        status=ScanStatus.FAILED,
                    )
                    await session.commit()
                    # Continue with other tools — don't abort the whole scan
                    continue

                except Exception as exc:
                    logger.exception("tool_unexpected_error", tool=tool_name)
                    failed = True
                    break

            # ── Intelligence pipeline ───────────────────────────
            intelligence = None
            try:
                intel_service = IntelligenceService()
                intelligence = await intel_service.analyze(scan_context)

                # Persist recommendations
                rec_repo = RecommendationRepository(session)
                for rec in intelligence.recommendations:
                    await rec_repo.create(
                        scan_id=scan_id,
                        priority=rec.priority,
                        category=rec.category,
                        title=rec.title,
                        rationale=rec.rationale,
                        source=rec.source,
                        tool_name=rec.tool_name,
                        tool_config=rec.tool_config,
                    )

                # Update finding risk scores in DB
                for fid, score in intelligence.finding_risk_scores.items():
                    await finding_repo.update_risk_score(fid, score)

                await session.commit()

                logger.info(
                    "intelligence_complete",
                    scan_id=scan_id,
                    risk_score=intelligence.risk_summary.score,
                    risk_label=intelligence.risk_summary.label,
                    recommendations=len(intelligence.recommendations),
                    correlations=len(intelligence.correlation_groups),
                    deduplicated=intelligence.deduplicated_count,
                )
            except Exception as exc:
                logger.warning("intelligence_failed", scan_id=scan_id, error=str(exc))

            # ── Workflow evaluation ─────────────────────────────
            try:
                workflow = WorkflowEngine()
                if intelligence:
                    decisions = workflow.evaluate(
                        scan_context, intelligence.tech_profile
                    )
                    if decisions:
                        logger.info(
                            "workflow_decisions",
                            scan_id=scan_id,
                            count=len(decisions),
                            rules=[d.rule_name for d in decisions],
                        )
            except Exception as exc:
                logger.warning("workflow_failed", scan_id=scan_id, error=str(exc))

            # Mark scan as completed or failed
            final_status = ScanStatus.FAILED if failed else ScanStatus.COMPLETED
            await scan_repo.update_status(
                scan_id,
                final_status,
                completed_at=datetime.now(timezone.utc),
            )
            await session.commit()

            logger.info(
                "scan_completed",
                scan_id=scan_id,
                status=final_status.value,
                total_findings=len(all_findings),
                tools_run=len(all_results),
            )

    def _chain_outputs(
        self,
        tool_name: str,
        options: dict[str, Any],
        previous_results: list[ToolResult],
        output_dir: Path,
    ) -> dict[str, Any]:
        """Inject outputs from previous tools into the current tool's options.

        For example, subfinder subdomains → httpx input list,
        or httpx live hosts → nuclei input list.
        """
        opts = dict(options)  # Don't mutate original

        if tool_name == "httpx" and not opts.get("input_list"):
            # Look for subfinder results
            for res in previous_results:
                if res.tool_name == "subfinder" and res.parsed_data.get("subdomains"):
                    subs = res.parsed_data["subdomains"]
                    list_file = output_dir / "subfinder_subdomains.txt"
                    list_file.write_text("\n".join(subs))
                    opts["input_list"] = str(list_file)
                    logger.debug("chain_output", from_="subfinder", to="httpx", count=len(subs))
                    break

        elif tool_name == "nuclei" and not opts.get("input_list"):
            # Look for httpx results (live hosts)
            for res in previous_results:
                if res.tool_name == "httpx" and res.parsed_data.get("hosts"):
                    urls = [h["url"] for h in res.parsed_data["hosts"] if h.get("url")]
                    if urls:
                        list_file = output_dir / "httpx_live_hosts.txt"
                        list_file.write_text("\n".join(urls))
                        opts["input_list"] = str(list_file)
                        logger.debug("chain_output", from_="httpx", to="nuclei", count=len(urls))
                    break

        return opts

    async def cancel_scan(self, scan_id: str) -> None:
        """Mark a scan as cancelled."""
        factory = _get_session_factory()
        async with factory() as session:
            repo = ScanRepository(session)
            await repo.update_status(
                scan_id,
                ScanStatus.CANCELLED,
                completed_at=datetime.now(timezone.utc),
            )
            await session.commit()
            logger.info("scan_cancelled", scan_id=scan_id)
