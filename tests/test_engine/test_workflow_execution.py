"""Tests for workflow-triggered scan expansion.

These cover the fix for the workflow engine being wired up but never
actually executed: `ScanEngine._execute_workflow_action` must run the
requested tool and persist its findings, and `WorkflowEngine` must
correctly split matched decisions into auto vs. pending actions so the
scanner knows what to execute immediately vs. surface for approval.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from driln.core.config import get_settings
from driln.db.repos import FindingRepository, ScanRepository, ToolRunRepository
from driln.engine.scanner import ScanEngine
from driln.intelligence.context import ScanContext
from driln.tools.base import BaseTool, ToolResult
from driln.tools.registry import ToolRegistry
from driln.workflow.decisions import WorkflowAction, WorkflowDecision
from driln.workflow.engine import WorkflowEngine


class _FakeNucleiTool(BaseTool):
    """A stand-in tool that never touches a real subprocess."""

    name = "nuclei"
    description = "fake"
    binary = "nuclei"

    def build_command(self, target: str, options: dict) -> list[str]:
        return ["nuclei", "-u", target]

    def parse_output(self, raw_output: str, exit_code: int) -> ToolResult:
        raise NotImplementedError

    async def check_installed(self) -> tuple[bool, str | None]:
        return True, "/usr/bin/nuclei"

    async def run(self, target: str, options=None, timeout: int = 300) -> ToolResult:
        return ToolResult(
            tool_name="nuclei",
            command="nuclei -u " + target,
            raw_output="{}",
            parsed_data={"severity_counts": {"critical": 1}},
            findings=[
                {
                    "severity": "critical",
                    "title": "Exposed Redis instance",
                    "host": target,
                    "port": 6379,
                    "service": "redis",
                }
            ],
            exit_code=0,
            duration=1.2,
            success=True,
        )


@pytest.mark.asyncio
async def test_execute_workflow_action_persists_findings(db_session):
    scan_repo = ScanRepository(db_session)
    run_repo = ToolRunRepository(db_session)
    finding_repo = FindingRepository(db_session)

    scan = await scan_repo.create(target="example.com", scan_type="full")
    await db_session.flush()

    registry = ToolRegistry()
    registry.register(_FakeNucleiTool())

    scan_context = ScanContext(scan_id=scan.id, target="example.com", scan_type="full")

    action = WorkflowAction(
        action_type="add_tool",
        tool_name="nuclei",
        tool_config={"tags": ["database"]},
        priority="critical",
        reason="Exposed database port detected",
    )

    engine = ScanEngine()
    produced_findings = await engine._execute_workflow_action(
        action,
        scan_id=scan.id,
        target="example.com",
        registry=registry,
        settings=get_settings(),
        run_repo=run_repo,
        finding_repo=finding_repo,
        scan_context=scan_context,
        all_results=[],
        all_findings=[],
        output_dir=Path("/tmp"),
    )
    await db_session.commit()

    assert produced_findings is True

    runs = await run_repo.list_by_scan(scan.id)
    assert len(runs) == 1
    assert runs[0].tool_name == "nuclei"
    assert runs[0].status.value == "completed"

    findings = await finding_repo.list_by_scan(scan.id)
    assert len(findings) == 1
    assert findings[0].title == "Exposed Redis instance"
    assert findings[0].severity.value == "critical"

    # The scan context used for re-analysis should also see the new finding.
    assert scan_context.finding_count == 1


@pytest.mark.asyncio
async def test_execute_workflow_action_skips_uninstalled_tool(db_session):
    run_repo = ToolRunRepository(db_session)
    finding_repo = FindingRepository(db_session)
    registry = ToolRegistry()  # nothing registered → tool lookup fails

    scan_context = ScanContext(scan_id="s1", target="example.com", scan_type="full")
    action = WorkflowAction(
        action_type="add_tool",
        tool_name="nuclei",
        tool_config={},
        priority="high",
        reason="test",
    )

    engine = ScanEngine()
    produced_findings = await engine._execute_workflow_action(
        action,
        scan_id="s1",
        target="example.com",
        registry=registry,
        settings=get_settings(),
        run_repo=run_repo,
        finding_repo=finding_repo,
        scan_context=scan_context,
        all_results=[],
        all_findings=[],
        output_dir=Path("/tmp"),
    )

    assert produced_findings is False
    assert scan_context.finding_count == 0


def test_workflow_engine_splits_auto_and_pending_actions():
    """Sanity check the split the scanner relies on: auto vs. pending."""
    auto_action = WorkflowAction(
        action_type="add_tool",
        tool_name="nuclei",
        tool_config={"tags": ["database"]},
        priority="critical",
        reason="auto",
    )
    pending_action = WorkflowAction(
        action_type="add_tool",
        tool_name="nuclei",
        tool_config={"tags": ["wordpress"]},
        priority="high",
        reason="pending",
    )
    decisions = [
        WorkflowDecision(rule_name="r1", matched=True, actions=[auto_action], requires_approval=False),
        WorkflowDecision(rule_name="r2", matched=True, actions=[pending_action], requires_approval=True),
    ]

    engine = WorkflowEngine()
    assert engine.get_auto_actions(decisions) == [auto_action]
    assert engine.get_pending_actions(decisions) == [pending_action]
