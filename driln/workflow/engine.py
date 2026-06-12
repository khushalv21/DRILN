"""Workflow engine — evaluates rules against scan state.

The engine is called after the intelligence service produces its report.
It evaluates all workflow rules and returns decisions.  It does **not**
auto-execute anything (unless ``--auto-expand`` is set) — it only
produces decisions for the scanner or CLI to act on.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from driln.schemas.intelligence import TechProfile
from driln.workflow.decisions import WorkflowAction, WorkflowDecision
from driln.workflow.rules import WORKFLOW_RULES

if TYPE_CHECKING:
    from driln.intelligence.context import ScanContext

logger = structlog.get_logger()


class WorkflowEngine:
    """Evaluate workflow rules against current scan state."""

    def evaluate(
        self,
        context: ScanContext,
        tech_profile: TechProfile,
    ) -> list[WorkflowDecision]:
        """Run all rules and return matching decisions."""
        decisions: list[WorkflowDecision] = []

        for rule in WORKFLOW_RULES:
            try:
                matched = rule.condition(context, tech_profile)
            except Exception as exc:
                logger.warning(
                    "workflow_rule_error",
                    rule=rule.name,
                    error=str(exc),
                )
                continue

            if matched:
                decision = WorkflowDecision(
                    rule_name=rule.name,
                    matched=True,
                    actions=rule.actions,
                    requires_approval=rule.requires_approval,
                )
                decisions.append(decision)
                logger.info(
                    "workflow_rule_matched",
                    rule=rule.name,
                    actions=len(rule.actions),
                    requires_approval=rule.requires_approval,
                )

        return decisions

    def get_auto_actions(
        self, decisions: list[WorkflowDecision]
    ) -> list[WorkflowAction]:
        """Return actions that don't require approval (safe to auto-execute)."""
        actions: list[WorkflowAction] = []
        for d in decisions:
            if not d.requires_approval:
                actions.extend(d.actions)
        return actions

    def get_pending_actions(
        self, decisions: list[WorkflowDecision]
    ) -> list[WorkflowAction]:
        """Return actions that require user approval."""
        actions: list[WorkflowAction] = []
        for d in decisions:
            if d.requires_approval:
                actions.extend(d.actions)
        return actions
