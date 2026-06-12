"""Workflow decision and action models.

These are pure data models — they describe *what* the workflow engine
wants to do, not *how* to do it.  The scanner consults the decisions
and either auto-executes (if ``--auto-expand`` is set) or presents
them to the user for approval.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class WorkflowAction(BaseModel):
    """A concrete action the workflow engine wants to take."""

    action_type: str = Field(
        ...,
        description="Action kind",
        pattern=r"^(add_tool|rerun_tool|notify|escalate)$",
    )
    tool_name: str | None = Field(None, description="Tool to add/rerun")
    tool_config: dict | None = Field(None, description="Tool-specific options")
    priority: str = Field(
        ..., pattern=r"^(critical|high|medium|low)$"
    )
    reason: str = Field(..., description="Human-readable justification")


class WorkflowDecision(BaseModel):
    """A decision made by the workflow engine after evaluating scan state."""

    rule_name: str = Field(..., description="Name of the rule that fired")
    matched: bool = Field(..., description="Whether the rule's condition was met")
    actions: list[WorkflowAction] = Field(default_factory=list)
    requires_approval: bool = Field(
        True, description="If True, user must approve before execution"
    )
