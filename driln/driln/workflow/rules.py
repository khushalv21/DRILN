"""Workflow rules — conditional scan expansion.

Each rule evaluates the current scan context and tech profile.  If the
condition matches, it produces one or more :class:`WorkflowAction` items
that the scanner can execute (with user approval).

Rules are separated from recommendations: recommendations *suggest*
future manual actions; workflow rules *trigger* automated scan expansion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from driln.schemas.intelligence import TechProfile
from driln.workflow.decisions import WorkflowAction

if TYPE_CHECKING:
    from driln.intelligence.context import ScanContext


@dataclass
class WorkflowRule:
    """A conditional scan expansion rule."""

    name: str
    description: str
    condition: Callable[[ScanContext, TechProfile], bool]
    actions: list[WorkflowAction]
    requires_approval: bool = True


def _has_tech(tp: TechProfile, name: str) -> bool:
    return any(t.name.lower() == name.lower() for t in tp.technologies)


def _has_service(ctx: ScanContext, *names: str) -> bool:
    targets = {n.lower() for n in names}
    return any(s.service.lower() in targets for s in ctx.get_all_services())


def _has_finding_kw(ctx: ScanContext, *kws: str) -> bool:
    for f in ctx.findings:
        title = f.get("title", "").lower()
        if any(k.lower() in title for k in kws):
            return True
    return False


def _open_port(ctx: ScanContext, port: int) -> bool:
    return any(port in h.ports for h in ctx.hosts.values())


# ── Rule definitions ────────────────────────────────────────────

WORKFLOW_RULES: list[WorkflowRule] = [
    WorkflowRule(
        name="wordpress_expand",
        description="WordPress detected — expand scan with auth templates",
        condition=lambda ctx, tp: _has_tech(tp, "WordPress"),
        actions=[
            WorkflowAction(
                action_type="add_tool",
                tool_name="nuclei",
                tool_config={
                    "tags": ["wordpress", "wp-plugin", "wp-theme"],
                    "severity": "medium,high,critical",
                },
                priority="high",
                reason="WordPress CMS detected — run WP-specific nuclei templates for deeper coverage",
            ),
        ],
        requires_approval=True,
    ),
    WorkflowRule(
        name="admin_panel_brute",
        description="Admin panel found — run default credential checks",
        condition=lambda ctx, tp: _has_finding_kw(
            ctx, "admin", "login", "wp-login", "administrator", "sign-in"
        ),
        actions=[
            WorkflowAction(
                action_type="add_tool",
                tool_name="nuclei",
                tool_config={
                    "tags": ["default-login"],
                    "severity": "medium,high,critical",
                },
                priority="high",
                reason="Admin/login panel detected — check for default and weak credentials",
            ),
        ],
        requires_approval=True,
    ),
    WorkflowRule(
        name="exposed_database_deep",
        description="Database port open — run targeted nuclei templates",
        condition=lambda ctx, tp: (
            _open_port(ctx, 3306) or _open_port(ctx, 5432)
            or _open_port(ctx, 27017) or _open_port(ctx, 6379)
        ),
        actions=[
            WorkflowAction(
                action_type="add_tool",
                tool_name="nuclei",
                tool_config={
                    "tags": ["database", "mysql", "postgres", "mongodb", "redis"],
                },
                priority="critical",
                reason="Exposed database port detected — run database-specific vulnerability checks",
            ),
        ],
        requires_approval=False,  # Critical enough to auto-run
    ),
    WorkflowRule(
        name="many_subdomains_expand",
        description="Large subdomain count — expand with port scanning",
        condition=lambda ctx, tp: len(ctx.hosts) > 20,
        actions=[
            WorkflowAction(
                action_type="notify",
                priority="medium",
                reason=(
                    f"Large attack surface detected — consider running targeted "
                    f"nmap against the top hosts for deeper port analysis"
                ),
            ),
        ],
        requires_approval=True,
    ),
    WorkflowRule(
        name="jenkins_unauthenticated",
        description="Jenkins detected — run Jenkins-specific templates",
        condition=lambda ctx, tp: _has_tech(tp, "Jenkins"),
        actions=[
            WorkflowAction(
                action_type="add_tool",
                tool_name="nuclei",
                tool_config={"tags": ["jenkins"]},
                priority="high",
                reason="Jenkins detected — check for script console access and known CVEs",
            ),
        ],
        requires_approval=True,
    ),
    WorkflowRule(
        name="git_exposed_dump",
        description="Exposed .git — attempt repository dump",
        condition=lambda ctx, tp: _has_finding_kw(ctx, ".git", "git config"),
        actions=[
            WorkflowAction(
                action_type="notify",
                priority="critical",
                reason="Exposed .git repository detected — source code and secrets may be extractable",
            ),
        ],
        requires_approval=True,
    ),
]
