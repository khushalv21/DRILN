"""Tests for markdown report template rendering.

Exercises the Jinja2 environment directly (rather than the full
`ReportGenerator.generate()`, which touches the module-level DB session
factory).
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from driln.reports.generator import ReportGenerator


def _base_context() -> dict:
    return {
        "scan_id": "11111111-1111-1111-1111-111111111111",
        "target": "example.com",
        "scan_type": "full",
        "status": "completed",
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "completed_at": datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
        "scan_duration": "5 minutes 0 seconds",
        "tool_runs": [
            {
                "tool_name": "nuclei",
                "status": "completed",
                "exit_code": 0,
                "duration_seconds": 12.3,
                "finding_count": 2,
            }
        ],
        "findings": [
            {
                "id": "f1",
                "severity": "critical",
                "title": "Unauthenticated RCE via Log4Shell",
                "description": "Unauthenticated RCE",
                "host": "example.com",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
            },
            {
                "id": "f2",
                "severity": "high",
                "title": "Outdated Apache version",
                "description": "Version disclosure",
                "host": "example.com",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
            },
        ],
        "severity_counts": {"critical": 1, "high": 1},
        "ai_summary": None,
        "generated_at": datetime(2026, 1, 1, 0, 6, tzinfo=UTC),
        "total_findings": 2,
        "intelligence": None,
        "tech_profile": SimpleNamespace(
            technologies=[SimpleNamespace(name="nginx", version="1.25", category="webserver", confidence=0.9)]
        ),
        "risk_summary": SimpleNamespace(
            score=87.5,
            label="critical",
            base_severity=1.0,
            exploitability=0.9,
            exposure=0.8,
            context_boost=0.1,
        ),
        "recommendations": [],
        "correlations": [],
        "diff": None,
    }


def _correlation_group():
    from driln.schemas.intelligence import CorrelationGroup

    return CorrelationGroup(
        group_id="g1",
        finding_ids=["f1", "f2"],
        relationship="attack_chain",
        summary="Service info + vulnerability on example.com:443",
        combined_risk=90.0,
    )


def _diff_with_changes():
    from driln.schemas.diff import ScanDiff
    from driln.schemas.findings import FindingOut

    return ScanDiff(
        scan_id="11111111-1111-1111-1111-111111111111",
        target="example.com",
        previous_scan_id="00000000-0000-0000-0000-000000000000",
        new_findings=[
            FindingOut(
                id="f3",
                scan_id="s2",
                severity="high",
                title="New exposed port",
                host="example.com",
                port=8080,
                discovered_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
        ],
        fixed_findings=[
            FindingOut(
                id="f4",
                scan_id="s1",
                severity="medium",
                title="Old outdated header",
                host="example.com",
                port=443,
                discovered_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
        ],
        persisted_findings=[],
    )


def _render(context: dict) -> str:
    env = ReportGenerator()._env
    return env.get_template("markdown.md.j2").render(**context)


def test_renders_title_and_metadata():
    content = _render(_base_context())
    assert "# 🛡️ Security Scan Report" in content
    assert "example.com" in content
    assert "11111111-1111-1111-1111-111111111111" in content


def test_renders_severity_pie_chart():
    content = _render(_base_context())
    assert "```mermaid" in content
    assert "pie showData title Findings by Severity" in content
    assert '"Critical" : 1' in content
    assert '"High" : 1' in content


def test_no_pie_chart_when_no_findings():
    context = _base_context()
    context["total_findings"] = 0
    context["findings"] = []
    context["severity_counts"] = {}
    content = _render(context)
    assert "pie showData" not in content


def test_renders_risk_gauge():
    content = _render(_base_context())
    assert "87/100" in content
    assert "█" in content
    assert "CRITICAL" in content


def test_renders_correlation_graph():
    context = _base_context()
    context["correlations"] = [_correlation_group()]
    content = _render(context)

    assert "Correlation Graph" in content
    assert "```mermaid" in content
    assert "graph LR" in content
    # Both correlated finding titles should show up as graph node labels.
    assert "Unauthenticated RCE via Log4Shell" in content
    assert "Outdated Apache version" in content
    assert "Attack Chain" in content


def test_no_correlation_section_when_empty():
    content = _render(_base_context())
    assert "Correlation Graph" not in content


def test_renders_diff_section():
    context = _base_context()
    context["diff"] = _diff_with_changes()
    content = _render(context)

    assert "Changes Since Last Scan" in content
    assert "New exposed port" in content
    assert "Old outdated header" in content


def test_no_diff_section_when_no_previous_scan():
    content = _render(_base_context())
    assert "Changes Since Last Scan" not in content


def test_table_of_contents_reflects_present_sections():
    context = _base_context()
    context["correlations"] = [_correlation_group()]
    context["diff"] = _diff_with_changes()
    content = _render(context)

    assert "[Risk Overview](#-risk-overview)" in content
    assert "[Changes Since Last Scan](#-changes-since-last-scan)" in content
    assert "[Findings Summary](#-findings-summary)" in content
    assert "[Correlation Graph](#-correlation-graph)" in content
    assert "[Technology Profile](#-technology-profile)" in content


def test_no_findings_message():
    context = _base_context()
    context["total_findings"] = 0
    context["findings"] = []
    context["severity_counts"] = {}
    content = _render(context)
    assert "found **no issues**" in content
