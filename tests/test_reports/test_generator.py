"""Tests for report template rendering.

Exercises the Jinja2 environment directly (rather than the full
`ReportGenerator.generate()`, which touches the module-level DB session
factory) to verify:
  * the markdown template still renders unescaped, as before
  * the new HTML template renders, is autoescaped (XSS-safe), and the
    `select_autoescape(enabled_extensions=("html.j2",))` config actually
    matches the ".html.j2" filename — this is the part most likely to
    silently regress if the template is ever renamed.
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
                "finding_count": 1,
            }
        ],
        "findings": [
            {
                "id": "f1",
                "severity": "critical",
                "title": "<script>alert(1)</script>",
                "description": "Unauthenticated RCE",
                "host": "example.com",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
            }
        ],
        "severity_counts": {"critical": 1},
        "ai_summary": None,
        "generated_at": datetime(2026, 1, 1, 0, 6, tzinfo=UTC),
        "total_findings": 1,
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


def _diff_with_changes():
    from driln.schemas.diff import ScanDiff
    from driln.schemas.findings import FindingOut

    return ScanDiff(
        scan_id="11111111-1111-1111-1111-111111111111",
        target="example.com",
        previous_scan_id="00000000-0000-0000-0000-000000000000",
        new_findings=[
            FindingOut(
                id="f2",
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
                id="f3",
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


def test_markdown_template_renders_unescaped():
    env = ReportGenerator()._env
    template = env.get_template("markdown.md.j2")
    content = template.render(**_base_context())

    assert "# Security Scan Report" in content
    # Markdown output must NOT be HTML-escaped.
    assert "<script>alert(1)</script>" in content
    assert "&lt;script&gt;" not in content


def test_html_template_renders_and_autoescapes():
    env = ReportGenerator()._env
    template = env.get_template("report.html.j2")
    content = template.render(**_base_context())

    assert "<!DOCTYPE html>" in content
    assert "example.com" in content
    # The finding title must be escaped — this is the actual XSS check.
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    # Risk score and severity badge should show up.
    assert "87" in content
    assert "CRITICAL" in content


def test_markdown_template_renders_diff_section():
    context = _base_context()
    context["diff"] = _diff_with_changes()
    env = ReportGenerator()._env
    content = env.get_template("markdown.md.j2").render(**context)

    assert "Changes Since Last Scan" in content
    assert "New exposed port" in content
    assert "Old outdated header" in content


def test_html_template_renders_diff_section():
    context = _base_context()
    context["diff"] = _diff_with_changes()
    env = ReportGenerator()._env
    content = env.get_template("report.html.j2").render(**context)

    assert "Changes Since Last Scan" in content
    assert "New exposed port" in content
    assert "Old outdated header" in content


def test_templates_render_without_diff_section_when_no_previous_scan():
    context = _base_context()
    context["diff"] = None
    env = ReportGenerator()._env

    md = env.get_template("markdown.md.j2").render(**context)
    html = env.get_template("report.html.j2").render(**context)

    assert "Changes Since Last Scan" not in md
    assert "Changes Since Last Scan" not in html
