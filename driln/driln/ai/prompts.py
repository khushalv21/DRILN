"""System prompts and template builders for AI-assisted analysis.

These prompts define the AI's role as a security analyst and provide
structured formats for scan data to maximize the quality of AI output.
"""

from __future__ import annotations

import json
from typing import Any

SYSTEM_PROMPT = """You are Driln AI, an expert cybersecurity analyst and penetration tester.

Your role is to analyze scan results from various security tools and provide:
1. A clear executive summary of the security posture
2. Prioritized risk assessment of all findings
3. Detailed analysis of critical and high-severity vulnerabilities
4. Actionable remediation recommendations
5. Attack surface observations and potential attack paths

Guidelines:
- Be precise and technical but accessible
- Prioritize findings by actual exploitability, not just CVSS scores
- Note relationships between findings (e.g., a service version + known CVE)
- Highlight quick wins and critical fixes separately
- Flag potential false positives when patterns suggest them
- Consider the target's likely architecture based on findings

Format your response in clear sections with markdown formatting."""


def build_analysis_prompt(scan_data: dict[str, Any]) -> str:
    """Build the user message for scan analysis.

    Args:
        scan_data: Dict containing target, tool_results, and findings.

    Returns:
        Formatted prompt string.
    """
    target = scan_data.get("target", "unknown")
    scan_type = scan_data.get("scan_type", "unknown")

    sections = [
        "## Scan Analysis Request\n",
        f"**Target:** {target}",
        f"**Scan Type:** {scan_type}",
        "",
    ]

    # Tool results summary
    tool_results = scan_data.get("tool_results", [])
    if tool_results:
        sections.append("### Tool Execution Summary\n")
        for tr in tool_results:
            status = "✅" if tr.get("success") else "❌"
            sections.append(
                f"- {status} **{tr.get('tool_name', '?')}** — "
                f"exit code {tr.get('exit_code', '?')}, "
                f"{tr.get('finding_count', 0)} findings, "
                f"{tr.get('duration', 0):.1f}s"
            )
        sections.append("")

    # Findings grouped by severity
    findings = scan_data.get("findings", [])
    if findings:
        sections.append(f"### Findings ({len(findings)} total)\n")

        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped: dict[str, list] = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            grouped.setdefault(sev, []).append(f)

        for sev in severity_order:
            items = grouped.get(sev, [])
            if not items:
                continue
            sections.append(f"#### {sev.upper()} ({len(items)})\n")
            for item in items[:20]:  # Cap at 20 per severity to avoid token explosion
                host = item.get("host", "")
                port = item.get("port", "")
                addr = f"{host}:{port}" if port else host
                sections.append(f"- **{item.get('title', 'Untitled')}** — {addr}")
                desc = item.get("description", "")
                if desc:
                    # Truncate long descriptions
                    if len(desc) > 300:
                        desc = desc[:297] + "..."
                    sections.append(f"  {desc}")
            if len(items) > 20:
                sections.append(f"  _(... {len(items) - 20} more {sev} findings omitted)_")
            sections.append("")

    # Raw data appendix (truncated)
    raw_data = scan_data.get("raw_parsed_data", {})
    if raw_data:
        raw_json = json.dumps(raw_data, indent=2, default=str)
        if len(raw_json) > 4000:
            raw_json = raw_json[:4000] + "\n... (truncated)"
        sections.append("### Raw Parsed Data (Appendix)\n")
        sections.append(f"```json\n{raw_json}\n```")

    sections.append("\n---\nPlease provide your comprehensive security analysis.")

    return "\n".join(sections)


def build_summary_prompt(findings: list[dict[str, Any]]) -> str:
    """Build a concise summarization prompt for report generation.

    Args:
        findings: List of finding dicts.

    Returns:
        Formatted prompt string.
    """
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    counts_str = ", ".join(f"{k}: {v}" for k, v in severity_counts.items())

    return (
        f"Summarize these penetration test findings in 2-3 paragraphs "
        f"suitable for an executive summary.\n\n"
        f"Finding counts by severity: {counts_str}\n"
        f"Total findings: {len(findings)}\n\n"
        f"Key findings:\n"
        + "\n".join(
            f"- [{f.get('severity', 'info').upper()}] {f.get('title', 'Untitled')}"
            for f in findings[:30]
        )
    )


# ── Structured analysis (Phase 2) ──────────────────────────────

_STRUCTURED_SCHEMA = """{
  "executive_summary": "string — 2-3 sentence summary of security posture",
  "overall_risk": "critical | high | medium | low | clean",
  "risk_score": "integer 0-100",
  "critical_findings": [
    {
      "finding_title": "string — title of the finding",
      "exploitability": "trivial | moderate | difficult | theoretical",
      "real_world_risk": "critical | high | medium | low | informational",
      "false_positive_likelihood": "float 0.0-1.0",
      "context": "string — why this matters for this target",
      "remediation": "string — specific fix"
    }
  ],
  "attack_paths": [
    {
      "name": "string — attack path name",
      "steps": ["string — ordered attack steps"],
      "finding_titles": ["string — finding titles involved"],
      "likelihood": "high | medium | low",
      "impact": "full_compromise | data_access | dos | info_leak | lateral_movement"
    }
  ],
  "recommendations": [
    {
      "priority": "critical | high | medium | low",
      "title": "string — action title",
      "rationale": "string — why",
      "tool_name": "string or null — suggested tool",
      "tool_config": "object or null — tool config"
    }
  ],
  "false_positive_flags": ["string — finding titles likely false positive"],
  "quick_wins": ["string — finding titles easy to fix"]
}"""

STRUCTURED_SYSTEM_PROMPT = (
    "You are Driln AI, an expert cybersecurity analyst and penetration tester.\n\n"
    "Analyze the scan results and respond with ONLY valid JSON (no markdown, "
    "no explanation outside the JSON).  Your response must match this exact schema:\n\n"
    f"```json\n{_STRUCTURED_SCHEMA}\n```\n\n"
    "Guidelines:\n"
    "- Be precise and technical\n"
    "- Prioritize findings by actual exploitability, not just CVSS scores\n"
    "- Identify attack chains — sequences of findings that together enable compromise\n"
    "- Flag potential false positives\n"
    "- Highlight quick wins (easy to fix, high impact)\n"
    "- Only include findings you have strong opinions about in critical_findings\n"
    "- Recommendations should be actionable and specific"
)


def build_structured_prompt(scan_data: dict[str, Any]) -> tuple[str, str]:
    """Build system + user prompts for structured JSON analysis.

    Returns:
        Tuple of ``(system_prompt, user_prompt)``.
    """
    # Reuse the same user prompt formatting
    user_prompt = build_analysis_prompt(scan_data)

    # Replace the final line to request JSON
    user_prompt = user_prompt.replace(
        "Please provide your comprehensive security analysis.",
        "Respond with ONLY valid JSON matching the schema from the system prompt.",
    )

    return STRUCTURED_SYSTEM_PROMPT, user_prompt
