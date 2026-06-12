"""Nuclei integration.

Runs Nuclei (ProjectDiscovery) with JSON output for template-based
vulnerability scanning.  Maps Nuclei severity levels directly to the
Driln severity enum.
"""

from __future__ import annotations

import json
from typing import Any

from driln.tools.base import BaseTool, ToolResult


class NucleiTool(BaseTool):
    name = "nuclei"
    description = "Template-based vulnerability scanner"
    binary = "nuclei"
    allowed_extra_args = frozenset({
        "-v", "-debug", "-as", "-stats", "-vnc", "-no-color", "-H"
    })

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build nuclei command.

        Supported options:
            silent (bool): Suppress banner. Default: True
            severity (str): Filter by severity, e.g. "medium,high,critical"
            templates (list[str]): Specific template paths or IDs.
            tags (list[str]): Template tags to include.
            rate_limit (int): Requests per second limit.
            input_list (str): Path to file with targets.
            extra_args (list[str]): Additional raw arguments.
        """
        cmd = [self.binary, "-json", "-no-color"]

        if options.get("silent", True):
            cmd.append("-silent")

        severity = options.get("severity")
        if severity:
            cmd.extend(["-severity", str(severity)])

        templates = options.get("templates")
        if templates:
            for t in templates:
                cmd.extend(["-t", t])

        tags = options.get("tags")
        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        rate_limit = options.get("rate_limit")
        if rate_limit:
            cmd.extend(["-rl", str(rate_limit)])

        input_list = options.get("input_list")
        if input_list:
            cmd.extend(["-l", str(input_list)])
        else:
            cmd.extend(["-u", target])

        extra = options.get("extra_args", [])
        cmd.extend(extra)

        return cmd

    def parse_output(self, raw_output: str, exit_code: int) -> ToolResult:
        """Parse nuclei JSON-lines output."""
        vulnerabilities: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []

        severity_map = {
            "info": "info",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        }

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = entry.get("info", {})
            vuln = {
                "template_id": entry.get("template-id", ""),
                "template_name": info.get("name", ""),
                "severity": info.get("severity", "info"),
                "host": entry.get("host", ""),
                "matched_at": entry.get("matched-at", ""),
                "matcher_name": entry.get("matcher-name", ""),
                "description": info.get("description", ""),
                "reference": info.get("reference", []),
                "tags": info.get("tags", []),
                "extracted_results": entry.get("extracted-results", []),
                "curl_command": entry.get("curl-command", ""),
            }
            vulnerabilities.append(vuln)

            # Map to finding
            severity_raw = vuln["severity"].lower()
            severity = severity_map.get(severity_raw, "info")

            refs = vuln["reference"]
            if isinstance(refs, list):
                refs_str = ", ".join(refs[:5])  # Limit references
            else:
                refs_str = str(refs)

            findings.append({
                "severity": severity,
                "title": f"[{vuln['template_id']}] {vuln['template_name']}",
                "description": (
                    f"{vuln['description']}\n\n"
                    f"Matched at: {vuln['matched_at']}\n"
                    f"References: {refs_str}"
                ).strip(),
                "host": vuln["host"],
                "metadata_": {
                    "template_id": vuln["template_id"],
                    "tags": vuln["tags"],
                    "matcher": vuln["matcher_name"],
                    "curl": vuln["curl_command"],
                },
            })

        # Severity counts
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return ToolResult(
            tool_name=self.name,
            command="",
            raw_output=raw_output,
            parsed_data={
                "vulnerabilities": vulnerabilities,
                "severity_counts": severity_counts,
                "total": len(vulnerabilities),
            },
            findings=findings,
            exit_code=exit_code,
            duration=0.0,
            success=True,  # Nuclei returns 0 even with findings
        )
