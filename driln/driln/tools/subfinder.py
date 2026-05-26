"""Subfinder integration.

Runs subfinder with JSON output for structured subdomain enumeration.
"""

from __future__ import annotations

import json
from typing import Any

from driln.tools.base import BaseTool, ToolResult


class SubfinderTool(BaseTool):
    name = "subfinder"
    description = "Fast passive subdomain enumeration"
    binary = "subfinder"

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build subfinder command.

        Supported options:
            silent (bool): Suppress banner. Default: True
            sources (list[str]): Specific data sources.
            recursive (bool): Use recursive enumeration.
            extra_args (list[str]): Additional raw arguments.
        """
        cmd = [self.binary, "-d", target, "-json"]

        if options.get("silent", True):
            cmd.append("-silent")

        sources = options.get("sources")
        if sources:
            cmd.extend(["-sources", ",".join(sources)])

        if options.get("recursive"):
            cmd.append("-recursive")

        extra = options.get("extra_args", [])
        cmd.extend(extra)

        return cmd

    def parse_output(self, raw_output: str, exit_code: int) -> ToolResult:
        """Parse subfinder JSON-lines output."""
        subdomains: list[str] = []
        parsed_entries: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                host = entry.get("host", "")
                if host:
                    subdomains.append(host)
                    parsed_entries.append(entry)

                    findings.append({
                        "severity": "info",
                        "title": f"Subdomain discovered: {host}",
                        "description": f"Subdomain {host} found via {entry.get('source', 'unknown')}",
                        "host": host,
                    })
            except json.JSONDecodeError:
                # Fallback: treat as plain text subdomain
                if "." in line:
                    subdomains.append(line)
                    findings.append({
                        "severity": "info",
                        "title": f"Subdomain discovered: {line}",
                        "host": line,
                    })

        return ToolResult(
            tool_name=self.name,
            command="",
            raw_output=raw_output,
            parsed_data={
                "subdomains": subdomains,
                "entries": parsed_entries,
                "count": len(subdomains),
            },
            findings=findings,
            exit_code=exit_code,
            duration=0.0,
            success=exit_code == 0,
        )
