"""httpx integration.

Runs httpx (ProjectDiscovery) with JSON output to probe live hosts,
extract status codes, titles, technologies, and content lengths.
"""

from __future__ import annotations

import json
from typing import Any

from driln.tools.base import BaseTool, ToolResult


class HttpxTool(BaseTool):
    name = "httpx"
    description = "Fast and multi-purpose HTTP toolkit"
    binary = "httpx"
    allowed_extra_args = frozenset({
        "-v", "-debug", "-stats", "-no-color", "-random-agent", "-H"
    })

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build httpx command.

        Supported options:
            silent (bool): Suppress banner. Default: True
            status_code (bool): Show status codes. Default: True
            title (bool): Show page titles. Default: True
            tech_detect (bool): Detect technologies. Default: True
            follow_redirects (bool): Follow redirects. Default: True
            input_list (str): Path to file with targets (one per line).
            extra_args (list[str]): Additional raw arguments.
        """
        cmd = [self.binary, "-json"]

        if options.get("silent", True):
            cmd.append("-silent")

        if options.get("status_code", True):
            cmd.append("-status-code")

        if options.get("title", True):
            cmd.append("-title")

        if options.get("tech_detect", True):
            cmd.append("-tech-detect")

        if options.get("follow_redirects", True):
            cmd.append("-follow-redirects")

        input_list = options.get("input_list")
        if input_list:
            cmd.extend(["-l", str(input_list)])
        else:
            cmd.extend(["-u", target])

        extra = options.get("extra_args", [])
        cmd.extend(extra)

        return cmd

    def parse_output(self, raw_output: str, exit_code: int) -> ToolResult:
        """Parse httpx JSON-lines output."""
        hosts: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            host_info = {
                "url": entry.get("url", ""),
                "status_code": entry.get("status_code"),
                "title": entry.get("title", ""),
                "tech": entry.get("tech", []),
                "content_length": entry.get("content_length"),
                "webserver": entry.get("webserver", ""),
                "host": entry.get("host", ""),
                "port": entry.get("port"),
                "scheme": entry.get("scheme", ""),
            }
            hosts.append(host_info)

            # Finding for each live host
            title = host_info["title"] or "No title"
            status = host_info["status_code"] or "?"
            tech = ", ".join(host_info.get("tech") or []) or "none detected"

            findings.append({
                "severity": "info",
                "title": f"Live host: {host_info['url']} [{status}]",
                "description": (
                    f"Title: {title}\n"
                    f"Server: {host_info['webserver']}\n"
                    f"Technologies: {tech}"
                ),
                "host": host_info.get("host", ""),
                "port": host_info.get("port"),
                "service": "http",
            })

        return ToolResult(
            tool_name=self.name,
            command="",
            raw_output=raw_output,
            parsed_data={
                "hosts": hosts,
                "live_count": len(hosts),
            },
            findings=findings,
            exit_code=exit_code,
            duration=0.0,
            success=exit_code == 0,
        )
