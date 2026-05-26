"""Nmap integration.

Runs nmap with XML output (``-oX -``) for structured parsing.  Extracts
hosts, ports, services, and OS information into normalized findings.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from driln.tools.base import BaseTool, ToolResult


class NmapTool(BaseTool):
    name = "nmap"
    description = "Network exploration and security auditing"
    binary = "nmap"

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build nmap command.

        Supported options:
            ports (str): Port specification, e.g. "80,443" or "1-1000"
            scan_type (str): "-sS", "-sT", "-sV", etc. Default: "-sV"
            scripts (bool): Run default scripts (-sC). Default: True
            extra_args (list[str]): Additional raw arguments.
        """
        cmd = [self.binary]

        scan_type = options.get("scan_type", "-sV")
        cmd.append(scan_type)

        if options.get("scripts", True):
            cmd.append("-sC")

        ports = options.get("ports")
        if ports:
            cmd.extend(["-p", str(ports)])

        # Always output XML to stdout for parsing
        cmd.extend(["-oX", "-"])

        extra = options.get("extra_args", [])
        cmd.extend(extra)

        cmd.append(target)
        return cmd

    def parse_output(self, raw_output: str, exit_code: int) -> ToolResult:
        """Parse nmap XML output into structured data."""
        parsed: dict[str, Any] = {"hosts": []}
        findings: list[dict[str, Any]] = []

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            return ToolResult(
                tool_name=self.name,
                command="",
                raw_output=raw_output,
                parsed_data={},
                findings=[],
                exit_code=exit_code,
                duration=0.0,
                success=False,
                error="Failed to parse XML output",
            )

        for host_elem in root.findall(".//host"):
            host_info: dict[str, Any] = {}

            # IP address
            addr = host_elem.find("address")
            if addr is not None:
                host_info["ip"] = addr.get("addr", "")
                host_info["addr_type"] = addr.get("addrtype", "")

            # Hostname
            hostname_elem = host_elem.find(".//hostname")
            if hostname_elem is not None:
                host_info["hostname"] = hostname_elem.get("name", "")

            # Host status
            status = host_elem.find("status")
            if status is not None:
                host_info["state"] = status.get("state", "")

            # OS detection
            os_match = host_elem.find(".//osmatch")
            if os_match is not None:
                host_info["os"] = os_match.get("name", "")
                host_info["os_accuracy"] = os_match.get("accuracy", "")

            # Ports
            ports: list[dict[str, Any]] = []
            for port_elem in host_elem.findall(".//port"):
                port_info: dict[str, Any] = {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                }

                state = port_elem.find("state")
                if state is not None:
                    port_info["state"] = state.get("state", "")

                service = port_elem.find("service")
                if service is not None:
                    port_info["service"] = service.get("name", "")
                    port_info["product"] = service.get("product", "")
                    port_info["version"] = service.get("version", "")
                    port_info["extra_info"] = service.get("extrainfo", "")

                ports.append(port_info)

                # Generate a finding for each open port
                if port_info.get("state") == "open":
                    svc = port_info.get("service", "unknown")
                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    svc_detail = f"{svc}"
                    if product:
                        svc_detail += f" ({product}"
                        if version:
                            svc_detail += f" {version}"
                        svc_detail += ")"

                    findings.append({
                        "severity": "info",
                        "title": f"Open port {port_info['port']}/{port_info['protocol']} — {svc_detail}",
                        "description": f"Port {port_info['port']} is open running {svc_detail}",
                        "host": host_info.get("ip", ""),
                        "port": port_info["port"],
                        "protocol": port_info["protocol"],
                        "service": svc,
                    })

            host_info["ports"] = ports

            # Scripts
            scripts: list[dict[str, str]] = []
            for script_elem in host_elem.findall(".//script"):
                scripts.append({
                    "id": script_elem.get("id", ""),
                    "output": script_elem.get("output", ""),
                })
            host_info["scripts"] = scripts

            parsed["hosts"].append(host_info)

        return ToolResult(
            tool_name=self.name,
            command="",
            raw_output=raw_output,
            parsed_data=parsed,
            findings=findings,
            exit_code=exit_code,
            duration=0.0,
            success=exit_code == 0,
        )
