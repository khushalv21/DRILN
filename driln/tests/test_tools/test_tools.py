"""Unit tests for tool command building and output parsing.

These tests verify the tool abstractions without requiring the actual
tool binaries to be installed — they test ``build_command`` and
``parse_output`` in isolation.
"""

from __future__ import annotations

import pytest

from driln.tools.nmap import NmapTool
from driln.tools.subfinder import SubfinderTool
from driln.tools.httpx_tool import HttpxTool
from driln.tools.nuclei import NucleiTool


class TestNmapTool:
    def setup_method(self):
        self.tool = NmapTool()

    def test_build_command_default(self):
        cmd = self.tool.build_command("example.com", {})
        assert cmd[0] == "nmap"
        assert "-sV" in cmd
        assert "-sC" in cmd
        assert "-oX" in cmd
        assert "example.com" in cmd

    def test_build_command_with_ports(self):
        cmd = self.tool.build_command("example.com", {"ports": "80,443"})
        assert "-p" in cmd
        idx = cmd.index("-p")
        assert cmd[idx + 1] == "80,443"

    def test_parse_output_valid_xml(self):
        xml_output = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <address addr="93.184.216.34" addrtype="ipv4"/>
                <status state="up"/>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="nginx" version="1.25.0"/>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""
        result = self.tool.parse_output(xml_output, 0)
        assert result.success
        assert len(result.findings) == 2
        assert result.parsed_data["hosts"][0]["ip"] == "93.184.216.34"

    def test_parse_output_invalid_xml(self):
        result = self.tool.parse_output("not xml at all", 0)
        assert not result.success
        assert result.error == "Failed to parse XML output"


class TestSubfinderTool:
    def setup_method(self):
        self.tool = SubfinderTool()

    def test_build_command_default(self):
        cmd = self.tool.build_command("example.com", {})
        assert cmd[0] == "subfinder"
        assert "-d" in cmd
        assert "example.com" in cmd
        assert "-json" in cmd
        assert "-silent" in cmd

    def test_parse_output_json_lines(self):
        output = (
            '{"host": "api.example.com", "source": "crtsh"}\n'
            '{"host": "mail.example.com", "source": "dnsdumpster"}\n'
        )
        result = self.tool.parse_output(output, 0)
        assert result.success
        assert len(result.findings) == 2
        assert "api.example.com" in result.parsed_data["subdomains"]
        assert result.parsed_data["count"] == 2

    def test_parse_output_plain_text_fallback(self):
        output = "api.example.com\nmail.example.com\n"
        result = self.tool.parse_output(output, 0)
        assert len(result.findings) == 2


class TestHttpxTool:
    def setup_method(self):
        self.tool = HttpxTool()

    def test_build_command_single_target(self):
        cmd = self.tool.build_command("example.com", {})
        assert cmd[0] == "httpx"
        assert "-u" in cmd
        assert "-json" in cmd

    def test_build_command_input_list(self):
        cmd = self.tool.build_command("example.com", {"input_list": "/tmp/targets.txt"})
        assert "-l" in cmd
        assert "-u" not in cmd

    def test_parse_output(self):
        output = '{"url": "https://example.com", "status_code": 200, "title": "Example", "host": "example.com", "tech": ["nginx"], "webserver": "nginx"}\n'
        result = self.tool.parse_output(output, 0)
        assert result.success
        assert len(result.findings) == 1
        assert result.parsed_data["live_count"] == 1


class TestNucleiTool:
    def setup_method(self):
        self.tool = NucleiTool()

    def test_build_command_default(self):
        cmd = self.tool.build_command("example.com", {})
        assert cmd[0] == "nuclei"
        assert "-json" in cmd
        assert "-u" in cmd

    def test_build_command_with_severity(self):
        cmd = self.tool.build_command("example.com", {"severity": "high,critical"})
        assert "-severity" in cmd

    def test_parse_output(self):
        output = '{"template-id": "cve-2021-44228", "info": {"name": "Log4Shell", "severity": "critical", "description": "RCE via Log4j", "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"], "tags": ["cve", "rce"]}, "host": "example.com", "matched-at": "https://example.com/api"}\n'
        result = self.tool.parse_output(output, 0)
        assert len(result.findings) == 1
        assert result.findings[0]["severity"] == "critical"
        assert result.parsed_data["severity_counts"]["critical"] == 1
