"""Scan context — unified state aggregated incrementally as tools complete.

The :class:`ScanContext` is the single source of truth for everything known
about a scan target at any point in time.  It is built incrementally: after
each tool completes, the scanner calls :meth:`add_tool_result` to update
hosts, services, technologies, and findings.  Every intelligence component
reads from context — none of them query the DB directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from driln.tools.base import ToolResult


@dataclass
class ServiceContext:
    """A single service discovered on a host:port."""

    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    product: str | None = None
    version: str | None = None


@dataclass
class HostContext:
    """Everything known about a single host."""

    address: str
    hostnames: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    os: str | None = None
    services: dict[int, ServiceContext] = field(default_factory=dict)

    def add_service(self, svc: ServiceContext) -> None:
        if svc.port not in self.ports:
            self.ports.append(svc.port)
        # Keep the richer entry (more fields filled)
        existing = self.services.get(svc.port)
        if existing is None or (svc.product and not existing.product):
            self.services[svc.port] = svc


@dataclass
class ScanContext:
    """Living document of everything known about a scan target.

    Updated after each tool completes.  Feeds correlation, risk scoring,
    technology aggregation, and recommendation engines.
    """

    scan_id: str
    target: str
    scan_type: str
    hosts: dict[str, HostContext] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    services: dict[tuple[str, int], ServiceContext] = field(default_factory=dict)
    _raw_techs: list[dict[str, Any]] = field(default_factory=list)

    # ── Incremental update ──────────────────────────────────────

    def add_tool_result(self, result: ToolResult) -> None:
        """Incorporate a new tool result into the context."""
        self.tool_results.append(result)

        # Add findings — tag with tool name for dedup/correlation
        for f in result.findings:
            f_copy = dict(f)
            if "tool_name" not in f_copy:
                f_copy["tool_name"] = result.tool_name
            self.findings.append(f_copy)

        # Extract host/service/tech info based on tool type
        if result.tool_name == "nmap":
            self._ingest_nmap(result)
        elif result.tool_name == "subfinder":
            self._ingest_subfinder(result)
        elif result.tool_name == "httpx":
            self._ingest_httpx(result)
        elif result.tool_name == "nuclei":
            self._ingest_nuclei(result)

    # ── Accessors ───────────────────────────────────────────────

    def get_all_hosts(self) -> list[str]:
        """Return all discovered host addresses."""
        return list(self.hosts.keys())

    def get_open_ports(self, host: str) -> list[int]:
        """Return open ports for a specific host."""
        h = self.hosts.get(host)
        return h.ports if h else []

    def get_service(self, host: str, port: int) -> ServiceContext | None:
        """Return service info for a host:port pair."""
        return self.services.get((host, port))

    def get_all_services(self) -> list[ServiceContext]:
        """Return all discovered services."""
        return list(self.services.values())

    @property
    def host_count(self) -> int:
        """Number of unique hosts discovered."""
        return len(self.hosts)

    @property
    def finding_count(self) -> int:
        """Number of findings currently in context."""
        return len(self.findings)

    @property
    def tool_count(self) -> int:
        """Number of tools that have produced results."""
        return len(self.tool_results)

    def summary(self) -> dict:
        """Quick diagnostic summary of scan state."""
        sev_counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        return {
            "hosts": self.host_count,
            "findings": self.finding_count,
            "tools_run": self.tool_count,
            "services": len(self.services),
            "techs": len(self._raw_techs),
            "severity_counts": sev_counts,
        }

    # ── Tool-specific ingestion ─────────────────────────────────

    def _ingest_nmap(self, result: ToolResult) -> None:
        """Extract hosts, ports, services, OS from nmap parsed data."""
        for host_data in result.parsed_data.get("hosts", []):
            ip = host_data.get("ip", "")
            if not ip:
                continue

            host = self._ensure_host(ip)
            hostname = host_data.get("hostname")
            if hostname and hostname not in host.hostnames:
                host.hostnames.append(hostname)

            os_name = host_data.get("os")
            if os_name:
                host.os = os_name

            for port_data in host_data.get("ports", []):
                if port_data.get("state") != "open":
                    continue
                svc = ServiceContext(
                    host=ip,
                    port=port_data.get("port", 0),
                    protocol=port_data.get("protocol", "tcp"),
                    service=port_data.get("service", ""),
                    product=port_data.get("product"),
                    version=port_data.get("version"),
                )
                host.add_service(svc)
                self.services[(ip, svc.port)] = svc

    def _ingest_subfinder(self, result: ToolResult) -> None:
        """Extract discovered subdomains."""
        for sub in result.parsed_data.get("subdomains", []):
            self._ensure_host(sub)

    def _ingest_httpx(self, result: ToolResult) -> None:
        """Extract live hosts, technologies, servers."""
        for host_data in result.parsed_data.get("hosts", []):
            url = host_data.get("url", "")
            host_addr = host_data.get("host", "")
            if not host_addr:
                continue

            host = self._ensure_host(host_addr)
            port = host_data.get("port")
            if port:
                svc = ServiceContext(
                    host=host_addr,
                    port=port,
                    protocol="tcp",
                    service="http",
                )
                host.add_service(svc)
                self.services[(host_addr, port)] = svc

            # Technologies
            for tech_name in host_data.get("tech", []):
                self._raw_techs.append({
                    "name": tech_name,
                    "source": "httpx",
                    "host": host_addr,
                })

            webserver = host_data.get("webserver", "")
            if webserver:
                self._raw_techs.append({
                    "name": webserver,
                    "source": "httpx",
                    "host": host_addr,
                    "category": "server",
                })

    def _ingest_nuclei(self, result: ToolResult) -> None:
        """Extract vulnerability context and technology confirmations."""
        for vuln in result.parsed_data.get("vulnerabilities", []):
            host = vuln.get("host", "")
            if host:
                self._ensure_host(host)

            # Tags often reveal technologies
            for tag in vuln.get("tags", []):
                tag_lower = tag.lower()
                if tag_lower in _KNOWN_TECH_TAGS:
                    self._raw_techs.append({
                        "name": _KNOWN_TECH_TAGS[tag_lower],
                        "source": "nuclei",
                        "host": host,
                    })

    # ── Helpers ──────────────────────────────────────────────────

    def _ensure_host(self, address: str) -> HostContext:
        """Get or create a host context entry."""
        if address not in self.hosts:
            self.hosts[address] = HostContext(address=address)
        return self.hosts[address]


# Tags from nuclei templates that map to known technologies
_KNOWN_TECH_TAGS: dict[str, str] = {
    "wordpress": "WordPress",
    "wp": "WordPress",
    "wp-plugin": "WordPress",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "magento": "Magento",
    "laravel": "Laravel",
    "django": "Django",
    "flask": "Flask",
    "spring": "Spring",
    "graphql": "GraphQL",
    "jenkins": "Jenkins",
    "gitlab": "GitLab",
    "kibana": "Kibana",
    "elasticsearch": "Elasticsearch",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
    "phpmyadmin": "phpMyAdmin",
    "tomcat": "Apache Tomcat",
    "nginx": "Nginx",
    "apache": "Apache",
    "iis": "Microsoft IIS",
    "struts": "Apache Struts",
}
