"""Rule-based recommendation engine.

Generates next-step recommendations by evaluating scan context and
technology profile against a declarative rule set.  Each rule is a
simple predicate: if the condition matches, the recommendation is
emitted.

No AI is required — this is pure pattern matching.  AI-generated
recommendations are handled separately in the intelligence service.

Rules are *data*, not code: each is a dataclass with a condition
callable, making it easy to add new rules without touching logic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from driln.schemas.intelligence import TechProfile

if TYPE_CHECKING:
    from driln.intelligence.context import ScanContext


# ── Recommendation data ─────────────────────────────────────────


@dataclass
class RuleRecommendation:
    """A recommendation emitted by a rule."""

    priority: str  # critical | high | medium | low
    category: str  # tool_suggestion | config_change | manual_check
    title: str
    rationale: str
    tool_name: str | None = None
    tool_config: dict[str, Any] | None = None


@dataclass
class RecommendationRule:
    """Declarative recommendation rule.

    Attributes:
        name: Unique rule identifier (for logging/debugging).
        condition: Predicate — receives ScanContext + TechProfile, returns bool.
        recommendation: The recommendation to emit if the condition is True.
    """

    name: str
    condition: Callable[[ScanContext, TechProfile], bool]
    recommendation: RuleRecommendation


# ── Rule definitions ────────────────────────────────────────────

def _has_tech(tp: TechProfile, name: str) -> bool:
    """Check if a technology is in the profile (case-insensitive)."""
    return any(t.name.lower() == name.lower() for t in tp.technologies)


def _has_service(ctx: ScanContext, *service_names: str) -> bool:
    """Check if any service matches the given names."""
    names = {n.lower() for n in service_names}
    return any(s.service.lower() in names for s in ctx.get_all_services())


def _has_finding_keyword(ctx: ScanContext, *keywords: str) -> bool:
    """Check if any finding title contains one of the keywords."""
    for f in ctx.findings:
        title = f.get("title", "").lower()
        if any(kw.lower() in title for kw in keywords):
            return True
    return False


def _has_open_port(ctx: ScanContext, port: int) -> bool:
    """Check if any host has the given port open."""
    return any(port in h.ports for h in ctx.hosts.values())


RULES: list[RecommendationRule] = [
    # ── CMS ──────────────────────────────────────────────────
    RecommendationRule(
        name="wordpress_detected",
        condition=lambda ctx, tp: _has_tech(tp, "WordPress"),
        recommendation=RuleRecommendation(
            priority="high",
            category="tool_suggestion",
            title="Run WPScan against WordPress installation",
            rationale=(
                "WordPress detected — WPScan enumerates plugins, themes, "
                "users, and known CVEs specific to the WP ecosystem"
            ),
            tool_name="wpscan",
        ),
    ),
    RecommendationRule(
        name="joomla_detected",
        condition=lambda ctx, tp: _has_tech(tp, "Joomla"),
        recommendation=RuleRecommendation(
            priority="high",
            category="tool_suggestion",
            title="Run JoomScan against Joomla installation",
            rationale="Joomla detected — JoomScan checks for known Joomla vulnerabilities and misconfigurations",
            tool_name="joomscan",
        ),
    ),
    RecommendationRule(
        name="drupal_detected",
        condition=lambda ctx, tp: _has_tech(tp, "Drupal"),
        recommendation=RuleRecommendation(
            priority="high",
            category="tool_suggestion",
            title="Run Droopescan against Drupal installation",
            rationale="Drupal detected — scan for known module vulnerabilities and version-specific CVEs",
            tool_name="droopescan",
        ),
    ),

    # ── API / Protocol ──────────────────────────────────────
    RecommendationRule(
        name="graphql_detected",
        condition=lambda ctx, tp: _has_tech(tp, "GraphQL"),
        recommendation=RuleRecommendation(
            priority="medium",
            category="tool_suggestion",
            title="Run GraphQL introspection and security analysis",
            rationale=(
                "GraphQL endpoint detected — check for introspection enabled, "
                "excessive data exposure, batch query attacks, and injection"
            ),
            tool_name="graphql-cop",
        ),
    ),

    # ── Protocol-specific ───────────────────────────────────
    RecommendationRule(
        name="smb_open",
        condition=lambda ctx, tp: _has_service(ctx, "smb", "microsoft-ds", "netbios-ssn"),
        recommendation=RuleRecommendation(
            priority="high",
            category="tool_suggestion",
            title="Run SMB enumeration",
            rationale=(
                "SMB service detected — check for null sessions, anonymous shares, "
                "user enumeration, and known SMB vulnerabilities (EternalBlue, etc.)"
            ),
            tool_name="enum4linux",
        ),
    ),
    RecommendationRule(
        name="ftp_open",
        condition=lambda ctx, tp: _has_service(ctx, "ftp"),
        recommendation=RuleRecommendation(
            priority="medium",
            category="manual_check",
            title="Check FTP for anonymous access and known vulnerabilities",
            rationale="FTP service detected — verify anonymous login is disabled and service is patched",
        ),
    ),
    RecommendationRule(
        name="ssh_weak",
        condition=lambda ctx, tp: (
            _has_service(ctx, "ssh")
            and _has_finding_keyword(ctx, "ssh", "openssh")
        ),
        recommendation=RuleRecommendation(
            priority="medium",
            category="tool_suggestion",
            title="Run SSH audit for weak algorithms and configurations",
            rationale="SSH service with findings detected — audit key exchange, ciphers, and MACs",
            tool_name="ssh-audit",
        ),
    ),
    RecommendationRule(
        name="snmp_open",
        condition=lambda ctx, tp: _has_service(ctx, "snmp"),
        recommendation=RuleRecommendation(
            priority="high",
            category="tool_suggestion",
            title="Run SNMP enumeration",
            rationale="SNMP service detected — check for default community strings and information disclosure",
            tool_name="snmpwalk",
        ),
    ),
    RecommendationRule(
        name="rdp_open",
        condition=lambda ctx, tp: _has_service(ctx, "ms-wbt-server", "rdp"),
        recommendation=RuleRecommendation(
            priority="high",
            category="manual_check",
            title="Check RDP for BlueKeep and NLA configuration",
            rationale="RDP service detected — verify Network Level Authentication is enabled and service is patched",
        ),
    ),

    # ── Database ports ──────────────────────────────────────
    RecommendationRule(
        name="mysql_exposed",
        condition=lambda ctx, tp: _has_open_port(ctx, 3306),
        recommendation=RuleRecommendation(
            priority="high",
            category="manual_check",
            title="Verify MySQL is not exposed to the internet",
            rationale="MySQL port 3306 is open — database ports should not be publicly accessible",
        ),
    ),
    RecommendationRule(
        name="postgres_exposed",
        condition=lambda ctx, tp: _has_open_port(ctx, 5432),
        recommendation=RuleRecommendation(
            priority="high",
            category="manual_check",
            title="Verify PostgreSQL is not exposed to the internet",
            rationale="PostgreSQL port 5432 is open — database ports should not be publicly accessible",
        ),
    ),
    RecommendationRule(
        name="mongodb_exposed",
        condition=lambda ctx, tp: _has_open_port(ctx, 27017),
        recommendation=RuleRecommendation(
            priority="critical",
            category="manual_check",
            title="Verify MongoDB requires authentication",
            rationale=(
                "MongoDB port 27017 is open — unauthenticated MongoDB instances "
                "are a top target for data theft and ransomware"
            ),
        ),
    ),
    RecommendationRule(
        name="redis_exposed",
        condition=lambda ctx, tp: _has_open_port(ctx, 6379),
        recommendation=RuleRecommendation(
            priority="critical",
            category="manual_check",
            title="Verify Redis requires authentication",
            rationale="Redis port 6379 is open — unauthenticated Redis allows arbitrary command execution",
        ),
    ),

    # ── Finding-based ───────────────────────────────────────
    RecommendationRule(
        name="admin_panel_detected",
        condition=lambda ctx, tp: _has_finding_keyword(ctx, "admin", "login", "wp-login", "administrator"),
        recommendation=RuleRecommendation(
            priority="high",
            category="config_change",
            title="Run targeted authentication testing against admin panel",
            rationale="Admin panel detected — test for default credentials and brute-force protections",
            tool_name="nuclei",
            tool_config={"tags": ["default-login", "admin-panel"], "severity": "medium,high,critical"},
        ),
    ),
    RecommendationRule(
        name="git_exposed",
        condition=lambda ctx, tp: _has_finding_keyword(ctx, ".git", "git config", "git repository"),
        recommendation=RuleRecommendation(
            priority="critical",
            category="tool_suggestion",
            title="Dump exposed Git repository",
            rationale="Exposed .git directory detected — source code and credentials may be extractable",
            tool_name="git-dumper",
        ),
    ),
    RecommendationRule(
        name="ssl_issues",
        condition=lambda ctx, tp: _has_finding_keyword(
            ctx, "ssl", "tls", "certificate", "expired cert", "self-signed"
        ),
        recommendation=RuleRecommendation(
            priority="medium",
            category="tool_suggestion",
            title="Run comprehensive SSL/TLS audit",
            rationale="SSL/TLS issues detected — verify cipher suites, protocol versions, and certificate chain",
            tool_name="testssl",
        ),
    ),
    RecommendationRule(
        name="cors_misconfiguration",
        condition=lambda ctx, tp: _has_finding_keyword(ctx, "cors", "access-control"),
        recommendation=RuleRecommendation(
            priority="medium",
            category="manual_check",
            title="Verify CORS policy is correctly configured",
            rationale="CORS-related finding detected — misconfigured CORS can allow cross-origin data theft",
        ),
    ),

    # ── Infrastructure ──────────────────────────────────────
    RecommendationRule(
        name="jenkins_detected",
        condition=lambda ctx, tp: _has_tech(tp, "Jenkins"),
        recommendation=RuleRecommendation(
            priority="high",
            category="tool_suggestion",
            title="Run nuclei Jenkins templates",
            rationale="Jenkins detected — check for unauthenticated access, script console, and known CVEs",
            tool_name="nuclei",
            tool_config={"tags": ["jenkins"], "severity": "medium,high,critical"},
        ),
    ),
    RecommendationRule(
        name="docker_api_exposed",
        condition=lambda ctx, tp: _has_open_port(ctx, 2375) or _has_open_port(ctx, 2376),
        recommendation=RuleRecommendation(
            priority="critical",
            category="manual_check",
            title="Check for exposed Docker API",
            rationale="Docker API port detected — unauthenticated Docker API allows full host compromise",
        ),
    ),
]


# ── Engine ──────────────────────────────────────────────────────


class RecommendationEngine:
    """Generate next-step recommendations from scan intelligence."""

    def generate(
        self,
        context: ScanContext,
        tech_profile: TechProfile,
    ) -> list[RuleRecommendation]:
        """Evaluate all rules and return matching recommendations."""
        results: list[RuleRecommendation] = []
        seen_names: set[str] = set()

        for rule in RULES:
            if rule.name in seen_names:
                continue
            try:
                if rule.condition(context, tech_profile):
                    results.append(rule.recommendation)
                    seen_names.add(rule.name)
            except Exception:
                # Never let a broken rule crash the pipeline
                continue

        return results
