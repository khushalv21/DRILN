"""Composite risk scoring.

Each finding gets a 0-100 risk score computed from four weighted factors:

* **Base severity** (40%) — maps the severity enum to a float.
* **Exploitability** (25%) — heuristic based on finding type.
* **Exposure** (20%) — is the service externally reachable?
* **Context boost** (15%) — correlated findings on the same service.

The scan-level score is the weighted average of all finding scores, biased
toward the top findings.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from driln.schemas.intelligence import RiskScore

if TYPE_CHECKING:
    from driln.intelligence.context import ScanContext


# ── Constants ───────────────────────────────────────────────────

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.05,
}

# Keywords that suggest easy exploitability
_HIGH_EXPLOIT_KEYWORDS = frozenset({
    "default", "credential", "rce", "remote code", "injection",
    "sqli", "sql injection", "command injection", "unauthenticated",
    "bypass", "traversal", "lfi", "rfi", "ssrf", "xxe", "upload",
    "deserialization", "exec", "shell",
})

_MEDIUM_EXPLOIT_KEYWORDS = frozenset({
    "xss", "cross-site", "csrf", "clickjacking", "cors",
    "redirect", "disclosure", "exposed", "misconfiguration",
    "missing header", "deprecated", "weak",
})

# Services typically internet-facing
_EXPOSED_SERVICES = frozenset({
    "http", "https", "ssh", "ftp", "smtp", "dns",
    "pop3", "imap",
})


class RiskScorer:
    """Compute composite risk scores for findings and scans."""

    def score_finding(
        self,
        finding: dict[str, Any],
        context: ScanContext,
    ) -> RiskScore:
        """Score a single finding."""
        base = self._base_severity(finding)
        exploit = self._exploitability(finding)
        exposure = self._exposure(finding, context)
        boost = self._context_boost(finding, context)

        # Weighted composite: base×40 + exploit×25 + exposure×20 + boost×15
        score = (base * 40) + (exploit * 25) + (exposure * 20) + (boost * 15)
        score = min(100.0, max(0.0, score))

        return RiskScore(
            score=round(score, 1),
            base_severity=base,
            exploitability=exploit,
            exposure=exposure,
            context_boost=boost,
            label=self._score_to_label(score),
        )

    def score_scan(
        self,
        findings: list[dict[str, Any]],
        context: ScanContext,
    ) -> RiskScore:
        """Compute an aggregate risk score for the entire scan.

        Uses a top-heavy average: the highest-risk findings weigh more.
        """
        if not findings:
            return RiskScore(
                score=0.0,
                base_severity=0.0,
                exploitability=0.0,
                exposure=0.0,
                context_boost=0.0,
                label="clean",
            )

        scores = [self.score_finding(f, context) for f in findings]
        scores.sort(key=lambda s: s.score, reverse=True)

        # Top-heavy average: top 20% findings get 3× weight
        top_count = max(1, len(scores) // 5)
        top_scores = scores[:top_count]
        rest_scores = scores[top_count:]

        weighted_sum = (
            sum(s.score * 3 for s in top_scores)
            + sum(s.score for s in rest_scores)
        )
        total_weight = (top_count * 3) + len(rest_scores)
        avg_score = weighted_sum / total_weight if total_weight else 0.0

        # Aggregate factors
        avg_base = sum(s.base_severity for s in scores) / len(scores)
        avg_exploit = sum(s.exploitability for s in scores) / len(scores)
        avg_exposure = sum(s.exposure for s in scores) / len(scores)
        avg_boost = sum(s.context_boost for s in scores) / len(scores)

        return RiskScore(
            score=round(min(100.0, avg_score), 1),
            base_severity=round(avg_base, 2),
            exploitability=round(avg_exploit, 2),
            exposure=round(avg_exposure, 2),
            context_boost=round(avg_boost, 2),
            label=self._score_to_label(avg_score),
        )

    # ── Factor calculators ──────────────────────────────────────

    def _base_severity(self, finding: dict[str, Any]) -> float:
        sev = finding.get("severity", "info").lower()
        return _SEVERITY_WEIGHTS.get(sev, 0.05)

    def _exploitability(self, finding: dict[str, Any]) -> float:
        """Heuristic: scan title/description for exploitation keywords."""
        text = (
            f"{finding.get('title', '')} {finding.get('description', '')}"
        ).lower()

        if any(kw in text for kw in _HIGH_EXPLOIT_KEYWORDS):
            return 0.9
        if any(kw in text for kw in _MEDIUM_EXPLOIT_KEYWORDS):
            return 0.5
        return 0.2

    def _exposure(self, finding: dict[str, Any], context: ScanContext) -> float:
        """Higher exposure for internet-facing services."""
        service = finding.get("service", "").lower()
        port = finding.get("port")

        if service in _EXPOSED_SERVICES:
            return 0.8

        # Well-known internet ports
        if port and port in (80, 443, 8080, 8443, 21, 22, 25, 53, 3306, 5432):
            return 0.7

        # Has a host context → we have some visibility
        host = finding.get("host", "")
        if host and host in context.hosts:
            host_ctx = context.hosts[host]
            # Many open ports = larger attack surface
            if len(host_ctx.ports) > 10:
                return 0.6

        return 0.3

    def _context_boost(self, finding: dict[str, Any], context: ScanContext) -> float:
        """Boost score when correlated context suggests higher risk."""
        host = finding.get("host", "")
        port = finding.get("port")
        boost = 0.0

        if not host:
            return boost

        # Boost if other findings exist on the same host:port
        same_service_count = sum(
            1 for f in context.findings
            if f.get("host") == host
            and f.get("port") == port
            and f is not finding
        )
        if same_service_count >= 3:
            boost += 0.4
        elif same_service_count >= 1:
            boost += 0.2

        # Boost if the host has many open ports (large attack surface)
        host_ctx = context.hosts.get(host)
        if host_ctx and len(host_ctx.ports) > 5:
            boost += 0.15

        # Boost for findings on services with known tech (more context = more risk)
        if port:
            svc = context.get_service(host, port)
            if svc and svc.product:
                boost += 0.1

        return min(1.0, boost)

    def _score_to_label(self, score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "informational"
