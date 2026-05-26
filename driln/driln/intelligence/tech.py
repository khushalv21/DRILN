"""Technology fingerprint aggregation.

Merges technology detections from all tool results into a unified
:class:`~driln.schemas.intelligence.TechProfile`.  Each tool produces
raw tech hints in different formats — this module normalises them.

Example: httpx reports ``["WordPress"]`` in its ``tech`` array, nmap
reports ``product="Apache"`` on port 80, and nuclei fires a template
tagged ``["wordpress", "wp-plugin"]``.  The aggregator merges these into
a single ``TechProfile`` with deduplicated, confidence-boosted entries.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from driln.schemas.intelligence import TechFingerprint, TechProfile

if TYPE_CHECKING:
    from driln.intelligence.context import ScanContext


# ── Category mapping ────────────────────────────────────────────

_CATEGORY_MAP: dict[str, str] = {
    # CMS
    "wordpress": "cms",
    "joomla": "cms",
    "drupal": "cms",
    "magento": "cms",
    "shopify": "cms",
    "squarespace": "cms",
    "wix": "cms",
    "ghost": "cms",
    # Servers
    "apache": "server",
    "nginx": "server",
    "iis": "server",
    "microsoft iis": "server",
    "litespeed": "server",
    "caddy": "server",
    "apache tomcat": "server",
    "gunicorn": "server",
    "uvicorn": "server",
    # Frameworks
    "laravel": "framework",
    "django": "framework",
    "flask": "framework",
    "spring": "framework",
    "express": "framework",
    "rails": "framework",
    "next.js": "framework",
    "nuxt.js": "framework",
    "react": "framework",
    "vue.js": "framework",
    "angular": "framework",
    "graphql": "framework",
    "fastapi": "framework",
    # Languages
    "php": "language",
    "python": "language",
    "java": "language",
    "ruby": "language",
    "node.js": "language",
    "go": "language",
    "asp.net": "language",
    # CDN / WAF
    "cloudflare": "cdn",
    "akamai": "cdn",
    "cloudfront": "cdn",
    "sucuri": "waf",
    "wordfence": "waf",
    "modsecurity": "waf",
    # Databases
    "mysql": "database",
    "postgresql": "database",
    "mongodb": "database",
    "redis": "database",
    "elasticsearch": "database",
    "mariadb": "database",
    # Infrastructure
    "docker": "other",
    "kubernetes": "other",
    "jenkins": "other",
    "gitlab": "other",
    "phpmyadmin": "other",
    "kibana": "other",
}


def _categorize(name: str) -> str:
    """Return the category for a technology name."""
    return _CATEGORY_MAP.get(name.lower(), "other")


class TechAggregator:
    """Merge technology detections from multiple tool results into a single profile."""

    def aggregate(self, context: ScanContext) -> TechProfile:
        """Build a unified tech profile from all raw tech hints in the context."""
        raw_techs: list[dict[str, Any]] = list(context._raw_techs)

        # Also extract from nmap service info
        for svc in context.get_all_services():
            if svc.product:
                raw_techs.append({
                    "name": svc.product,
                    "version": svc.version,
                    "source": "nmap",
                    "host": svc.host,
                    "category": "server" if svc.service in ("http", "https") else "other",
                })

        # Normalize and deduplicate
        fingerprints = self._normalize(raw_techs)
        merged = self._merge_duplicates(fingerprints)

        # Build profile
        servers = []
        frameworks = []
        languages = []
        os_hints = []

        for fp in merged:
            label = fp.name
            if fp.version:
                label += f"/{fp.version}"

            if fp.category == "server":
                servers.append(label)
            elif fp.category in ("framework", "cms"):
                frameworks.append(label)
            elif fp.category == "language":
                languages.append(label)
            elif fp.category == "os":
                os_hints.append(label)

        # OS hints from hosts
        for host in context.hosts.values():
            if host.os and host.os not in os_hints:
                os_hints.append(host.os)

        return TechProfile(
            technologies=merged,
            servers=servers,
            frameworks=frameworks,
            languages=languages,
            os_hints=os_hints,
        )

    def _normalize(self, raw_techs: list[dict[str, Any]]) -> list[TechFingerprint]:
        """Convert raw tech dicts to TechFingerprint instances."""
        results: list[TechFingerprint] = []
        for raw in raw_techs:
            name = raw.get("name", "").strip()
            if not name:
                continue

            # Parse version from name if present (e.g., "Apache/2.4.52")
            version = raw.get("version")
            if "/" in name and not version:
                parts = name.split("/", 1)
                name = parts[0].strip()
                version = parts[1].strip()

            category = raw.get("category", _categorize(name))

            results.append(TechFingerprint(
                name=name,
                version=version,
                category=category,
                confidence=1.0,
                sources=[raw.get("source", "unknown")],
            ))
        return results

    def _merge_duplicates(self, techs: list[TechFingerprint]) -> list[TechFingerprint]:
        """Merge entries with the same name — combine sources, boost confidence."""
        by_name: dict[str, TechFingerprint] = {}

        for fp in techs:
            key = fp.name.lower()
            existing = by_name.get(key)
            if existing is None:
                by_name[key] = fp
            else:
                # Merge sources
                for src in fp.sources:
                    if src not in existing.sources:
                        existing.sources.append(src)
                # Boost confidence (cap at 1.0)
                existing.confidence = min(1.0, existing.confidence + 0.1)
                # Prefer more specific version
                if fp.version and not existing.version:
                    existing.version = fp.version
                # Prefer more specific category
                if fp.category != "other" and existing.category == "other":
                    existing.category = fp.category

        return list(by_name.values())
