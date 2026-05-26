"""Finding correlation engine.

Groups related findings from different tools into
:class:`~driln.schemas.intelligence.CorrelationGroup` instances.

Three correlation strategies run in sequence:

1. **Same service** — findings on the same host:port are grouped together.
   A port scan finding + a vulnerability on the same service = one group.

2. **Attack chain** — a version/service finding paired with a CVE or
   vulnerability on the same service suggests an exploitable chain.

3. **Technology overlap** — technology detected by httpx confirmed by a
   nuclei template finding on the same host.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Any

from driln.schemas.intelligence import CorrelationGroup, TechProfile


class FindingCorrelator:
    """Group related findings from different tools."""

    def correlate(
        self,
        findings: list[dict[str, Any]],
        tech_profile: TechProfile | None = None,
    ) -> list[CorrelationGroup]:
        """Run all correlation strategies and return groups.

        Only groups with 2+ findings are returned.
        """
        groups: list[CorrelationGroup] = []
        groups.extend(self._by_host_port(findings))
        groups.extend(self._by_attack_chain(findings))
        if tech_profile:
            groups.extend(self._by_technology(findings, tech_profile))
        return groups

    def _by_host_port(self, findings: list[dict[str, Any]]) -> list[CorrelationGroup]:
        """Group findings that share the same host:port from different tools."""
        buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for f in findings:
            host = f.get("host", "")
            port = f.get("port")
            if host and port:
                key = f"{host}:{port}"
                buckets[key].append(f)

        groups: list[CorrelationGroup] = []
        for key, group_findings in buckets.items():
            # Only interesting if multiple tools found things on the same service
            tools: set[str] = set()
            for f in group_findings:
                tool = f.get("tool_name") or (
                    f.get("source_tools", ["unknown"])[0]
                    if f.get("source_tools")
                    else "unknown"
                )
                tools.add(tool)
            if len(group_findings) >= 2 and len(tools) >= 2:
                finding_ids = [f.get("id", "") for f in group_findings if f.get("id")]
                if not finding_ids:
                    continue
                groups.append(CorrelationGroup(
                    group_id=str(uuid.uuid4()),
                    finding_ids=finding_ids,
                    relationship="same_service",
                    summary=f"Multiple tools found issues on {key}: {', '.join(tools)}",
                ))
        return groups

    def _by_attack_chain(self, findings: list[dict[str, Any]]) -> list[CorrelationGroup]:
        """Identify potential attack chains: version disclosure + vulnerability."""
        # Index: host:port → findings by severity
        service_findings: dict[str, dict[str, list[dict]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for f in findings:
            host = f.get("host", "")
            port = f.get("port")
            if not host:
                continue
            key = f"{host}:{port}" if port else host
            sev = f.get("severity", "info")
            service_findings[key][sev].append(f)

        groups: list[CorrelationGroup] = []
        for key, by_sev in service_findings.items():
            # Attack chain = info/low findings + medium/high/critical findings
            # on the same service
            low_tier = by_sev.get("info", []) + by_sev.get("low", [])
            high_tier = (
                by_sev.get("medium", [])
                + by_sev.get("high", [])
                + by_sev.get("critical", [])
            )

            if low_tier and high_tier:
                all_ids = [
                    f.get("id", "")
                    for f in low_tier + high_tier
                    if f.get("id")
                ]
                if len(all_ids) < 2:
                    continue

                high_titles = [f.get("title", "?") for f in high_tier[:3]]
                groups.append(CorrelationGroup(
                    group_id=str(uuid.uuid4()),
                    finding_ids=all_ids,
                    relationship="attack_chain",
                    summary=(
                        f"Service info + vulnerability on {key}: "
                        f"{', '.join(high_titles)}"
                    ),
                ))
        return groups

    def _by_technology(
        self,
        findings: list[dict[str, Any]],
        tech_profile: TechProfile,
    ) -> list[CorrelationGroup]:
        """Group findings related to the same detected technology."""
        tech_names = {t.name.lower() for t in tech_profile.technologies}
        if not tech_names:
            return []

        # Bucket findings by which tech they mention
        tech_buckets: dict[str, list[dict]] = defaultdict(list)
        for f in findings:
            title_lower = f.get("title", "").lower()
            desc_lower = (f.get("description") or "").lower()
            text = f"{title_lower} {desc_lower}"

            for tech in tech_names:
                if tech in text:
                    tech_buckets[tech].append(f)
                    break  # One finding → one tech bucket

        groups: list[CorrelationGroup] = []
        for tech, grouped in tech_buckets.items():
            if len(grouped) >= 2:
                ids = [f.get("id", "") for f in grouped if f.get("id")]
                if not ids:
                    continue
                groups.append(CorrelationGroup(
                    group_id=str(uuid.uuid4()),
                    finding_ids=ids,
                    relationship="tech_overlap",
                    summary=f"{len(grouped)} findings related to {tech}",
                ))
        return groups
