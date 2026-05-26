"""Finding deduplication.

When multiple tools report the same issue (e.g. nmap and nuclei both flag
an open port with a known service), we merge them into a single finding
with multiple ``source_tools``.

Matching criteria — two findings are considered duplicates when:

* Same host
* Same port (if present)
* Same or compatible severity
* Title similarity above the configured threshold

The *primary* finding (richer description, higher severity) is kept;
the duplicate is discarded but its source tool is recorded.
"""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any

import structlog

logger = structlog.get_logger()


class FindingDeduplicator:
    """Detect and merge duplicate findings from different tools."""

    def __init__(self, similarity_threshold: float = 0.70) -> None:
        self._threshold = similarity_threshold

    def deduplicate(
        self, findings: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int]:
        """Deduplicate a list of findings.

        Returns:
            Tuple of ``(deduplicated_findings, number_of_merges)``.
        """
        if not findings:
            return [], 0

        # Track which indices have been merged into another
        merged_into: dict[int, int] = {}  # victim_idx → primary_idx
        merge_count = 0

        for i in range(len(findings)):
            if i in merged_into:
                continue
            for j in range(i + 1, len(findings)):
                if j in merged_into:
                    continue
                if self._are_duplicates(findings[i], findings[j]):
                    # Merge j into i (keep the richer one as primary)
                    primary_idx, victim_idx = self._pick_primary(i, j, findings)
                    self._merge(findings[primary_idx], findings[victim_idx])
                    merged_into[victim_idx] = primary_idx
                    merge_count += 1

        result = [f for idx, f in enumerate(findings) if idx not in merged_into]

        if merge_count:
            logger.info(
                "findings_deduplicated",
                original=len(findings),
                merged=merge_count,
                remaining=len(result),
            )

        return result, merge_count

    def _are_duplicates(self, a: dict[str, Any], b: dict[str, Any]) -> bool:
        """Determine if two findings are duplicates."""
        # Must be on the same host
        if a.get("host") != b.get("host"):
            return False

        # If both have ports, they must match
        port_a = a.get("port")
        port_b = b.get("port")
        if port_a is not None and port_b is not None and port_a != port_b:
            return False

        # Must come from different tools to be a cross-tool duplicate
        tool_a = a.get("tool_name", "")
        tool_b = b.get("tool_name", "")
        if tool_a and tool_b and tool_a == tool_b:
            return False

        # Title similarity check
        title_a = a.get("title", "")
        title_b = b.get("title", "")
        similarity = self._title_similarity(title_a, title_b)

        return similarity >= self._threshold

    def _title_similarity(self, a: str, b: str) -> float:
        """Compute normalised similarity between two finding titles."""
        if not a or not b:
            return 0.0

        # Normalize: lowercase, strip common prefixes
        a_norm = self._normalize_title(a)
        b_norm = self._normalize_title(b)

        # Check for substring containment first (fast path)
        if a_norm in b_norm or b_norm in a_norm:
            return 0.95

        return SequenceMatcher(None, a_norm, b_norm).ratio()

    def _normalize_title(self, title: str) -> str:
        """Normalize a title for comparison."""
        t = title.lower().strip()
        # Remove common prefixes
        for prefix in ("open port", "live host:", "subdomain discovered:"):
            if t.startswith(prefix):
                t = t[len(prefix):].strip()
        # Remove bracketed prefixes like "[template-id]"
        if t.startswith("[") and "]" in t:
            t = t[t.index("]") + 1:].strip()
        return t

    def _pick_primary(
        self, i: int, j: int, findings: list[dict[str, Any]]
    ) -> tuple[int, int]:
        """Return (primary_idx, victim_idx) — keep the richer finding."""
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sev_i = sev_order.get(findings[i].get("severity", "info"), 0)
        sev_j = sev_order.get(findings[j].get("severity", "info"), 0)

        # Higher severity wins
        if sev_i > sev_j:
            return i, j
        if sev_j > sev_i:
            return j, i

        # Longer description wins
        desc_i = len(findings[i].get("description") or "")
        desc_j = len(findings[j].get("description") or "")
        if desc_i >= desc_j:
            return i, j
        return j, i

    def _merge(self, primary: dict[str, Any], victim: dict[str, Any]) -> None:
        """Merge victim into primary, recording source tools."""
        # Combine source_tools
        primary_tools = primary.get("source_tools") or []
        if not primary_tools:
            tool = primary.get("tool_name", "unknown")
            primary_tools = [tool] if tool else []

        victim_tool = victim.get("tool_name", "")
        if victim_tool and victim_tool not in primary_tools:
            primary_tools.append(victim_tool)

        primary["source_tools"] = primary_tools
        primary["deduplicated"] = True

        # Merge description if victim has more detail
        if victim.get("description") and not primary.get("description"):
            primary["description"] = victim["description"]
