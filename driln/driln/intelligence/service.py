"""Intelligence service — central orchestrator.

Runs the full intelligence pipeline in order:

1. Technology aggregation
2. Finding deduplication
3. Finding correlation
4. Risk scoring
5. Recommendation generation

Called by the scanner after each tool completes (incremental) or by the
API/CLI for a full analysis of a completed scan.
"""

from __future__ import annotations

import structlog

from driln.intelligence.context import ScanContext
from driln.intelligence.correlator import FindingCorrelator
from driln.intelligence.dedup import FindingDeduplicator
from driln.intelligence.recommendations import RecommendationEngine
from driln.intelligence.risk import RiskScorer
from driln.intelligence.tech import TechAggregator
from driln.schemas.intelligence import RecommendationOut, ScanIntelligence
from driln.tools.base import ToolResult

logger = structlog.get_logger()


class IntelligenceService:
    """Central orchestrator for all intelligence processing.

    Stateless — each call receives a :class:`ScanContext` and returns
    a :class:`ScanIntelligence` report.
    """

    def __init__(self) -> None:
        self._tech = TechAggregator()
        self._correlator = FindingCorrelator()
        self._dedup = FindingDeduplicator()
        self._risk = RiskScorer()
        self._recommendations = RecommendationEngine()

    async def analyze(self, context: ScanContext) -> ScanIntelligence:
        """Run the full intelligence pipeline on the current context.

        This is the main entry point.  It can be called multiple times
        as the context grows (incremental analysis).
        """
        # 1. Aggregate technologies
        tech_profile = self._tech.aggregate(context)
        logger.debug(
            "intel_tech_aggregated",
            scan_id=context.scan_id,
            tech_count=len(tech_profile.technologies),
        )

        # 2. Deduplicate findings
        deduped, merge_count = self._dedup.deduplicate(list(context.findings))
        logger.debug(
            "intel_dedup_complete",
            scan_id=context.scan_id,
            original=len(context.findings),
            merged=merge_count,
        )

        # 3. Correlate findings
        correlations = self._correlator.correlate(deduped, tech_profile)
        logger.debug(
            "intel_correlation_complete",
            scan_id=context.scan_id,
            groups=len(correlations),
        )

        # 4. Score risk per finding
        finding_scores: dict[str, float] = {}
        for f in deduped:
            score = self._risk.score_finding(f, context)
            fid = f.get("id", "")
            if fid:
                finding_scores[fid] = score.score

        # 5. Aggregate scan-level risk
        scan_risk = self._risk.score_scan(deduped, context)
        logger.info(
            "intel_risk_scored",
            scan_id=context.scan_id,
            scan_risk=scan_risk.score,
            label=scan_risk.label,
        )

        # 6. Generate recommendations
        rule_recs = self._recommendations.generate(context, tech_profile)
        recommendations = [
            RecommendationOut(
                id="",  # Will be assigned when persisted
                priority=r.priority,
                category=r.category,
                title=r.title,
                rationale=r.rationale,
                tool_name=r.tool_name,
                tool_config=r.tool_config,
                source="rule_engine",
            )
            for r in rule_recs
        ]
        logger.info(
            "intel_recommendations",
            scan_id=context.scan_id,
            count=len(recommendations),
        )

        return ScanIntelligence(
            scan_id=context.scan_id,
            tech_profile=tech_profile,
            risk_summary=scan_risk,
            correlation_groups=correlations,
            recommendations=recommendations,
            deduplicated_count=merge_count,
            enriched_count=len(deduped),
            finding_risk_scores=finding_scores,
        )

    async def analyze_incremental(
        self,
        context: ScanContext,
        new_result: ToolResult,
    ) -> ScanIntelligence:
        """Update context with a new tool result and re-analyze.

        Called by the scanner after each tool completes.
        """
        context.add_tool_result(new_result)
        logger.debug(
            "intel_incremental",
            scan_id=context.scan_id,
            tool=new_result.tool_name,
            new_findings=len(new_result.findings),
        )
        return await self.analyze(context)
