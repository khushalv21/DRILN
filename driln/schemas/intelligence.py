"""Intelligence-related Pydantic schemas.

These models define the structured outputs of the intelligence layer:
technology fingerprinting, risk scoring, finding correlation, and
next-step recommendations.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Technology Fingerprinting ───────────────────────────────────


class TechFingerprint(BaseModel):
    """Single technology detection from one or more tools."""

    name: str = Field(..., description="Technology name, e.g. 'wordpress'")
    version: str | None = Field(None, description="Detected version, e.g. '6.4'")
    category: str = Field(
        ...,
        description="Technology category",
        pattern=r"^(cms|server|framework|language|cdn|waf|database|os|library|other)$",
    )
    confidence: float = Field(
        1.0, ge=0.0, le=1.0, description="Detection confidence (0.0-1.0)"
    )
    sources: list[str] = Field(
        default_factory=list, description="Tools that detected this"
    )


class TechProfile(BaseModel):
    """Aggregated technology profile for a scan target."""

    technologies: list[TechFingerprint] = Field(default_factory=list)
    servers: list[str] = Field(
        default_factory=list, description="Web/app servers detected"
    )
    frameworks: list[str] = Field(
        default_factory=list, description="CMS/frameworks detected"
    )
    languages: list[str] = Field(
        default_factory=list, description="Programming languages detected"
    )
    os_hints: list[str] = Field(
        default_factory=list, description="OS detection hints"
    )

    @property
    def has_cms(self) -> bool:
        return any(t.category == "cms" for t in self.technologies)

    @property
    def cms_names(self) -> list[str]:
        return [t.name for t in self.technologies if t.category == "cms"]


# ── Risk Scoring ────────────────────────────────────────────────


class RiskScore(BaseModel):
    """Composite risk score for a finding or an entire scan."""

    score: float = Field(..., ge=0.0, le=100.0, description="Composite score 0-100")
    base_severity: float = Field(
        ..., ge=0.0, le=1.0, description="Normalized base severity"
    )
    exploitability: float = Field(
        ..., ge=0.0, le=1.0, description="How easy to exploit"
    )
    exposure: float = Field(
        ..., ge=0.0, le=1.0, description="Exposure factor (internet-facing, etc.)"
    )
    context_boost: float = Field(
        ..., ge=0.0, le=1.0, description="Boost from correlated context"
    )
    label: str = Field(
        ..., description="Human-readable label: critical/high/medium/low/informational"
    )


# ── Finding Correlation ─────────────────────────────────────────


class CorrelationGroup(BaseModel):
    """Group of related findings from different tools."""

    group_id: str
    finding_ids: list[str] = Field(..., description="IDs of correlated findings")
    relationship: str = Field(
        ...,
        description="Correlation type",
        pattern=r"^(same_service|attack_chain|tech_overlap|same_host)$",
    )
    summary: str = Field(..., description="Human-readable summary of the correlation")
    combined_risk: float = Field(
        0.0, ge=0.0, le=100.0, description="Combined risk score of the group"
    )


# ── Recommendations ─────────────────────────────────────────────


class RecommendationOut(BaseModel):
    """API output for a recommendation."""

    id: str
    priority: str
    category: str
    title: str
    rationale: str
    tool_name: str | None = None
    tool_config: dict | None = None
    source: str
    accepted: bool | None = None
    triggered_by: list[str] | None = None

    model_config = {"from_attributes": True}


# ── Scan Intelligence Aggregate ─────────────────────────────────


class ScanIntelligence(BaseModel):
    """Full intelligence report for a scan — output of IntelligenceService."""

    scan_id: str
    tech_profile: TechProfile
    risk_summary: RiskScore
    correlation_groups: list[CorrelationGroup] = Field(default_factory=list)
    recommendations: list[RecommendationOut] = Field(default_factory=list)
    deduplicated_count: int = Field(0, description="Number of findings merged")
    enriched_count: int = Field(0, description="Number of findings after dedup")
    finding_risk_scores: dict[str, float] = Field(
        default_factory=dict, description="finding_id → risk_score"
    )
