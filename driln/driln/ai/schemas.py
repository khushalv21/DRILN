"""Structured AI output schemas.

These Pydantic models define the *exact* shape of AI responses.  The AI
provider is instructed to return JSON matching these schemas instead of
free-form prose.  This makes downstream processing deterministic and
machine-readable.

The schemas are embedded in the system prompt and optionally enforced via
the OpenAI ``response_format`` parameter.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AIFindingAnalysis(BaseModel):
    """AI analysis of a single finding."""

    finding_title: str = Field(..., description="Title of the finding being analyzed")
    exploitability: str = Field(
        ...,
        description="How easy to exploit",
        pattern=r"^(trivial|moderate|difficult|theoretical)$",
    )
    real_world_risk: str = Field(
        ...,
        description="Actual risk level considering context",
        pattern=r"^(critical|high|medium|low|informational)$",
    )
    false_positive_likelihood: float = Field(
        0.0, ge=0.0, le=1.0, description="Probability this is a false positive"
    )
    context: str = Field(
        ..., description="Why this finding matters for this specific target"
    )
    remediation: str = Field(..., description="Specific remediation steps")


class AIAttackPath(BaseModel):
    """A potential attack chain identified by AI analysis."""

    name: str = Field(..., description="Human-readable attack path name")
    steps: list[str] = Field(
        ..., description="Ordered list of attack steps"
    )
    finding_titles: list[str] = Field(
        ..., description="Finding titles involved in this path"
    )
    likelihood: str = Field(
        ..., pattern=r"^(high|medium|low)$"
    )
    impact: str = Field(
        ...,
        description="Potential impact",
        pattern=r"^(full_compromise|data_access|dos|info_leak|lateral_movement)$",
    )


class AIRecommendation(BaseModel):
    """AI-generated next-step recommendation."""

    priority: str = Field(
        ..., pattern=r"^(critical|high|medium|low)$"
    )
    title: str = Field(..., description="Short action title")
    rationale: str = Field(..., description="Why this action is recommended")
    tool_name: str | None = Field(
        None, description="Suggested tool to run, or null if manual"
    )
    tool_config: dict | None = Field(
        None, description="Suggested tool configuration"
    )


class AIStructuredAnalysis(BaseModel):
    """Complete structured AI analysis output.

    This replaces free-form prose analysis.  The AI provider is instructed
    to return JSON matching this schema exactly.
    """

    executive_summary: str = Field(
        ..., description="2-3 sentence executive summary of security posture"
    )
    overall_risk: str = Field(
        ...,
        description="Overall risk rating",
        pattern=r"^(critical|high|medium|low|clean)$",
    )
    risk_score: int = Field(
        ..., ge=0, le=100, description="Numeric risk score 0-100"
    )
    critical_findings: list[AIFindingAnalysis] = Field(
        default_factory=list,
        description="Analysis of the most important findings",
    )
    attack_paths: list[AIAttackPath] = Field(
        default_factory=list,
        description="Potential attack chains",
    )
    recommendations: list[AIRecommendation] = Field(
        default_factory=list,
        description="Recommended next steps",
    )
    false_positive_flags: list[str] = Field(
        default_factory=list,
        description="Finding titles that are likely false positives",
    )
    quick_wins: list[str] = Field(
        default_factory=list,
        description="Finding titles that are easy to fix",
    )

    @staticmethod
    def to_json_schema() -> str:
        """Return the JSON schema string for prompt injection."""
        import json

        return json.dumps(AIStructuredAnalysis.model_json_schema(), indent=2)
