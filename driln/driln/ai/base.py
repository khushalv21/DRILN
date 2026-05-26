"""Base AI provider abstraction.

Every AI/LLM backend inherits from :class:`BaseAIProvider` and implements
the ``complete`` and ``analyze_scan`` methods.  This allows the framework
to swap providers (OpenAI, Anthropic, local models) without touching
business logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AIResponse:
    """Structured response from an AI provider."""

    content: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)
    raw_response: dict[str, Any] | None = None

    @property
    def total_tokens(self) -> int:
        return self.usage.get("prompt_tokens", 0) + self.usage.get("completion_tokens", 0)


class BaseAIProvider(ABC):
    """Abstract base class for AI/LLM providers.

    Subclass contract:
        1. Set ``name`` class attribute.
        2. Implement ``complete(messages, **kwargs) -> AIResponse``.
        3. Implement ``analyze_scan(scan_data) -> str``.
    """

    name: str = ""

    @abstractmethod
    async def complete(
        self,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> AIResponse:
        """Send a chat completion request.

        Args:
            messages: OpenAI-format messages list
                ``[{"role": "system", "content": "..."}, ...]``
            **kwargs: Provider-specific overrides (temperature, max_tokens, etc.)

        Returns:
            Structured AI response.
        """
        ...

    @abstractmethod
    async def analyze_scan(self, scan_data: dict[str, Any]) -> str:
        """Analyze scan results and return a human-readable summary.

        Args:
            scan_data: Aggregated scan results including tool outputs and findings.

        Returns:
            AI-generated analysis text.
        """
        ...

    async def structured_analyze(
        self, scan_data: dict[str, Any]
    ) -> "AIStructuredAnalysis":
        """Analyze scan results and return structured JSON output.

        Default implementation calls :meth:`analyze_scan` and wraps the
        prose result in a minimal :class:`AIStructuredAnalysis`.
        Subclasses can override to request true JSON mode from the API.

        Returns:
            Parsed and validated structured analysis.
        """
        from driln.ai.schemas import AIStructuredAnalysis

        # Fallback: wrap prose in a minimal structured envelope
        prose = await self.analyze_scan(scan_data)
        return AIStructuredAnalysis(
            executive_summary=prose[:500] if prose else "Analysis unavailable.",
            overall_risk="medium",
            risk_score=50,
            critical_findings=[],
            attack_paths=[],
            recommendations=[],
            false_positive_flags=[],
            quick_wins=[],
        )

    async def health_check(self) -> bool:
        """Verify the provider is reachable.  Default: try a minimal completion."""
        try:
            resp = await self.complete(
                [{"role": "user", "content": "ping"}],
                max_tokens=5,
            )
            return bool(resp.content)
        except Exception:
            return False
