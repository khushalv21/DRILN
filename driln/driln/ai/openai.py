"""OpenAI-compatible AI provider.

Works with any API that implements the OpenAI chat completions endpoint:
OpenAI, Azure OpenAI, OpenRouter, Ollama (``/v1``), vLLM, LM Studio, etc.

Set ``DRILN_AI_BASE_URL`` to point at a local or alternative endpoint.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from driln.ai.base import AIResponse, BaseAIProvider
from driln.ai.prompts import SYSTEM_PROMPT, build_analysis_prompt, build_structured_prompt
from driln.ai.schemas import AIStructuredAnalysis
from driln.core.config import get_settings
from driln.core.exceptions import AIConnectionError, AIResponseError

logger = structlog.get_logger()

_DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAIProvider(BaseAIProvider):
    """OpenAI-compatible chat completions provider."""

    name = "openai"

    def __init__(self) -> None:
        settings = get_settings()
        self._model = settings.ai_model
        self._temperature = settings.ai_temperature
        self._max_tokens = settings.ai_max_tokens
        self._base_url = (settings.ai_base_url or _DEFAULT_BASE_URL).rstrip("/")

        api_key = settings.ai_api_key
        self._api_key = api_key.get_secret_value() if api_key else ""

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=httpx.Timeout(120.0, connect=10.0),
        )

    async def complete(
        self,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> AIResponse:
        """Send a chat completion request to the OpenAI-compatible API."""
        payload = {
            "model": kwargs.get("model", self._model),
            "messages": messages,
            "temperature": kwargs.get("temperature", self._temperature),
            "max_tokens": kwargs.get("max_tokens", self._max_tokens),
        }

        # Support response_format if requested
        if "response_format" in kwargs:
            payload["response_format"] = kwargs["response_format"]

        try:
            response = await self._client.post("/chat/completions", json=payload)
        except httpx.ConnectError as exc:
            raise AIConnectionError(
                f"Cannot connect to AI provider at {self._base_url}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise AIConnectionError("AI provider request timed out") from exc

        if response.status_code != 200:
            raise AIResponseError(
                f"AI provider returned {response.status_code}: {response.text[:500]}"
            )

        try:
            data = response.json()
        except json.JSONDecodeError as exc:
            raise AIResponseError("AI provider returned non-JSON response") from exc

        # Extract response
        choices = data.get("choices", [])
        if not choices:
            raise AIResponseError("AI provider returned empty choices")

        content = choices[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})

        logger.info(
            "ai_completion",
            model=data.get("model", self._model),
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
        )

        return AIResponse(
            content=content,
            model=data.get("model", self._model),
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            raw_response=data,
        )

    async def analyze_scan(self, scan_data: dict[str, Any]) -> str:
        """Analyze scan results using the system prompt + analysis template."""
        if not self._api_key:
            return "_AI analysis unavailable — set DRILN_AI_API_KEY to enable._"

        user_prompt = build_analysis_prompt(scan_data)

        response = await self.complete([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ])

        return response.content

    async def structured_analyze(
        self, scan_data: dict[str, Any]
    ) -> AIStructuredAnalysis:
        """Request structured JSON analysis with validation.

        Strategy:
        1. Try ``response_format: {type: "json_object"}`` (OpenAI native)
        2. Fall back to prompt engineering + JSON extraction
        3. Validate against ``AIStructuredAnalysis`` Pydantic schema
        """
        system_prompt, user_prompt = build_structured_prompt(scan_data)

        # Attempt 1: native JSON mode
        try:
            response = await self.complete(
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
            )
            parsed = json.loads(response.content)
            return AIStructuredAnalysis.model_validate(parsed)
        except (json.JSONDecodeError, Exception) as exc:
            logger.debug("structured_json_mode_failed", error=str(exc))

        # Attempt 2: prompt engineering fallback (no response_format)
        try:
            response = await self.complete([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ])
            json_str = self._extract_json(response.content)
            parsed = json.loads(json_str)
            return AIStructuredAnalysis.model_validate(parsed)
        except (json.JSONDecodeError, Exception) as exc:
            logger.warning("structured_analysis_parse_failed", error=str(exc))

        # Final fallback: wrap prose analysis
        return await super().structured_analyze(scan_data)

    def _extract_json(self, text: str) -> str:
        """Extract JSON from LLM response that might contain markdown fences."""
        import re

        # Try to find JSON in code blocks first
        match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if match:
            return match.group(1).strip()

        # Try to find raw JSON object
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return match.group(0)

        return text

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
