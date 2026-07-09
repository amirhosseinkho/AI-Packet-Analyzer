from __future__ import annotations

from typing import Optional

from app.llm.providers.base import BaseLLMProvider


class MockProvider(BaseLLMProvider):
    """Deterministic provider used in tests — no network calls."""

    @property
    def name(self) -> str:
        return "mock"

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 512,
    ) -> str:
        return "Mock LLM explanation: Normal network traffic detected."

    async def health_check(self) -> bool:
        return True
