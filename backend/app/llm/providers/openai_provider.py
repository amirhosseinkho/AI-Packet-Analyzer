from __future__ import annotations

from typing import Optional

from app.config import get_settings
from app.llm.providers.base import BaseLLMProvider
from app.logger import get_logger

log = get_logger(__name__)
settings = get_settings()


class OpenAIProvider(BaseLLMProvider):
    """LLM provider backed by the OpenAI API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:
            raise ImportError("openai package is required: pip install openai") from exc

        from openai import AsyncOpenAI

        self._client = AsyncOpenAI(api_key=api_key or settings.openai_api_key or None)
        self._model = model or settings.openai_model

    @property
    def name(self) -> str:
        return "openai"

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 512,
    ) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                messages=messages,  # type: ignore[arg-type]
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            log.error("OpenAI request failed", error=str(exc))
            raise

    async def health_check(self) -> bool:
        try:
            await self._client.models.list()
            return True
        except Exception:
            return False
