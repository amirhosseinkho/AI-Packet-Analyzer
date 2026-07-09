from __future__ import annotations

from typing import Optional

import httpx

from app.config import get_settings
from app.llm.providers.base import BaseLLMProvider
from app.logger import get_logger

log = get_logger(__name__)
settings = get_settings()


class OllamaProvider(BaseLLMProvider):
    """LLM provider backed by a local Ollama instance."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        self._base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self._model = model or settings.llm_model
        self._timeout = timeout

    @property
    def name(self) -> str:
        return "ollama"

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

        payload = {
            "model": self._model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                response = await client.post(f"{self._base_url}/api/chat", json=payload)
                response.raise_for_status()
                data = response.json()
                return data["message"]["content"].strip()
            except httpx.HTTPStatusError as exc:
                log.error("Ollama HTTP error", status=exc.response.status_code, error=str(exc))
                raise
            except Exception as exc:
                log.error("Ollama request failed", error=str(exc))
                raise

    async def health_check(self) -> bool:
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                r = await client.get(f"{self._base_url}/api/tags")
                return r.status_code == 200
            except Exception:
                return False
