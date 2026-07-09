from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class BaseLLMProvider(ABC):
    """Abstract contract for LLM providers."""

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 512,
    ) -> str:
        """Return a completion string for the given prompt."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the provider is reachable."""
        ...

    @property
    @abstractmethod
    def name(self) -> str: ...
