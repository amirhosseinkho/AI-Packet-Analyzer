from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ────────────────────────────────────────────────────────────
    app_env: Literal["development", "testing", "production"] = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    secret_key: str = "insecure-dev-key"
    log_level: str = "INFO"

    # ── Database ───────────────────────────────────────────────────────────────
    database_url: str = Field(
        default="postgresql+asyncpg://analyzer:analyzer_secret@localhost:5432/packet_analyzer"
    )

    # ── Capture ────────────────────────────────────────────────────────────────
    capture_interface: str = "eth0"
    capture_filter: str = ""
    capture_buffer_size: int = 65536
    capture_batch_size: int = 100

    # ── AI ────────────────────────────────────────────────────────────────────
    isolation_forest_contamination: float = 0.05
    autoencoder_epochs: int = 50
    autoencoder_batch_size: int = 64
    autoencoder_hidden_dim: int = 32
    model_save_path: Path = Path("./models")

    # ── LLM ───────────────────────────────────────────────────────────────────
    llm_provider: Literal["ollama", "openai", "mock"] = "ollama"
    llm_model: str = "llama3.2"
    llm_temperature: float = 0.3
    llm_max_tokens: int = 512
    ollama_base_url: str = "http://localhost:11434"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    # ── Reporting ─────────────────────────────────────────────────────────────
    report_output_dir: Path = Path("./reports")

    @field_validator("model_save_path", "report_output_dir", mode="before")
    @classmethod
    def _ensure_path(cls, v: str | Path) -> Path:
        p = Path(v)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def is_testing(self) -> bool:
        return self.app_env == "testing"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
