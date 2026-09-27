"""Application settings loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    openai_api_key: str | None
    openai_model: str
    nvd_api_key: str | None
    request_timeout_seconds: int = 20
    max_retries: int = 3


def load_settings() -> Settings:
    """Load .env once and return typed application settings."""
    load_dotenv()
    return Settings(
        openai_api_key=os.getenv("OPENAI_API_KEY") or None,
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        nvd_api_key=os.getenv("NVD_API_KEY") or None,
    )
