"""
config/settings.py
==================
ALR configuration — all values sourced from environment variables.

Load order:
  1. python-dotenv loads .env (override=True so .env values win over shell)
  2. os.getenv() reads the merged environment

Precedence: .env values > shell environment values > hardcoded defaults.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv_safe() -> None:
    """
    Load .env using python-dotenv if available (preferred),
    falling back to a minimal stdlib parser.

    override=True ensures .env values take effect even if the shell
    already has these variables set (predictable local dev behavior).
    """
    env_file = Path(".env")
    if not env_file.exists():
        return

    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv(dotenv_path=env_file, override=True)
        return
    except ImportError:
        pass

    # Minimal stdlib fallback (no override — conservative)
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key   = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ[key] = value  # override=True equivalent


# Load .env at import time — must happen before any os.getenv calls
_load_dotenv_safe()


@dataclass
class Settings:
    """
    Central configuration for ALR.

    All values are read from environment variables after .env is loaded.
    Environment variable names are the canonical source of truth.
    """

    # ---- GitHub ----
    github_token: str = field(
        default_factory=lambda: os.getenv("GITHUB_TOKEN", "")
    )

    # ---- Paths ----
    output_base_dir: str = field(
        default_factory=lambda: os.getenv("ALR_OUTPUT_DIR", "data/outputs")
    )

    # ---- Tool binary paths (override if not on PATH) ----
    subfinder_bin: str = field(
        default_factory=lambda: os.getenv("SUBFINDER_BIN", "subfinder")
    )
    httpx_bin: str = field(
        default_factory=lambda: os.getenv("HTTPX_BIN", "httpx")
    )
    dnsx_bin: str = field(
        default_factory=lambda: os.getenv("DNSX_BIN", "dnsx")
    )
    naabu_bin: str = field(
        default_factory=lambda: os.getenv("NAABU_BIN", "naabu")
    )

    # ---- Scan behaviour ----
    default_timeout: int = field(
        default_factory=lambda: int(os.getenv("ALR_TIMEOUT", "60"))
    )

    # ---- OpenAI AI layer (optional — requires --enable-ai flag) ----
    openai_api_key: str = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", "")
    )
    openai_model: str = field(
        default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    )
    openai_base_url: str = field(
        default_factory=lambda: os.getenv("OPENAI_BASE_URL", "")
    )
    # Token budget: OPENAI_MAX_TOKENS is the canonical env var name
    ai_max_tokens: int = field(
        default_factory=lambda: int(
            os.getenv("OPENAI_MAX_TOKENS") or os.getenv("ALR_AI_MAX_TOKENS", "1500")
        )
    )
    ai_timeout: int = field(
        default_factory=lambda: int(os.getenv("ALR_AI_TIMEOUT", "60"))
    )

    @classmethod
    def load(cls) -> "Settings":
        """
        Instantiate Settings — .env is already loaded at module import time.
        Calling load() again refreshes values from the current environment.
        """
        return cls()


# Global singleton — created after .env is loaded
settings = Settings.load()
