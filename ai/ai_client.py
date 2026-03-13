"""
ai/ai_client.py
================
Provider-isolated OpenAI client for ALR AI analysis.

Provider:    OpenAI
Credentials: OPENAI_API_KEY  (environment variable — never hardcoded)
Model:       OPENAI_MODEL    (environment variable, default: gpt-4o-mini)
Max tokens:  OPENAI_MAX_TOKENS or ALR_AI_MAX_TOKENS (default: 1500)
Timeout:     ALR_AI_TIMEOUT  (default: 60 s)

Retry policy: up to 2 retries on transient rate-limit / server errors
with simple bounded backoff (2 s, 4 s). Permanent errors raise immediately.

Install openai:  pip install openai
"""
from __future__ import annotations

import json
import os
import time
from typing import Optional

from utils.logger import get_logger
from ai.prompt_templates import SYSTEM_PROMPT, OUTPUT_SCHEMA_KEYS

logger = get_logger(__name__)

_MAX_RETRIES    = 2
_BACKOFF_BASE_S = 2   # seconds; doubles each retry


class AIClientError(Exception):
    """Raised when AI call fails and pipeline should fall back."""


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def call_openai(
    user_prompt: str,
    api_key: str,
    model: str,
    base_url: str = "",
    max_tokens: int = 1500,
    timeout: int = 60,
) -> dict:
    """
    Call the OpenAI chat completions endpoint with conservative settings.

    Retries up to _MAX_RETRIES times on rate-limit / server errors.
    All other errors raise AIClientError immediately.

    Returns
    -------
    dict  — validated AI response matching OUTPUT_SCHEMA_KEYS

    Raises
    ------
    AIClientError — caller must catch and fall back cleanly.
    """
    try:
        import openai  # type: ignore
    except ImportError:
        raise AIClientError(
            "openai package not installed — pip install openai"
        )

    client_kwargs: dict = {"api_key": api_key, "timeout": timeout}
    if base_url:
        client_kwargs["base_url"] = base_url

    logger.info(
        "AI: using OpenAI | model=%s | max_tokens=%d | timeout=%ds",
        model, max_tokens, timeout,
    )

    client = openai.OpenAI(**client_kwargs)

    last_exc: Optional[Exception] = None
    for attempt in range(1 + _MAX_RETRIES):
        try:
            response = client.chat.completions.create(
                model=model,
                max_tokens=max_tokens,
                temperature=0.2,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_prompt},
                ],
            )
            raw = response.choices[0].message.content or ""
            logger.debug("AI: response received, length=%d chars", len(raw))
            parsed = _parse_and_validate(raw)
            logger.info("AI: parsed successfully — %d fields", len(parsed))
            return parsed

        except openai.AuthenticationError as exc:
            # Authentication failures are permanent — do not retry
            raise AIClientError(
                "OpenAI authentication failed — check OPENAI_API_KEY"
            ) from exc

        except (openai.RateLimitError, openai.APIStatusError) as exc:
            last_exc = exc
            if attempt < _MAX_RETRIES:
                wait = _BACKOFF_BASE_S * (2 ** attempt)
                logger.warning(
                    "AI: rate-limit / server error (attempt %d/%d) — "
                    "retrying in %ds: %s",
                    attempt + 1, 1 + _MAX_RETRIES, wait, exc,
                )
                time.sleep(wait)
            continue

        except openai.APITimeoutError as exc:
            raise AIClientError(
                "OpenAI request timed out after " + str(timeout) + "s"
            ) from exc

        except AIClientError:
            raise

        except Exception as exc:
            raise AIClientError("OpenAI call failed: " + str(exc)) from exc

    raise AIClientError(
        "OpenAI call failed after " + str(1 + _MAX_RETRIES) +
        " attempts: " + str(last_exc)
    )


def _parse_and_validate(raw: str) -> dict:
    """
    Parse AI JSON response and validate required fields.
    Strips accidental markdown fences before parsing.
    Raises AIClientError if the response is not usable.
    """
    text = raw.strip()

    # Strip ``` fences the model might add despite instructions
    if text.startswith("```"):
        text = "\n".join(
            l for l in text.splitlines()
            if not l.strip().startswith("```")
        ).strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AIClientError(
            "AI response is not valid JSON: " + str(exc) +
            " | raw (first 300): " + text[:300]
        ) from exc

    if not isinstance(parsed, dict):
        raise AIClientError("AI response is not a JSON object")

    # Ensure all expected keys with safe defaults
    result: dict = {}
    for key in OUTPUT_SCHEMA_KEYS:
        val = parsed.get(key)
        if key == "executive_summary":
            result[key] = str(val) if val else ""
        else:
            result[key] = val if isinstance(val, list) else []

    return result


def resolve_ai_config() -> tuple[str, str, str, int, int]:
    """
    Resolve all OpenAI settings from environment.

    Returns (api_key, model, base_url, max_tokens, timeout).

    Config env vars (in priority order for each setting):
      OPENAI_API_KEY
      OPENAI_MODEL         (default: gpt-4o-mini)
      OPENAI_BASE_URL      (default: "")
      OPENAI_MAX_TOKENS    (default: 1500; also reads ALR_AI_MAX_TOKENS)
      ALR_AI_TIMEOUT       (default: 60)
    """
    api_key    = os.getenv("OPENAI_API_KEY", "")
    model      = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    base_url   = os.getenv("OPENAI_BASE_URL", "")
    max_tokens = int(
        os.getenv("OPENAI_MAX_TOKENS") or os.getenv("ALR_AI_MAX_TOKENS", "1500")
    )
    timeout    = int(os.getenv("ALR_AI_TIMEOUT", "60"))

    logger.debug(
        "AI config: model=%s max_tokens=%d timeout=%ds base_url=%s",
        model, max_tokens, timeout, base_url or "(default OpenAI)",
    )
    return api_key, model, base_url, max_tokens, timeout
