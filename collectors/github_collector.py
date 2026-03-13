"""
collectors/github_collector.py
===============================
GitHub public exposure check — pluggable stub module.

Currently operates as an informed stub that returns placeholder results.
To enable live querying, set GITHUB_TOKEN in .env and implement
the search API calls in `_query_github_search()`.

IMPORTANT: This module only checks PUBLIC repositories.
It does NOT clone, extract, or store any code.
All results are hints requiring manual validation.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from models.schema import GitHubExposure, GitHubHit, TargetContext
from utils.logger import get_logger

logger = get_logger(__name__)

# Keywords that indicate possible credential / config exposure
_EXPOSURE_KEYWORDS = [
    "password", "passwd", "secret", "api_key", "apikey",
    "token", "private_key", "aws_access", "db_password",
    ".env", "config.yml", "database.yml",
]


def _query_github_search(domain: str, token: str) -> list[GitHubHit]:
    """
    LIVE implementation placeholder.

    To activate:
    1. pip install PyGithub
    2. Replace this stub with real API calls using:
       - github.Github(token).search_code(f'"{domain}"')
    3. Respect rate limits: authenticated = 30 req/min

    Parameters
    ----------
    domain : str
        Target domain to search for in public GitHub code.
    token : str
        GitHub personal access token.

    Returns
    -------
    list[GitHubHit]
        List of exposure hints found.
    """
    logger.info("GitHub live search not yet implemented — returning empty results")
    # Placeholder — implement with PyGithub or requests + GitHub API v3
    return []


def _mock_github_hits(domain: str) -> list[GitHubHit]:
    """Synthetic GitHub exposure hints for demonstration."""
    return [
        GitHubHit(
            repo=f"some-user/{domain.split('.')[0]}-infra",
            file_path="config/database.yml",
            snippet=f"# hostname: db.{domain}",
            hint_type="config_hint",
        ),
        GitHubHit(
            repo=f"contractor-xyz/deployment-scripts",
            file_path=".env.example",
            snippet=f"API_BASE_URL=https://api.{domain}",
            hint_type="endpoint_hint",
        ),
    ]


def collect_github_exposure(ctx: TargetContext) -> GitHubExposure:
    """
    Check for public GitHub exposure hints for the target domain.

    Parameters
    ----------
    ctx : TargetContext
        Active run context. ``enable_github`` must be True.
    """
    target = ctx.domain or ctx.raw_input
    exposure = GitHubExposure(target=target)

    if not ctx.enable_github:
        logger.info("GitHub check disabled — skipping")
        exposure.note = "GitHub check disabled (use --enable-github-check to enable)"
        return exposure

    github_token = os.getenv("GITHUB_TOKEN", "")

    if github_token:
        logger.info("GitHub token found — attempting live search for %s", target)
        hits = _query_github_search(target, github_token)
        exposure.queried = True
    else:
        logger.warning(
            "No GITHUB_TOKEN set — GitHub check uses mock/stub data. "
            "Set GITHUB_TOKEN in .env for live results."
        )
        hits = _mock_github_hits(target)
        exposure.queried = False
        exposure.note = "Mock data — set GITHUB_TOKEN for live results. Manual validation required."

    exposure.hits = hits
    logger.info("GitHub exposure: %d hints found for %s", len(hits), target)

    norm_file = Path(ctx.output_dir) / "github_normalized.json"
    norm_file.write_text(
        json.dumps(
            {
                "target": target,
                "queried": exposure.queried,
                "note": exposure.note,
                "hits": [h.model_dump() for h in hits],
            },
            indent=2,
        )
    )

    return exposure
