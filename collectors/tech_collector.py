"""
collectors/tech_collector.py
=============================
Technology stack detection — heuristic only (HTTP metadata based).

wappalyzer has been removed from the MVP pipeline.
Detection is based solely on HTTP response headers and page titles
collected by httpx. Results are labeled "heuristic" to reflect this.

data_source values:
  "heuristic"  — derived from real httpx HTTP metadata
  "disabled"   — no HTTP profile available to derive from
"""
from __future__ import annotations

import re
from pathlib import Path
import json
from typing import Optional

from models.schema import HTTPProfile, TechDetection, TechProfile, TargetContext
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Header/title signature map for heuristic detection
# ---------------------------------------------------------------------------
_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    # (field, pattern, tech_name)
    ("server",       r"nginx",            "Nginx"),
    ("server",       r"apache",           "Apache"),
    ("server",       r"iis",              "Microsoft IIS"),
    ("server",       r"cloudflare",       "Cloudflare"),
    ("server",       r"litespeed",        "LiteSpeed"),
    ("server",       r"openresty",        "OpenResty"),
    ("server",       r"tomcat",           "Apache Tomcat"),
    ("content_type", r"application/json", "REST API (JSON)"),
    ("tech",         r"wordpress",        "WordPress"),
    ("tech",         r"drupal",           "Drupal"),
    ("tech",         r"joomla",           "Joomla"),
    ("tech",         r"react",            "React"),
    ("tech",         r"angular",          "Angular"),
    ("tech",         r"vue",              "Vue.js"),
    ("tech",         r"jquery",           "jQuery"),
    ("tech",         r"bootstrap",        "Bootstrap"),
    ("tech",         r"php",              "PHP"),
    ("tech",         r"asp\.net",         "ASP.NET"),
    ("tech",         r"django",           "Django"),
    ("tech",         r"rails",            "Ruby on Rails"),
    ("tech",         r"laravel",          "Laravel"),
    ("tech",         r"spring",           "Spring Framework"),
    ("title",        r"gitlab",           "GitLab"),
    ("title",        r"jenkins",          "Jenkins"),
    ("title",        r"jira",             "Jira"),
    ("title",        r"confluence",       "Confluence"),
    ("title",        r"grafana",          "Grafana"),
    ("title",        r"kibana",           "Kibana"),
    ("title",        r"phpmyadmin",       "phpMyAdmin"),
    ("title",        r"adminer",          "Adminer"),
    ("title",        r"sonarqube",        "SonarQube"),
    ("title",        r"swagger",          "Swagger / OpenAPI"),
]


def _heuristic_detection(http_profile: HTTPProfile) -> list[TechDetection]:
    """
    Derive technology hints from real httpx HTTP response metadata.
    Confidence is conservative (0.6) — not confirmed by fingerprint tools.
    """
    detections: dict[str, TechDetection] = {}

    for asset in http_profile.assets:
        asset_dict = {
            "server":       (asset.server or "").lower(),
            "content_type": (asset.content_type or "").lower(),
            "title":        (asset.title or "").lower(),
            "tech":         " ".join(asset.tech).lower() if asset.tech else "",
        }
        for field, pattern, tech_name in _HEADER_SIGNATURES:
            val = asset_dict.get(field, "")
            if val and re.search(pattern, val, re.IGNORECASE):
                if tech_name not in detections:
                    detections[tech_name] = TechDetection(
                        name=tech_name,
                        confidence=0.6,
                        category="heuristic",
                    )

    return list(detections.values())


def collect_tech(
    ctx: TargetContext,
    http_profile: Optional[HTTPProfile] = None,
) -> TechProfile:
    """
    Heuristic tech stack detection from real HTTP metadata.

    No external tool required. Results labeled as "heuristic".
    If no HTTP profile is available, returns empty profile labeled "disabled".

    Parameters
    ----------
    ctx : TargetContext
    http_profile : HTTPProfile, optional
        Real HTTP asset data collected by httpx collector.
    """
    target = ctx.domain or ctx.raw_input
    profile = TechProfile(target=target)

    if not http_profile or not http_profile.assets:
        logger.info("Tech detection: no HTTP profile available — disabled")
        profile.data_source = "disabled"
        profile.raw_output  = "NO_HTTP_PROFILE"
    else:
        profile.detections = _heuristic_detection(http_profile)
        profile.data_source = "heuristic"
        profile.raw_output  = "HEURISTIC_FROM_HTTP"
        logger.info(
            "Tech detection: %d hints (heuristic from HTTP metadata) for %s",
            len(profile.detections), target,
        )

    norm_file = Path(ctx.output_dir) / "tech_normalized.json"
    norm_file.write_text(json.dumps(
        {"data_source": profile.data_source,
         "note": "heuristic detection only — derived from HTTP response metadata",
         "detections": [t.model_dump() for t in profile.detections]},
        indent=2,
    ))
    return profile
