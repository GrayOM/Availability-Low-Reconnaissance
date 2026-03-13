"""
collectors/http_collector.py
=============================
HTTP asset profiling using httpx. Returns data_source: "httpx" | "mock" | "missing"
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
from models.schema import HTTPAsset, HTTPProfile, SubdomainResult, TargetContext
from utils.logger import get_logger
from utils.subprocess_runner import run_tool

logger = get_logger(__name__)

_MOCK_MAP = {
    "admin":   (200, "Admin Panel",      "nginx/1.18"),
    "api":     (200, "API Gateway",      "Apache/2.4"),
    "dev":     (200, "Dev Environment",  "Werkzeug/2.0"),
    "staging": (200, "Staging Site",     "nginx/1.20"),
    "mail":    (200, "Webmail",          "Apache/2.4"),
    "vpn":     (200, "VPN Portal",       None),
    "git":     (200, "GitLab",           "nginx"),
    "www":     (200, "Corporate Site",   "cloudflare"),
}


def _mock_http_assets(url_list: list) -> list:
    result = []
    for url in url_list[:8]:
        prefix = url.replace("https://", "").replace("http://", "").split(".")[0]
        defaults = _MOCK_MAP.get(prefix, (200, "Website", "nginx"))
        result.append(HTTPAsset(
            url=url, status_code=defaults[0], title=defaults[1],
            server=defaults[2], content_type="text/html",
            alive=True, tls=url.startswith("https://"),
        ))
    return result


def _build_url_list(ctx: TargetContext, subdomains: Optional[SubdomainResult]) -> list:
    urls = []
    if subdomains and subdomains.subdomains:
        for sub in subdomains.subdomains:
            urls.append("http://" + sub.fqdn)
            urls.append("https://" + sub.fqdn)
    else:
        target = ctx.domain or ctx.raw_input
        urls = ["http://" + target, "https://" + target]
    return urls


def _parse_httpx_line(line: str) -> Optional[HTTPAsset]:
    try:
        obj = json.loads(line)
        return HTTPAsset(
            url=obj.get("url", ""),
            status_code=obj.get("status-code") or obj.get("status_code"),
            title=obj.get("title"),
            server=obj.get("webserver") or obj.get("server"),
            content_type=obj.get("content-type"),
            redirect_url=obj.get("location"),
            alive=True,
            tls=(obj.get("url", "")).startswith("https://"),
            tech=obj.get("tech", []),
        )
    except Exception:
        return None


def collect_http(ctx: TargetContext, allow_mock: bool = False,
                 subdomains: Optional[SubdomainResult] = None):
    target = ctx.domain or ctx.raw_input
    profile = HTTPProfile(target=target)
    url_list = _build_url_list(ctx, subdomains)

    probe_file = Path(ctx.output_dir) / "http_probe_list.txt"
    probe_file.write_text("\n".join(url_list))

    tool_result = run_tool(
        "httpx",
        args=["-l", str(probe_file), "-json", "-silent", "-title",
              "-server", "-status-code", "-content-type", "-location",
              "-tech-detect", "-timeout", str(min(ctx.timeout, 10))],
        timeout=ctx.timeout,
    )

    if tool_result.skipped:
        if not allow_mock:
            profile.data_source = "missing"
            return profile
        logger.warning("httpx unavailable — using MOCK data for %s", target)
        profile.assets = _mock_http_assets(url_list)
        profile.raw_output = "MOCK_DATA"
        profile.data_source = "mock"
    elif not tool_result.success:
        logger.error("httpx failed rc=%d", tool_result.returncode)
        profile.raw_output = tool_result.stderr
        profile.data_source = "error"
    else:
        raw = tool_result.stdout.strip()
        profile.raw_output = raw
        profile.data_source = "httpx"
        for line in raw.splitlines():
            asset = _parse_httpx_line(line.strip())
            if asset:
                profile.assets.append(asset)

    logger.info("HTTP: %d assets (source: %s)", len(profile.assets), profile.data_source)
    norm_file = Path(ctx.output_dir) / "http_normalized.json"
    norm_file.write_text(json.dumps(
        {"data_source": profile.data_source,
         "assets": [a.model_dump() for a in profile.assets]}, indent=2))
    return profile
