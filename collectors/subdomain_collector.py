"""
collectors/subdomain_collector.py
==================================
Subdomain discovery via subfinder.
Returns data_source tag: "subfinder" | "mock"
"""
from __future__ import annotations
import json
from pathlib import Path
from models.schema import Subdomain, SubdomainResult, TargetContext
from utils.logger import get_logger
from utils.subprocess_runner import run_tool

logger = get_logger(__name__)


def _mock_subdomains(domain: str) -> list[str]:
    return [
        "www." + domain, "mail." + domain, "api." + domain,
        "dev." + domain, "staging." + domain, "admin." + domain,
        "vpn." + domain, "git." + domain,
    ]


def collect_subdomains(ctx: TargetContext, allow_mock: bool = False):
    """Run subfinder; fall back to mock only if allow_mock=True."""
    target = ctx.domain or ctx.raw_input
    raw_file = str(Path(ctx.output_dir) / "subfinder_raw.txt")
    result = SubdomainResult(target=target)

    if str(ctx.input_type) != "domain":
        logger.info("Subdomain discovery skipped — target is not a domain")
        result.data_source = "skipped"
        return result

    tool_result = run_tool(
        "subfinder",
        args=["-d", target, "-silent", "-o", raw_file],
        timeout=ctx.timeout,
    )

    if tool_result.skipped:
        if not allow_mock:
            result.data_source = "missing"
            return result
        logger.warning("subfinder unavailable — using MOCK data for %s", target)
        fqdns = _mock_subdomains(target)
        result.raw_output = "MOCK_DATA"
        result.data_source = "mock"
    elif not tool_result.success:
        logger.error("subfinder failed (rc=%d)", tool_result.returncode)
        result.raw_output = tool_result.stderr
        result.data_source = "error"
        fqdns = []
    else:
        raw = tool_result.stdout.strip()
        result.raw_output = raw
        result.data_source = "subfinder"
        fqdns = [line.strip() for line in raw.splitlines() if line.strip()]
        if not fqdns and Path(raw_file).exists():
            fqdns = Path(raw_file).read_text().splitlines()

    seen: set = set()
    for fqdn in fqdns:
        fqdn = fqdn.lower().strip()
        if fqdn and fqdn not in seen:
            seen.add(fqdn)
            result.subdomains.append(Subdomain(fqdn=fqdn, source="subfinder"))

    logger.info("Subdomains: %d found (source: %s)", len(result.subdomains), result.data_source)

    norm_file = Path(ctx.output_dir) / "subdomains_normalized.json"
    norm_file.write_text(json.dumps(
        {"data_source": result.data_source,
         "subdomains": [s.model_dump() for s in result.subdomains]}, indent=2))
    return result
