"""
collectors/dns_collector.py
============================
DNS profiling using dnsx.
Returns data_source: "dnsx" | "mock" | "missing" | "error"

dnsx invocation fix:
  OLD (broken): dnsx -d target.com -a -json
    → newer dnsx requires wordlist with -d flag → "missing wordlist" error
  CORRECT: pipe domain list via stdin, or use -l <file>
    → echo "target.com" | dnsx -a -cname -mx -txt -json -silent
    → or: write domain list to temp file, dnsx -l file.txt ...

ALR uses the -l <file> approach (no shell=True, safe subprocess).
"""
from __future__ import annotations

import json
from pathlib import Path

from models.schema import DNSProfile, DNSRecord, RecordType, TargetContext
from utils.logger import get_logger
from utils.subprocess_runner import run_tool

logger = get_logger(__name__)


def _mock_dns_records(target: str) -> list[dict]:
    return [
        {"hostname": target,          "type": "A",     "value": "93.184.216.34"},
        {"hostname": "www." + target, "type": "CNAME", "value": target},
        {"hostname": target,          "type": "MX",    "value": "mail." + target},
        {"hostname": target,          "type": "TXT",   "value": "v=spf1 include:_spf.google.com ~all"},
    ]


def _parse_dnsx_line(line: str, target: str) -> list:
    """Parse a single dnsx JSON output line into DNSRecord objects."""
    try:
        obj = json.loads(line)
        host = obj.get("host", target)
        records = []
        for rtype in ("a", "aaaa", "cname", "mx", "txt", "ns"):
            values = obj.get(rtype, [])
            if isinstance(values, str):
                values = [values]
            for val in values:
                try:
                    records.append(DNSRecord(
                        hostname=host,
                        record_type=RecordType(rtype.upper()),
                        value=str(val),
                    ))
                except ValueError:
                    pass
        return records
    except Exception:
        return []


def _build_domain_list(ctx: TargetContext, subdomains=None) -> list:
    """
    Build the list of domains to resolve.
    Always includes the root target. Adds discovered subdomains if provided.
    """
    targets = set()
    targets.add(ctx.domain or ctx.raw_input)

    if subdomains and hasattr(subdomains, "subdomains"):
        for sub in subdomains.subdomains:
            targets.add(sub.fqdn)

    return sorted(targets)


def collect_dns(ctx: TargetContext, allow_mock: bool = False, subdomains=None):
    """
    Profile DNS records for the target using dnsx.

    Uses -l <file> input method (NOT -d flag) to avoid the
    "missing wordlist" error in newer dnsx versions.

    Parameters
    ----------
    ctx : TargetContext
    allow_mock : bool
    subdomains : SubdomainResult, optional
        If provided, discovered subdomains are also resolved.
    """
    target = ctx.domain or ctx.raw_input
    profile = DNSProfile(target=target)

    # Build domain list file for dnsx -l input
    domain_list = _build_domain_list(ctx, subdomains)
    input_file  = Path(ctx.output_dir) / "dnsx_input.txt"
    raw_file    = Path(ctx.output_dir) / "dnsx_raw.txt"
    input_file.write_text("\n".join(domain_list))

    logger.debug("dnsx input: %d domains -> %s", len(domain_list), input_file)

    tool_result = run_tool(
        "dnsx",
        args=[
            "-l", str(input_file),   # ← correct: file list input, NOT -d
            "-a", "-aaaa", "-cname", "-mx", "-txt",
            "-json",
            "-silent",
            "-o", str(raw_file),
        ],
        timeout=ctx.timeout,
    )

    if tool_result.skipped:
        if not allow_mock:
            profile.data_source = "missing"
            return profile
        logger.warning("dnsx unavailable — using MOCK data for %s", target)
        profile.raw_output = "MOCK_DATA"
        profile.data_source = "mock"
        for entry in _mock_dns_records(target):
            try:
                profile.records.append(DNSRecord(
                    hostname=entry["hostname"],
                    record_type=RecordType(entry["type"]),
                    value=entry["value"],
                ))
            except Exception:
                pass

    elif not tool_result.success:
        logger.error("dnsx failed rc=%d stderr=%s",
                     tool_result.returncode, tool_result.stderr[:300])
        profile.raw_output = tool_result.stderr
        profile.data_source = "error"

    else:
        raw = tool_result.stdout.strip()
        profile.raw_output = raw
        profile.data_source = "dnsx"

        # Parse stdout first
        for line in raw.splitlines():
            profile.records.extend(_parse_dnsx_line(line.strip(), target))

        # Also read -o output file if stdout was empty
        if not profile.records and raw_file.exists():
            for line in raw_file.read_text().splitlines():
                profile.records.extend(_parse_dnsx_line(line.strip(), target))

    logger.info("DNS: %d records (source: %s)", len(profile.records), profile.data_source)

    norm_file = Path(ctx.output_dir) / "dns_normalized.json"
    norm_file.write_text(json.dumps(
        {"data_source": profile.data_source,
         "records": [r.model_dump() for r in profile.records]},
        indent=2,
    ))
    return profile
