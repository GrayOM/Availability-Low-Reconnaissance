"""
collectors/ct_collector.py
===========================
Certificate Transparency passive enrichment via crt.sh public API.

Data source label: "ct_passive"
Disabled label:    "disabled"
Error label:       "error"

IMPORTANT:
  All results are from public Certificate Transparency logs via crt.sh.
  Data reflects historical certificate issuance — not live service state.
  Findings are clue-based and should be manually validated.

No API key required. Uses the public crt.sh JSON API.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)

_CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
_REQUEST_TIMEOUT = 20  # seconds


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class CTEntry:
    """A single certificate entry from CT logs."""
    common_name:  str
    name_value:   str                        # may contain multiple SANs
    issuer_cn:    str = ""
    not_before:   str = ""
    not_after:    str = ""


@dataclass
class CTResult:
    """Aggregated CT passive enrichment result."""
    target:          str
    data_source:     str              = "disabled"
    entries:         list             = field(default_factory=list)
    subdomain_hints: list             = field(default_factory=list)
    wildcard_hints:  list             = field(default_factory=list)
    raw_count:       int              = 0
    note:            str              = ""
    collected_at:    str              = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def model_dump(self) -> dict:
        return {
            "target":          self.target,
            "data_source":     self.data_source,
            "raw_count":       self.raw_count,
            "subdomain_hints": self.subdomain_hints,
            "wildcard_hints":  self.wildcard_hints,
            "note":            self.note,
            "entries":         [
                {
                    "common_name": e.common_name,
                    "name_value":  e.name_value,
                    "issuer_cn":   e.issuer_cn,
                    "not_before":  e.not_before,
                    "not_after":   e.not_after,
                }
                for e in self.entries[:100]  # cap stored entries
            ],
            "collected_at":    self.collected_at,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fetch_crtsh(domain: str, timeout: int = _REQUEST_TIMEOUT) -> list:
    """
    Fetch CT entries from crt.sh JSON API.
    Returns raw list of dicts or raises on failure.
    """
    url = _CRTSH_URL.format(domain=urllib.parse.quote(domain))
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "ALR-passive-recon/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw)


# urllib.parse needs to be imported
import urllib.parse  # noqa: E402 (placed after function that references it)


def _extract_names(entry: dict) -> list:
    """Extract all hostnames from a crt.sh entry's name_value field."""
    raw = entry.get("name_value", "") or ""
    names = []
    for line in raw.splitlines():
        name = line.strip().lstrip("*.")
        if name:
            names.append(name)
    return names


def _is_valid_subdomain(name: str, target: str) -> bool:
    """True if name is a valid subdomain (or equals) target."""
    name = name.lower().strip()
    target = target.lower().strip()
    return name == target or name.endswith("." + target)


def _is_wildcard(raw_name: str) -> bool:
    return raw_name.strip().startswith("*.")


def _deduplicate_subdomains(names: list) -> list:
    seen = set()
    result = []
    for n in names:
        n = n.lower().strip()
        if n and n not in seen:
            seen.add(n)
            result.append(n)
    return sorted(result)


# ---------------------------------------------------------------------------
# Public collector function
# ---------------------------------------------------------------------------

def collect_ct(ctx, timeout: int = 20) -> CTResult:
    """
    Passive CT enrichment for the target domain via crt.sh.

    - Fetches certificate entries from public CT logs
    - Extracts subdomain hints from SANs / CN fields
    - Deduplicates and normalizes results
    - Saves to {output_dir}/ct_normalized.json

    Parameters
    ----------
    ctx : TargetContext
    timeout : int
        HTTP request timeout in seconds.

    Returns
    -------
    CTResult — always returned, never raises.
    """
    target = ctx.domain or ctx.raw_input
    result = CTResult(target=target)

    if str(ctx.input_type) != "domain":
        logger.info("CT: skipping — target is not a domain (input_type=%s)", ctx.input_type)
        result.data_source = "skipped"
        result.note = "CT enrichment requires a domain target."
        _save(ctx, result)
        return result

    logger.info("CT: querying crt.sh for %s", target)

    try:
        raw_entries = _fetch_crtsh(target, timeout=timeout)
    except urllib.error.HTTPError as exc:
        logger.warning("CT: crt.sh HTTP error %s", exc)
        result.data_source = "error"
        result.note = "crt.sh returned HTTP " + str(exc.code)
        _save(ctx, result)
        return result
    except Exception as exc:
        logger.warning("CT: crt.sh unreachable — %s", exc)
        result.data_source = "error"
        result.note = "crt.sh query failed: " + str(exc)
        _save(ctx, result)
        return result

    if not raw_entries:
        logger.info("CT: no entries found for %s", target)
        result.data_source = "ct_passive"
        result.note = "No CT entries found for this target."
        _save(ctx, result)
        return result

    result.raw_count = len(raw_entries)
    logger.info("CT: %d raw entries from crt.sh", result.raw_count)

    # Parse entries
    subdomain_set: set = set()
    wildcard_set:  set = set()

    for entry in raw_entries:
        cn          = (entry.get("common_name") or "").strip()
        name_value  = (entry.get("name_value") or "").strip()
        issuer_cn   = (entry.get("issuer", {}) or {}).get("CN", "") if isinstance(entry.get("issuer"), dict) else ""
        not_before  = str(entry.get("not_before") or "")
        not_after   = str(entry.get("not_after") or "")

        result.entries.append(CTEntry(
            common_name=cn,
            name_value=name_value,
            issuer_cn=issuer_cn,
            not_before=not_before,
            not_after=not_after,
        ))

        # Collect all names from this entry
        raw_names = []
        for line in name_value.splitlines():
            raw_names.append(line.strip())
        if cn:
            raw_names.append(cn)

        for raw_name in raw_names:
            if _is_wildcard(raw_name):
                clean = raw_name.lstrip("*.")
                if _is_valid_subdomain(clean, target):
                    wildcard_set.add(clean)
            clean = raw_name.lstrip("*.")
            if _is_valid_subdomain(clean, target):
                subdomain_set.add(clean)

    result.subdomain_hints = _deduplicate_subdomains(list(subdomain_set))
    result.wildcard_hints  = _deduplicate_subdomains(list(wildcard_set))
    result.data_source     = "ct_passive"
    result.note = (
        "Passive data from public Certificate Transparency logs (crt.sh). "
        "Reflects historical certificate issuance — not confirmed live services."
    )

    logger.info(
        "CT: %d unique subdomain hints, %d wildcard patterns",
        len(result.subdomain_hints), len(result.wildcard_hints),
    )

    _save(ctx, result)
    return result


def _save(ctx, result: CTResult) -> None:
    out = Path(ctx.output_dir) / "ct_normalized.json"
    out.write_text(json.dumps(result.model_dump(), indent=2, default=str))
    logger.debug("CT output saved: %s", out)
