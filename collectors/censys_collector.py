"""
collectors/censys_collector.py
================================
Censys passive enrichment — primary passive intelligence source for ALR.

Data collected:
  - Host-level service hints (ports, protocols) from Censys Search API
  - Web property / virtual host information
  - Certificate Subject Alternative Names (SANs) → subdomain hints
  - Exposed service context (labeled as passive external intelligence)

Data source label: "censys_passive"
Disabled label:    "disabled"
Error label:       "error"

IMPORTANT:
  All results are passive external intelligence from Censys public datasets.
  They reflect historical internet scans, NOT live direct probing.
  Findings must be treated as clue-based and may be outdated.

Setup:
  Set CENSYS_API_ID and CENSYS_API_SECRET in .env
  pip install censys

  Or use CENSYS_API_KEY (new unified key format) if available.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass
class CensysServiceHint:
    """A single passive service hint from Censys."""
    ip:       str
    port:     int
    protocol: str = ""
    service:  str = ""
    banner:   str = ""


@dataclass
class CenysyCertHint:
    """Certificate SAN entry that may reveal subdomains."""
    common_name: str
    sans:        list = field(default_factory=list)
    issuer:      str  = ""
    not_after:   str  = ""


@dataclass
class CensysResult:
    """Aggregated Censys passive enrichment result."""
    target:        str
    data_source:   str                  = "disabled"
    queried:       bool                 = False
    service_hints: list                 = field(default_factory=list)
    cert_hints:    list                 = field(default_factory=list)
    subdomain_hints: list               = field(default_factory=list)
    raw_host:      Optional[dict]       = None
    note:          str                  = ""
    collected_at:  str                  = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def model_dump(self) -> dict:
        return {
            "target":          self.target,
            "data_source":     self.data_source,
            "queried":         self.queried,
            "note":            self.note,
            "service_hints":   [
                {"ip": s.ip, "port": s.port, "protocol": s.protocol,
                 "service": s.service, "banner": s.banner}
                for s in self.service_hints
            ],
            "cert_hints":      [
                {"common_name": c.common_name, "sans": c.sans,
                 "issuer": c.issuer, "not_after": c.not_after}
                for c in self.cert_hints
            ],
            "subdomain_hints": self.subdomain_hints,
            "collected_at":    self.collected_at,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_credentials() -> tuple[Optional[str], Optional[str]]:
    """
    Return (api_id, api_secret) from environment.
    Supports both legacy key pair and new unified API key format.
    """
    api_id     = os.getenv("CENSYS_API_ID", "")
    api_secret = os.getenv("CENSYS_API_SECRET", "")
    api_key    = os.getenv("CENSYS_API_KEY", "")  # unified key (v2)

    if api_key:
        return api_key, None   # unified key: pass as api_id, secret=None
    if api_id and api_secret:
        return api_id, api_secret
    return None, None


def _extract_subdomain_hints(cert_hints: list, target: str) -> list:
    """Pull unique subdomain candidates from certificate SANs."""
    found = set()
    for cert in cert_hints:
        for san in cert.sans:
            san = san.lstrip("*.")
            if san.endswith("." + target) or san == target:
                found.add(san)
    return sorted(found)


def _query_censys_host(api_id: str, api_secret: Optional[str], ip: str) -> dict:
    """Query Censys Hosts API for a specific IP."""
    from censys.search import CensysHosts  # type: ignore
    if api_secret:
        h = CensysHosts(api_id=api_id, api_secret=api_secret)
    else:
        h = CensysHosts(api_id=api_id)
    return h.view(ip)


def _query_censys_certs(api_id: str, api_secret: Optional[str], domain: str) -> list:
    """
    Search Censys certificates for a domain and extract SAN hints.
    Uses the certificates search (v2 API).
    """
    from censys.search import CensysCerts  # type: ignore

    if api_secret:
        c = CensysCerts(api_id=api_id, api_secret=api_secret)
    else:
        c = CensysCerts(api_id=api_id)

    hints = []
    try:
        # Search for certs matching this domain in SANs or CN
        query = "parsed.names: " + domain
        fields = [
            "parsed.subject_dn",
            "parsed.names",
            "parsed.issuer.organization",
            "parsed.validity.end",
        ]
        for cert in c.search(query, fields=fields, max_records=50):
            names = cert.get("parsed.names", [])
            hints.append(CenysyCertHint(
                common_name=cert.get("parsed.subject_dn", ""),
                sans=names if isinstance(names, list) else [names],
                issuer=str(cert.get("parsed.issuer.organization", "")),
                not_after=str(cert.get("parsed.validity.end", "")),
            ))
    except Exception as exc:
        logger.warning("Censys cert search error: %s", exc)

    return hints


def _query_censys_domain(api_id: str, api_secret: Optional[str], domain: str) -> list:
    """
    Search Censys for hosts related to the domain (passive host search).
    Returns a list of service hint dicts.
    """
    from censys.search import CensysHosts  # type: ignore

    if api_secret:
        h = CensysHosts(api_id=api_id, api_secret=api_secret)
    else:
        h = CensysHosts(api_id=api_id)

    hints = []
    try:
        query = "dns.reverse_dns.reverse_dns.names: " + domain
        for host in h.search(query, per_page=50, pages=1):
            ip = host.get("ip", "")
            for svc in host.get("services", []):
                hints.append(CensysServiceHint(
                    ip=ip,
                    port=svc.get("port", 0),
                    protocol=svc.get("transport_protocol", ""),
                    service=svc.get("service_name", ""),
                    banner=str(svc.get("banner", ""))[:200],
                ))
    except Exception as exc:
        logger.warning("Censys host search error: %s", exc)

    return hints


# ---------------------------------------------------------------------------
# Public collector function
# ---------------------------------------------------------------------------

def collect_censys(ctx, subdomains=None) -> CensysResult:
    """
    Run Censys passive enrichment for the target.

    Collects:
      - Certificate SAN hints → passive subdomain discovery
      - Host service hints (for IP targets or resolved IPs)

    Parameters
    ----------
    ctx : TargetContext
    subdomains : SubdomainResult, optional

    Returns
    -------
    CensysResult
        Always returned — never raises.
        data_source = "censys_passive" | "disabled" | "error"
    """
    target = ctx.domain or ctx.raw_input
    result = CensysResult(target=target)

    api_id, api_secret = _get_credentials()

    if not api_id:
        logger.info(
            "Censys: no credentials configured — set CENSYS_API_ID + CENSYS_API_SECRET "
            "or CENSYS_API_KEY in .env"
        )
        result.data_source = "disabled"
        result.note = (
            "Censys not configured. Set CENSYS_API_ID + CENSYS_API_SECRET "
            "in .env to enable passive enrichment."
        )
        _save(ctx, result)
        return result

    # Check censys package is installed
    try:
        import censys  # noqa
    except ImportError:
        logger.warning("Censys package not installed — run: pip install censys")
        result.data_source = "disabled"
        result.note = "censys Python package not installed. Run: pip install censys"
        _save(ctx, result)
        return result

    logger.info("Censys: querying passive data for %s", target)
    result.queried = True

    try:
        if str(ctx.input_type) == "domain":
            # Certificate-based subdomain hints
            result.cert_hints = _query_censys_certs(api_id, api_secret, target)
            result.subdomain_hints = _extract_subdomain_hints(result.cert_hints, target)
            logger.info(
                "Censys: %d cert hints, %d subdomain hints",
                len(result.cert_hints), len(result.subdomain_hints),
            )

            # Passive host service hints via reverse DNS
            result.service_hints = _query_censys_domain(api_id, api_secret, target)
            logger.info("Censys: %d service hints", len(result.service_hints))

        elif str(ctx.input_type) in ("ip", "cidr"):
            # Direct IP host view
            raw = _query_censys_host(api_id, api_secret, target)
            result.raw_host = raw
            for svc in raw.get("services", []):
                result.service_hints.append(CensysServiceHint(
                    ip=target,
                    port=svc.get("port", 0),
                    protocol=svc.get("transport_protocol", ""),
                    service=svc.get("service_name", ""),
                    banner=str(svc.get("banner", ""))[:200],
                ))
            logger.info("Censys: %d services from host view", len(result.service_hints))

        result.data_source = "censys_passive"
        result.note = (
            "Passive external intelligence from Censys internet scan data. "
            "Data reflects historical scans and may not represent the current live state."
        )

    except Exception as exc:
        logger.error("Censys query failed: %s", exc)
        result.data_source = "error"
        result.note = "Censys query failed: " + str(exc)

    _save(ctx, result)
    return result


def _save(ctx, result: CensysResult) -> None:
    """Write normalized Censys output to disk."""
    out = Path(ctx.output_dir) / "censys_normalized.json"
    out.write_text(json.dumps(result.model_dump(), indent=2, default=str))
    logger.debug("Censys output saved: %s", out)
