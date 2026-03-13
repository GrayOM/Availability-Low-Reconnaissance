"""
collectors/rdap_collector.py
=============================
Passive RDAP / WHOIS / ASN enrichment using public APIs.

Sources used (all public, no API key required):
  - RDAP:  https://rdap.org/  (IANA-compliant RDAP bootstrap)
  - ASN:   https://ipinfo.io/  (public JSON endpoint, no auth for basic use)

Data source label: "rdap_passive"
Disabled label:    "disabled"
Error label:       "error"

IMPORTANT:
  All data is from public registration records.
  Data may be outdated. Findings are ownership/context clues only.
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)

_RDAP_DOMAIN_URL  = "https://rdap.org/domain/{domain}"
_RDAP_IP_URL      = "https://rdap.org/ip/{ip}"
_IPINFO_URL       = "https://ipinfo.io/{ip}/json"
_TIMEOUT          = 15


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class RDAPResult:
    """Aggregated RDAP/WHOIS/ASN passive enrichment."""
    target:       str
    data_source:  str  = "disabled"
    registrar:    str  = ""
    registrant:   str  = ""
    org:          str  = ""
    country:      str  = ""
    created_date: str  = ""
    updated_date: str  = ""
    expiry_date:  str  = ""
    name_servers: list = field(default_factory=list)
    # ASN
    asn:          str  = ""
    asn_org:      str  = ""
    asn_cidr:     str  = ""
    # IP info
    ip:           str  = ""
    city:         str  = ""
    region:       str  = ""
    # Resolved IPs for domain targets
    resolved_ips: list = field(default_factory=list)
    note:         str  = ""
    collected_at: str  = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def model_dump(self) -> dict:
        return {
            "target":       self.target,
            "data_source":  self.data_source,
            "registrar":    self.registrar,
            "registrant":   self.registrant,
            "org":          self.org,
            "country":      self.country,
            "created_date": self.created_date,
            "updated_date": self.updated_date,
            "expiry_date":  self.expiry_date,
            "name_servers": self.name_servers,
            "asn":          self.asn,
            "asn_org":      self.asn_org,
            "asn_cidr":     self.asn_cidr,
            "ip":           self.ip,
            "city":         self.city,
            "region":       self.region,
            "resolved_ips": self.resolved_ips,
            "note":         self.note,
            "collected_at": self.collected_at,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fetch_json(url: str, timeout: int = _TIMEOUT) -> dict:
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "ALR-passive-recon/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _resolve_domain_ips(domain: str) -> list:
    """Passive-compatible: use socket.getaddrinfo (stdlib DNS)."""
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({info[4][0] for info in infos})
        return ips
    except Exception:
        return []


def _parse_rdap_domain(data: dict, result: RDAPResult) -> None:
    """Extract useful fields from RDAP domain response."""
    # Registrar
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [])
        name = ""
        if isinstance(vcard, list) and len(vcard) > 1:
            for prop in vcard[1]:
                if prop[0] == "fn":
                    name = prop[3]
                    break
        if "registrar" in roles and name:
            result.registrar = name
        if "registrant" in roles and name:
            result.registrant = name
        if "administrative" in roles and not result.registrant and name:
            result.registrant = name

    # Name servers
    for ns in data.get("nameservers", []):
        ldhName = ns.get("ldhName", "")
        if ldhName:
            result.name_servers.append(ldhName.lower())

    # Events (dates)
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date   = event.get("eventDate", "")[:10]
        if action == "registration":
            result.created_date = date
        elif action == "last changed":
            result.updated_date = date
        elif action == "expiration":
            result.expiry_date = date


def _parse_rdap_ip(data: dict, result: RDAPResult) -> None:
    """Extract useful fields from RDAP IP response."""
    result.org    = data.get("name", "")
    result.country = data.get("country", "")
    # IP CIDR
    start = data.get("startAddress", "")
    end   = data.get("endAddress", "")
    if start and end:
        result.asn_cidr = start + " - " + end
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [])
        if isinstance(vcard, list) and len(vcard) > 1:
            for prop in vcard[1]:
                if prop[0] == "fn":
                    if "registrant" in roles or "administrative" in roles:
                        result.registrant = prop[3]
                        break


def _enrich_asn(ip: str, result: RDAPResult) -> None:
    """Fetch ASN/org/network info from ipinfo.io public endpoint."""
    try:
        data = _fetch_json(_IPINFO_URL.format(ip=ip))
        result.asn      = data.get("org", "").split(" ")[0]  # e.g. "AS12345"
        result.asn_org  = " ".join(data.get("org", "").split(" ")[1:])
        result.country  = result.country or data.get("country", "")
        result.city     = data.get("city", "")
        result.region   = data.get("region", "")
        result.asn_cidr = result.asn_cidr or data.get("network", "")
        logger.debug("ASN info: %s / %s", result.asn, result.asn_org)
    except Exception as exc:
        logger.debug("ASN enrichment skipped: %s", exc)


# ---------------------------------------------------------------------------
# Public collector function
# ---------------------------------------------------------------------------

def collect_rdap(ctx) -> RDAPResult:
    """
    Passive RDAP/WHOIS/ASN enrichment for the target.

    For domain targets:
      1. RDAP domain lookup → registrar, dates, name servers
      2. Passive DNS resolution via stdlib socket
      3. ASN enrichment for resolved IPs via ipinfo.io

    For IP targets:
      1. RDAP IP lookup → network ownership
      2. ASN enrichment via ipinfo.io

    Returns
    -------
    RDAPResult — always returned, never raises.
    """
    target = ctx.domain or ctx.ip or ctx.raw_input
    result = RDAPResult(target=target)
    input_type = str(ctx.input_type)

    try:
        if input_type == "domain":
            _collect_for_domain(target, result)
        elif input_type in ("ip", "cidr"):
            _collect_for_ip(target, result)
        else:
            result.data_source = "skipped"
            result.note = "RDAP enrichment requires domain or IP target."
            _save(ctx, result)
            return result

        result.data_source = "rdap_passive"
        result.note = (
            "Passive data from public RDAP and ipinfo.io endpoints. "
            "Reflects registration records — ownership context clues only."
        )

    except Exception as exc:
        logger.error("RDAP collector error: %s", exc)
        result.data_source = "error"
        result.note = "RDAP collection failed: " + str(exc)

    _save(ctx, result)
    return result


def _collect_for_domain(domain: str, result: RDAPResult) -> None:
    """RDAP + ASN enrichment for a domain target."""
    # RDAP domain registration data
    try:
        url  = _RDAP_DOMAIN_URL.format(domain=urllib.parse.quote(domain))
        data = _fetch_json(url)
        _parse_rdap_domain(data, result)
        logger.info("RDAP: domain data fetched for %s", domain)
    except urllib.error.HTTPError as exc:
        logger.warning("RDAP domain lookup failed (HTTP %s): %s", exc.code, domain)
    except Exception as exc:
        logger.warning("RDAP domain lookup failed: %s", exc)

    # Passive IP resolution
    ips = _resolve_domain_ips(domain)
    result.resolved_ips = ips
    logger.info("RDAP: resolved %d IPs for %s", len(ips), domain)

    # ASN enrichment for first resolved IP
    if ips:
        result.ip = ips[0]
        _enrich_asn(ips[0], result)


def _collect_for_ip(ip: str, result: RDAPResult) -> None:
    """RDAP + ASN enrichment for an IP target."""
    result.ip = ip
    # RDAP IP data
    try:
        url  = _RDAP_IP_URL.format(ip=urllib.parse.quote(ip))
        data = _fetch_json(url)
        _parse_rdap_ip(data, result)
        logger.info("RDAP: IP data fetched for %s", ip)
    except urllib.error.HTTPError as exc:
        logger.warning("RDAP IP lookup failed (HTTP %s): %s", exc.code, ip)
    except Exception as exc:
        logger.warning("RDAP IP lookup failed: %s", exc)

    _enrich_asn(ip, result)


def _save(ctx, result: RDAPResult) -> None:
    out = Path(ctx.output_dir) / "rdap_normalized.json"
    out.write_text(json.dumps(result.model_dump(), indent=2, default=str))
    logger.debug("RDAP output saved: %s", out)
