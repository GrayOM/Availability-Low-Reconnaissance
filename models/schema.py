"""
models/schema.py  (stdlib-only, no pydantic required)
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any


# ---------------------------------------------------------------------------
# Minimal BaseModel shim
# ---------------------------------------------------------------------------

class BaseModel:
    def model_dump(self) -> dict:
        def _cvt(obj):
            if isinstance(obj, BaseModel):
                return obj.model_dump()
            if isinstance(obj, list):
                return [_cvt(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _cvt(v) for k, v in obj.items()}
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, datetime):
                return obj.isoformat()
            return obj
        return {k: _cvt(v) for k, v in self.__dict__.items()}

    def __repr__(self):
        attrs = ", ".join(f"{k}={v!r}" for k, v in self.__dict__.items())
        return f"{self.__class__.__name__}({attrs})"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class InputType(str, Enum):
    DOMAIN  = "domain"
    IP      = "ip"
    CIDR    = "cidr"
    UNKNOWN = "unknown"


class RiskHint(str, Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"
    REVIEW = "review_recommended"


class RecordType(str, Enum):
    A     = "A"
    AAAA  = "AAAA"
    CNAME = "CNAME"
    MX    = "MX"
    TXT   = "TXT"
    NS    = "NS"
    SOA   = "SOA"


# ---------------------------------------------------------------------------
# Target Context
# ---------------------------------------------------------------------------

class TargetContext(BaseModel):
    def __init__(self, raw_input: str, input_type, domain=None, ip=None,
                 run_id: str = "", started_at=None, output_dir: str = "data/outputs",
                 timeout: int = 60, verbose: bool = False,
                 enable_ai: bool = False, enable_github: bool = False):
        self.raw_input    = raw_input
        self.input_type   = input_type.value if isinstance(input_type, Enum) else input_type
        self.domain       = domain
        self.ip           = ip
        self.run_id       = run_id
        self.started_at   = started_at or datetime.utcnow()
        self.output_dir   = output_dir
        self.timeout      = timeout
        self.verbose      = verbose
        self.enable_ai    = enable_ai
        self.enable_github= enable_github


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

class DNSRecord(BaseModel):
    def __init__(self, hostname: str, record_type, value: str, ttl=None):
        self.hostname    = hostname
        self.record_type = record_type.value if isinstance(record_type, Enum) else record_type
        self.value       = value
        self.ttl         = ttl


class DNSProfile(BaseModel):
    def __init__(self, target: str, records=None, raw_output=None):
        self.target     = target
        self.records: List[DNSRecord] = records or []
        self.raw_output = raw_output


# ---------------------------------------------------------------------------
# Subdomains
# ---------------------------------------------------------------------------

class Subdomain(BaseModel):
    def __init__(self, fqdn: str, source: str = "subfinder", alive=None):
        self.fqdn   = fqdn
        self.source = source
        self.alive  = alive


class SubdomainResult(BaseModel):
    def __init__(self, target: str, subdomains=None, raw_output=None):
        self.target     = target
        self.subdomains: List[Subdomain] = subdomains or []
        self.raw_output = raw_output


# ---------------------------------------------------------------------------
# HTTP Asset
# ---------------------------------------------------------------------------

class HTTPAsset(BaseModel):
    def __init__(self, url: str, status_code=None, title=None, server=None,
                 content_type=None, redirect_url=None, webserver=None,
                 tech=None, alive: bool = False, tls: bool = False):
        self.url          = url
        self.status_code  = status_code
        self.title        = title
        self.server       = server
        self.content_type = content_type
        self.redirect_url = redirect_url
        self.webserver    = webserver
        self.tech: List[str] = tech or []
        self.alive        = alive
        self.tls          = tls


class HTTPProfile(BaseModel):
    def __init__(self, target: str, assets=None, raw_output=None):
        self.target     = target
        self.assets: List[HTTPAsset] = assets or []
        self.raw_output = raw_output


# ---------------------------------------------------------------------------
# Port Exposure
# ---------------------------------------------------------------------------

class OpenPort(BaseModel):
    def __init__(self, host: str, port: int, protocol: str = "tcp",
                 service=None, banner=None):
        self.host     = host
        self.port     = port
        self.protocol = protocol
        self.service  = service
        self.banner   = banner


class PortSummary(BaseModel):
    def __init__(self, target: str, open_ports=None, raw_output=None):
        self.target     = target
        self.open_ports: List[OpenPort] = open_ports or []
        self.raw_output = raw_output


# ---------------------------------------------------------------------------
# Tech Stack
# ---------------------------------------------------------------------------

class TechDetection(BaseModel):
    def __init__(self, name: str, version=None, confidence=None, category=None):
        self.name       = name
        self.version    = version
        self.confidence = confidence
        self.category   = category


class TechProfile(BaseModel):
    def __init__(self, target: str, detections=None, raw_output=None):
        self.target     = target
        self.detections: List[TechDetection] = detections or []
        self.raw_output = raw_output


# ---------------------------------------------------------------------------
# GitHub Exposure
# ---------------------------------------------------------------------------

class GitHubHit(BaseModel):
    def __init__(self, repo: str, file_path=None, snippet=None,
                 hint_type: str = "keyword_match"):
        self.repo      = repo
        self.file_path = file_path
        self.snippet   = snippet
        self.hint_type = hint_type


class GitHubExposure(BaseModel):
    def __init__(self, target: str, hits=None, queried: bool = False,
                 note: str = "manual validation required"):
        self.target  = target
        self.hits: List[GitHubHit] = hits or []
        self.queried = queried
        self.note    = note


# ---------------------------------------------------------------------------
# Recon Bundle
# ---------------------------------------------------------------------------

class ReconBundle(BaseModel):
    def __init__(self, target: TargetContext, dns=None, subdomains=None,
                 http=None, ports=None, tech=None, github=None,
                 ct=None, rdap=None, censys=None,
                 errors=None, collected_at=None):
        self.target      = target
        self.dns         = dns
        self.subdomains  = subdomains
        self.http        = http
        self.ports       = ports
        self.tech        = tech
        self.github      = github
        self.ct          = ct       # CT passive enrichment
        self.rdap        = rdap     # RDAP/WHOIS/ASN enrichment
        self.censys      = censys   # optional: Censys (disabled by default)
        self.errors: Dict[str, str] = errors or {}
        self.collected_at = collected_at or datetime.utcnow()


# ---------------------------------------------------------------------------
# Surface Analysis
# ---------------------------------------------------------------------------

class SurfaceObservation(BaseModel):
    def __init__(self, asset: str, observation: str,
                 risk_hint=RiskHint.REVIEW,
                 category: str = "general",
                 recommendation: str = "manual validation required",
                 tags=None):
        self.asset          = asset
        self.observation    = observation
        self.risk_hint      = risk_hint.value if isinstance(risk_hint, Enum) else risk_hint
        self.category       = category
        self.recommendation = recommendation
        self.tags: List[str] = tags or []


class SurfaceReport(BaseModel):
    def __init__(self, target: str, observations=None,
                 priority_assets=None, summary_notes=None):
        self.target           = target
        self.observations: List[SurfaceObservation] = observations or []
        self.priority_assets: List[str] = priority_assets or []
        self.summary_notes: List[str]   = summary_notes or []


# ---------------------------------------------------------------------------
# AI Report
# ---------------------------------------------------------------------------

class AIReport(BaseModel):
    def __init__(self, executive_summary: str = "",
                 key_findings=None,
                 priority_assets=None,
                 analyst_notes=None,
                 review_recommendations=None,
                 reliability_notes=None,
                 availability_impact_notes=None,
                 review_notes=None,       # legacy alias
                 generated_at=None,
                 model_used: str = "none",
                 ai_enabled: bool = False,
                 ai_provider: str = "",
                 disclaimer: str = (
                     "This report is generated from passive OSINT data. "
                     "Observations are clue-based and require manual validation. "
                     "No confirmed vulnerabilities are asserted."
                 )):
        self.executive_summary          = executive_summary
        self.key_findings:     List[str]  = key_findings or []
        self.priority_assets:  List[dict] = priority_assets or []
        self.analyst_notes:    List[str]  = analyst_notes or []
        self.review_recommendations: List[str] = review_recommendations or []
        self.reliability_notes:      List[str] = reliability_notes or []
        self.availability_impact_notes: List[str] = availability_impact_notes or []
        self.review_notes:     List[str]  = review_notes or []  # legacy
        self.generated_at  = generated_at or datetime.utcnow()
        self.model_used    = model_used
        self.ai_enabled    = ai_enabled
        self.ai_provider   = ai_provider
        self.disclaimer    = disclaimer


# ---------------------------------------------------------------------------
# data_source mixin — injected dynamically at runtime
# (avoids rewriting every __init__ signature)
# ---------------------------------------------------------------------------
# All collector result objects get a .data_source attribute set after init.
# Default is "unknown". This is handled by the collectors directly.

def _inject_data_source(obj, value: str = "unknown"):
    """Attach a data_source attribute to any BaseModel instance."""
    obj.data_source = value

# Patch BaseModel to always have a default data_source
_orig_init = BaseModel.__init__
def _patched_init(self, *args, **kwargs):
    _orig_init(self, *args, **kwargs)
    if not hasattr(self, "data_source"):
        self.data_source = "unknown"
BaseModel.__init__ = _patched_init
