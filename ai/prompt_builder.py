"""
ai/prompt_builder.py
=====================
Builds a compact, structured AI input from normalized ALR recon data.

Design rules:
- Only send structured, normalized data — not raw collector noise
- Cap list sizes to avoid token bloat
- Always include data source reliability metadata
- Tell the AI when data is sparse or modules failed
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models.schema import ReconBundle, SurfaceReport


# caps — keep prompt tokens sane
_MAX_SUBDOMAINS    = 40
_MAX_CT_HINTS      = 30
_MAX_HTTP_ASSETS   = 20
_MAX_OBSERVATIONS  = 25
_MAX_PRIORITY      = 10
_MAX_GITHUB_HITS   = 10


def build_ai_prompt(
    bundle: "ReconBundle",
    surface: "SurfaceReport",
    module_status: dict,
    passive_only: bool = True,
) -> str:
    """
    Build a compact, structured AI prompt from normalized ALR data.

    Returns a JSON-serialized string that the AI can parse in context.
    Includes data source reliability labels for every module.
    """
    ctx = _build_context(bundle, surface, module_status, passive_only)
    return json.dumps(ctx, indent=2, default=str)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_context(bundle, surface, module_status, passive_only):
    target = bundle.target.raw_input
    mode   = "passive-only" if passive_only else "passive+light-active"

    context = {
        "task": "Generate a conservative, clue-based reconnaissance analysis report.",
        "target": target,
        "input_type": str(bundle.target.input_type),
        "run_mode": mode,
        "data_sources": module_status,
        "summary_counts": _summary_counts(bundle, surface),
        "collected_data": {},
        "surface_analysis": {},
        "limitations": [],
    }

    # Subdomains
    if bundle.subdomains and bundle.subdomains.subdomains:
        fqdns = [s.fqdn for s in bundle.subdomains.subdomains][:_MAX_SUBDOMAINS]
        context["collected_data"]["subdomains"] = {
            "source":  getattr(bundle.subdomains, "data_source", "passive"),
            "count":   len(bundle.subdomains.subdomains),
            "sample":  fqdns,
            "truncated": len(bundle.subdomains.subdomains) > _MAX_SUBDOMAINS,
        }
    else:
        context["collected_data"]["subdomains"] = {"source": "none", "count": 0}
        context["limitations"].append("No subdomain data collected.")

    # CT
    ct = getattr(bundle, "ct", None)
    if ct and getattr(ct, "data_source", "disabled") not in ("disabled", "error", "skipped"):
        hints = getattr(ct, "subdomain_hints", [])[:_MAX_CT_HINTS]
        wilds = getattr(ct, "wildcard_hints", [])
        context["collected_data"]["certificate_transparency"] = {
            "source":          ct.data_source,
            "raw_cert_count":  getattr(ct, "raw_count", 0),
            "subdomain_hints": hints,
            "wildcard_hints":  wilds[:10],
            "note":            getattr(ct, "note", ""),
        }
    else:
        context["collected_data"]["certificate_transparency"] = {
            "source": "disabled", "note": "CT data not available."
        }
        context["limitations"].append("Certificate Transparency data unavailable.")

    # RDAP
    rdap = getattr(bundle, "rdap", None)
    if rdap and getattr(rdap, "data_source", "disabled") not in ("disabled", "error", "skipped"):
        context["collected_data"]["rdap_whois_asn"] = {
            "source":      rdap.data_source,
            "registrar":   rdap.registrar,
            "registrant":  rdap.registrant,
            "org":         rdap.org,
            "country":     rdap.country,
            "asn":         rdap.asn,
            "asn_org":     rdap.asn_org,
            "name_servers": rdap.name_servers[:6],
            "created_date": rdap.created_date,
            "expiry_date":  rdap.expiry_date,
            "resolved_ips": rdap.resolved_ips[:8],
        }
    else:
        context["collected_data"]["rdap_whois_asn"] = {
            "source": "disabled", "note": "RDAP data not available."
        }
        context["limitations"].append("RDAP/WHOIS/ASN data unavailable.")

    # HTTP assets
    if bundle.http and bundle.http.assets:
        alive = [a for a in bundle.http.assets if a.alive][:_MAX_HTTP_ASSETS]
        context["collected_data"]["http_assets"] = {
            "source":      getattr(bundle.http, "data_source", "light_active"),
            "total_alive": len([a for a in bundle.http.assets if a.alive]),
            "assets": [
                {
                    "url":         a.url,
                    "status_code": a.status_code,
                    "title":       (a.title or "")[:80],
                    "server":      a.server or "",
                    "redirect_url": a.redirect_url or "",
                }
                for a in alive
            ],
        }
    else:
        context["collected_data"]["http_assets"] = {
            "source": "none", "total_alive": 0
        }
        context["limitations"].append("No live HTTP assets detected.")

    # Tech
    if bundle.tech and bundle.tech.detections:
        context["collected_data"]["technology"] = {
            "source":     getattr(bundle.tech, "data_source", "heuristic"),
            "detections": [
                {"name": t.name, "category": t.category, "confidence": t.confidence}
                for t in bundle.tech.detections
            ],
        }

    # GitHub
    if bundle.github and getattr(bundle.github, "queried", False):
        context["collected_data"]["github_public"] = {
            "source":  "passive",
            "hits":    len(bundle.github.hits),
            "note":    bundle.github.note,
            "samples": [
                {"repo": h.repo, "file": h.file_path, "type": h.hint_type}
                for h in bundle.github.hits[:_MAX_GITHUB_HITS]
            ],
        }

    # Surface analysis
    high_obs = [
        {
            "asset":          o.asset,
            "risk":           o.risk_hint,
            "category":       o.category,
            "observation":    o.observation,
            "recommendation": o.recommendation,
        }
        for o in surface.observations
        if o.risk_hint in ("high", "review_recommended")
    ][:_MAX_OBSERVATIONS]

    all_obs_sample = [
        {
            "asset":       o.asset,
            "risk":        o.risk_hint,
            "observation": o.observation,
        }
        for o in surface.observations
        if o.risk_hint not in ("high", "review_recommended")
    ][:10]

    context["surface_analysis"] = {
        "total_observations":      len(surface.observations),
        "priority_assets":         surface.priority_assets[:_MAX_PRIORITY],
        "summary_notes":           surface.summary_notes,
        "high_priority_obs":       high_obs,
        "other_observations_sample": all_obs_sample,
    }

    # Errors
    if bundle.errors:
        context["collection_errors"] = bundle.errors
        for module in bundle.errors:
            context["limitations"].append("Collection error in module: " + module)

    if not context["limitations"]:
        context["limitations"] = ["None identified."]

    return context


def _summary_counts(bundle, surface) -> dict:
    sub_count  = len(bundle.subdomains.subdomains) if bundle.subdomains else 0
    http_count = len([a for a in bundle.http.assets if a.alive]) if bundle.http else 0
    tech_count = len(bundle.tech.detections) if bundle.tech else 0
    gh_hits    = len(bundle.github.hits) if bundle.github else 0

    ct = getattr(bundle, "ct", None)
    ct_hints = len(getattr(ct, "subdomain_hints", [])) if ct else 0

    rdap = getattr(bundle, "rdap", None)
    has_rdap = bool(rdap and getattr(rdap, "registrar", ""))

    return {
        "subdomains_discovered": sub_count,
        "ct_subdomain_hints":    ct_hints,
        "rdap_enriched":         has_rdap,
        "live_http_assets":      http_count,
        "technologies_detected": tech_count,
        "github_hits":           gh_hits,
        "surface_observations":  len(surface.observations),
        "collection_errors":     len(bundle.errors),
    }
