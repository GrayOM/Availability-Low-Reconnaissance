"""
ai/report_generator.py
=======================
Structured reconnaissance report generator.

ARCHITECTURE NOTE (v8+):
  The active AI API path has been removed from the default workflow.
  ALR now generates a structured report directly from surface analysis data.
  The PDF is the primary final artifact — users can upload it to ChatGPT
  or another assistant for manual interpretation if desired.

  No OPENAI_API_KEY, no ANTHROPIC_API_KEY, no external API billing required.

The _fallback_report() function now IS the report generator.
It produces a clean, structured AIReport from surface analysis data.
"""
from __future__ import annotations

from datetime import datetime

from models.schema import AIReport, ReconBundle, SurfaceReport
from utils.logger import get_logger
from ai.prompt_templates import FALLBACK_DISCLAIMER, SPARSE_DATA_NOTE

logger = get_logger(__name__)


def generate_ai_report(
    bundle: ReconBundle,
    surface: SurfaceReport,
    module_status: dict = None,
    passive_only: bool = True,
) -> AIReport:
    """
    Generate a structured reconnaissance report from surface analysis data.

    No external AI API is called. The report is derived entirely from
    the normalized data collected during the ALR pipeline.

    Returns an AIReport suitable for JSON, Markdown, and PDF export.
    """
    module_status = module_status or {}
    logger.info("Generating structured report...")
    return _build_structured_report(bundle, surface, module_status, passive_only)


def _build_structured_report(
    bundle: ReconBundle,
    surface: SurfaceReport,
    module_status: dict,
    passive_only: bool,
) -> AIReport:
    """
    Build a structured, professional report from surface analysis data.
    Conservative language enforced — no confirmed vulnerability claims.
    """
    target     = bundle.target.raw_input
    obs_count  = len(surface.observations)
    high_count = sum(1 for o in surface.observations if o.risk_hint == "high")
    med_count  = sum(1 for o in surface.observations if o.risk_hint == "medium")
    sparse     = obs_count < 3

    # Executive summary
    cat_count = len(set(o.category for o in surface.observations))

    if obs_count == 0:
        exec_summary = (
            "Passive and lightweight reconnaissance was conducted against "
            + target + ". The collection returned limited externally visible indicators. "
            "This may reflect a minimal public footprint or a gap in passive data coverage. "
            "No surface observations were identified from the current evidence set. "
            "Further manual review or active collection may be warranted."
        )
    elif sparse:
        obs_word = "observation was" if obs_count == 1 else "observations were"
        exec_summary = (
            "Passive and lightweight reconnaissance was conducted against "
            + target + ". "
            + str(obs_count) + " surface " + obs_word + " identified. "
            "The evidence set is limited and may not fully represent "
            "non-public or recently changed assets. "
            "All findings are heuristic and require manual validation."
        )
    else:
        cat_word = "category" if cat_count == 1 else "categories"
        parts = [
            "Passive and lightweight reconnaissance was conducted against "
            + target + ". ",
            str(obs_count) + " surface observations were identified across "
            + str(cat_count) + " " + cat_word + ". ",
        ]
        if high_count:
            h_word = "observation requires" if high_count == 1 else "observations require"
            parts.append(str(high_count) + " " + h_word + " high-priority review. ")
        if med_count:
            m_word = "medium-priority observation was" if med_count == 1 else "medium-priority observations were"
            parts.append(str(med_count) + " " + m_word + " noted. ")
        parts.append("All findings are heuristic and require manual validation.")
        exec_summary = "".join(parts)

    # Key findings — top 10
    key_findings = [
        "[" + o.risk_hint.upper() + "] " + o.asset + ": " + o.observation
        for o in surface.observations[:10]
    ]

    # Priority assets
    priority_assets = [
        {"asset": a, "reason": ["flagged by surface analysis"], "priority": "review"}
        for a in surface.priority_assets[:8]
    ]

    # Analyst notes from surface summary
    analyst_notes = list(surface.summary_notes)

    # Recommendations — context-aware
    review_recommendations = []
    if high_count:
        review_recommendations.append(
            "Manually review all high-risk observations before drawing conclusions."
        )
    if surface.priority_assets:
        review_recommendations.append(
            "Validate ownership and intended exposure of each priority asset."
        )
    ct = getattr(bundle, "ct", None)
    ct_hints = getattr(ct, "subdomain_hints", []) if ct else []
    if ct_hints:
        review_recommendations.append(
            "Cross-reference Certificate Transparency hints against your known asset inventory."
        )
    rdap_local = getattr(bundle, "rdap", None)
    expiry = getattr(rdap_local, "expiry_date", "") if rdap_local else ""
    if expiry:
        review_recommendations.append(
            "Confirm domain registration renewal is planned to avoid unintended expiry."
        )
    if bundle.http and bundle.http.assets:
        review_recommendations.append(
            "Review each reachable HTTP asset for intended public exposure and access controls."
        )
    if not review_recommendations:
        review_recommendations.append(
            "No specific high-priority items were flagged. "
            "Consider broader active collection for a more complete picture."
        )
    review_recommendations.append(
        "This PDF may be uploaded to ChatGPT or another AI assistant "
        "for further manual interpretation."
    )

    # Reliability notes
    reliability_notes = [
        "All data is from passive and/or lightweight active sources.",
        "Findings are clue-based and require manual validation.",
        "No active exploitation, port scanning, or brute-force was performed.",
    ]
    if sparse:
        reliability_notes.append(SPARSE_DATA_NOTE)

    # Availability impact notes
    availability_impact_notes = [
        "Data was collected using passive intelligence and lightweight HTTP probing.",
        "No aggressive or intrusive methods were used.",
    ]
    mock_used = any(v == "mock" for v in module_status.values())
    if mock_used:
        availability_impact_notes.append(
            "WARNING: Mock/fallback data was used — results do not reflect real collection."
        )

    return AIReport(
        executive_summary         = exec_summary,
        key_findings              = key_findings,
        priority_assets           = priority_assets,
        analyst_notes             = analyst_notes,
        review_recommendations    = review_recommendations,
        reliability_notes         = reliability_notes,
        availability_impact_notes = availability_impact_notes,
        model_used                = "structured-report",
        ai_enabled                = False,
        ai_provider               = "none",
        disclaimer                = _disclaimer(),
    )


def _disclaimer() -> str:
    return (
        "This report is generated from passive OSINT and lightweight active data. "
        "Observations are clue-based and require manual validation. "
        "No confirmed vulnerabilities are asserted."
    )
