"""
reports/pdf_writer.py
======================
PDF report generator for ALR — Availability Low Reconnaissance.

This module produces a structured, professional PDF report from
the normalized data collected during the ALR pipeline.

The PDF is the primary final artifact. It is:
  - readable without any additional tooling
  - structured for professional review
  - suitable for manual upload to ChatGPT for interpretation
  - conservative in language (no confirmed vulnerability claims)

Sections:
  1. Cover / Title Block
  2. Executive Summary
  3. Data Collection Scope & Reliability
  4. Reconnaissance Summary (counts/totals)
  5. Surface Analysis Findings
  6. Priority Review Targets
  7. Infrastructure & Ownership Context
  8. HTTP Exposure Summary
  9. Public Exposure Hints (GitHub, if any)
  10. Limitations & Notes
  11. Appendix — Output References

Install: pip install reportlab
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
_ACCENT   = (0.12, 0.30, 0.60)   # professional dark blue
_DARK     = (0.13, 0.13, 0.18)   # near-black body text
_MID      = (0.35, 0.35, 0.40)   # secondary text
_WARN     = (0.72, 0.20, 0.15)   # red for warnings/mock/high
_ORANGE   = (0.75, 0.40, 0.05)   # orange for medium
_GREEN    = (0.06, 0.50, 0.30)   # green for passive / low
_LIGHT_BG = (0.95, 0.97, 1.00)   # page header/table background tint
_BORDER   = (0.78, 0.84, 0.92)   # subtle border

_RISK_COLORS = {
    "high":               _WARN,
    "medium":             _ORANGE,
    "low":                _GREEN,
    "review_recommended": (0.12, 0.30, 0.60),
}

_SOURCE_COLORS = {
    "passive":      _GREEN,
    "ct_passive":   _GREEN,
    "rdap_passive": _GREEN,
    "light_active": (0.20, 0.50, 0.80),
    "heuristic":    _ORANGE,
    "mock":         _WARN,
    "disabled":     _MID,
    "error":        _WARN,
    "skipped":      _MID,
    "ok":           _GREEN,
}

_DISCLAIMER = (
    "All observations in this report are based on passive and/or lightweight "
    "active reconnaissance data. Findings are clue-based pattern indicators "
    "and do NOT constitute confirmed vulnerabilities. Manual validation by a "
    "qualified security professional is required before drawing conclusions or "
    "taking action on any observation listed here."
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def write_pdf_report(
    bundle,
    surface,
    ai_report,
    md_path: str,
    output_dir: str,
    target: str,
    run_id: str,
    module_status: dict = None,
    passive_only: bool = True,
    allow_mock: bool = False,
    # legacy compat — ignored; AI is no longer part of the active path
    ai_enabled: bool = False,
) -> Optional[str]:
    """
    Render a structured PDF reconnaissance report.

    Parameters
    ----------
    bundle      : ReconBundle — collected reconnaissance data
    surface     : SurfaceReport — heuristic findings
    ai_report   : AIReport — structured report (no AI API needed)
    md_path     : str — path to the Markdown report (for appendix reference)
    output_dir  : str — directory to write report.pdf
    target      : str — target domain or IP
    run_id      : str — unique run identifier
    module_status : dict — module name -> data source label
    passive_only  : bool — True if no active tools were used
    allow_mock    : bool — True if mock/fallback data was used

    Returns
    -------
    str or None — path to written PDF, or None if reportlab unavailable
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib import colors as rl_colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak, KeepTogether,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    except ImportError:
        logger.warning(
            "reportlab not installed — skipping PDF export. "
            "Install with: pip install reportlab"
        )
        return None

    module_status = module_status or {}
    mock_used     = any(v == "mock" for v in module_status.values())
    timestamp     = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    mode_label    = "Passive-Only" if passive_only else "Passive + Light Active"
    out_path      = Path(output_dir) / "report.pdf"

    # ----------------------------------------------------------------
    # Document
    # ----------------------------------------------------------------
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=2.2 * cm,
        rightMargin=2.2 * cm,
        topMargin=2.4 * cm,
        bottomMargin=2.4 * cm,
        title="ALR Reconnaissance Report — " + target,
        author="ALR — Availability Low Reconnaissance",
        subject="Passive reconnaissance findings for " + target,
    )

    # ----------------------------------------------------------------
    # Style definitions
    # ----------------------------------------------------------------
    base = getSampleStyleSheet()

    def _ps(name, parent="Normal", **kw):
        s = ParagraphStyle(name, parent=base[parent])
        for k, v in kw.items():
            setattr(s, k, v)
        return s

    C = rl_colors.Color   # shorthand

    s_title    = _ps("T",   "Title",    fontSize=22, textColor=C(*_ACCENT),
                     spaceAfter=2, spaceBefore=0)
    s_subtitle = _ps("ST",  "Normal",   fontSize=10, textColor=C(*_MID),
                     spaceAfter=6)
    s_h1       = _ps("H1",  "Heading1", fontSize=13, textColor=C(*_ACCENT),
                     spaceBefore=16, spaceAfter=5, leading=18)
    s_h2       = _ps("H2",  "Heading2", fontSize=10, textColor=C(*_DARK),
                     spaceBefore=10, spaceAfter=3, leading=14)
    s_body     = _ps("B",   "Normal",   fontSize=9,  leading=14,
                     textColor=C(*_DARK), spaceAfter=4)
    s_small    = _ps("SM",  "Normal",   fontSize=7.5, textColor=C(*_MID),
                     spaceAfter=2)
    s_warn     = _ps("W",   "Normal",   fontSize=9,
                     textColor=C(*_WARN), spaceBefore=4, spaceAfter=4)
    s_bullet   = _ps("BL",  "Normal",   fontSize=9,  leading=13,
                     leftIndent=14, spaceAfter=2, textColor=C(*_DARK))
    s_center   = _ps("CC",  "Normal",   fontSize=7.5, alignment=TA_CENTER,
                     textColor=C(*_MID))
    s_tag_pass = _ps("TP",  "Normal",   fontSize=8,  textColor=C(*_GREEN))
    s_tag_warn = _ps("TW",  "Normal",   fontSize=8,  textColor=C(*_WARN))
    s_italic   = _ps("IT",  "Normal",   fontSize=8.5, textColor=C(*_MID),
                     spaceAfter=3)

    story = []

    def hr(thick=0.5, color=_BORDER):
        return HRFlowable(width="100%", color=C(*color), thickness=thick, spaceAfter=4)

    def spacer(h=0.25):
        return Spacer(1, h * cm)

    def heading1(text):
        clean = re.sub(r"[^\x20-\x7E]", "", text).strip()
        return [spacer(0.1), Paragraph(clean, s_h1), hr(0.4)]

    def heading2(text):
        clean = re.sub(r"[^\x20-\x7E]", "", text).strip()
        return [Paragraph(clean, s_h2)]

    def body(text):
        return Paragraph(_safe_xml(text), s_body)

    def bullet(text):
        return Paragraph("&#x2022;  " + _safe_xml(text), s_bullet)

    def _tbl(data, col_widths, style_cmds):
        """Build a reportlab Table with standard base styling."""
        ts = TableStyle([
            ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
            ("GRID",          (0, 0), (-1, -1), 0.3, C(*_BORDER)),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ] + style_cmds)
        t = Table(data, colWidths=col_widths)
        t.setStyle(ts)
        return t

    # ================================================================
    # SECTION 1 — COVER / TITLE BLOCK
    # ================================================================
    story.append(Paragraph("ALR Reconnaissance Report", s_title))
    story.append(Paragraph("Availability Low Reconnaissance — Passive-First OSINT", s_subtitle))
    story.append(hr(1.5, _ACCENT))
    story.append(spacer(0.3))

    meta_rows = [
        ["Target",    target],
        ["Run ID",    run_id],
        ["Generated", timestamp],
        ["Mode",      mode_label],
        ["Mock Data", "YES — for demo/dev only" if mock_used else "No"],
    ]
    meta_ts = [
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",    (0, 0), (0, -1), C(*_ACCENT)),
        ("TEXTCOLOR",    (1, 0), (1, -1), C(*_DARK)),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C(*_LIGHT_BG), rl_colors.white]),
    ]
    if mock_used:
        meta_ts.append(("TEXTCOLOR", (1, 4), (1, 4), C(*_WARN)))
    story.append(_tbl(meta_rows, ["30%", "70%"], meta_ts))
    story.append(spacer(0.4))

    # Mode banner
    if mock_used:
        story.append(Paragraph(
            "WARNING: This report contains MOCK/FALLBACK data. "
            "Results do NOT reflect real reconnaissance. "
            "Install real tools and run without --allow-mock for production use.",
            s_warn,
        ))
    elif passive_only:
        story.append(Paragraph(
            "PASSIVE-ONLY REPORT — No direct probing of the target was performed. "
            "All findings are derived from public passive sources. "
            "Data may be incomplete or outdated.",
            s_italic,
        ))
    else:
        story.append(Paragraph(
            "MIXED MODE — Passive intelligence combined with lightweight HTTP verification. "
            "No aggressive scanning was performed.",
            s_italic,
        ))
    story.append(spacer(0.2))

    # ================================================================
    # SECTION 2 — EXECUTIVE SUMMARY
    # ================================================================
    story += heading1("Executive Summary")
    story.append(body(ai_report.executive_summary or
                      "Reconnaissance was conducted against " + target + ". "
                      "See findings below."))
    story.append(spacer(0.2))

    # ================================================================
    # SECTION 3 — DATA COLLECTION SCOPE & RELIABILITY
    # ================================================================
    story += heading1("Data Collection Scope & Reliability")
    story.append(body(
        "The following table shows which data collection modules were active "
        "during this run and the type of data source each represents."
    ))
    story.append(spacer(0.1))

    if module_status:
        rel_header = [["Module", "Source Type", "Notes"]]
        source_notes = {
            "passive":      "Public passive query — no target contact",
            "ct_passive":   "Certificate Transparency log (public, passive)",
            "rdap_passive": "RDAP/WHOIS/ASN registry data (public, passive)",
            "light_active": "Lightweight HTTP probe — minimal footprint",
            "heuristic":    "Inferred from HTTP metadata (no external call)",
            "mock":         "MOCK data — not real reconnaissance",
            "disabled":     "Module disabled for this run",
            "error":        "Module encountered an error — data absent",
            "skipped":      "Skipped (not applicable for this target type)",
        }
        rel_rows = rel_header[:]
        for mod, status in sorted(module_status.items()):
            note = source_notes.get(status.lower(), "")
            rel_rows.append([mod, status, note])
        rel_ts = [
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND",   (0, 0), (-1, 0), C(*_ACCENT)),
            ("TEXTCOLOR",    (0, 0), (-1, 0), rl_colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [rl_colors.white, C(*_LIGHT_BG)]),
        ]
        for i, (mod, status) in enumerate(sorted(module_status.items()), start=1):
            col = _SOURCE_COLORS.get(status.lower(), _DARK)
            rel_ts.append(("TEXTCOLOR", (1, i), (1, i), C(*col)))
        story.append(_tbl(rel_rows, ["25%", "25%", "50%"], rel_ts))
    else:
        story.append(body("No module status data available."))
    story.append(spacer(0.2))

    # ================================================================
    # SECTION 4 — RECONNAISSANCE SUMMARY
    # ================================================================
    story += heading1("Reconnaissance Summary")

    sub_count  = len(bundle.subdomains.subdomains) if bundle.subdomains else 0
    http_count = len(bundle.http.assets) if bundle.http else 0
    http_alive = sum(1 for a in bundle.http.assets if a.alive) if bundle.http else 0
    port_count = len(bundle.ports.open_ports) if bundle.ports else 0
    gh_count   = len(bundle.github.hits) if bundle.github and bundle.github.hits else 0

    ct = getattr(bundle, "ct", None)
    ct_count = len(getattr(ct, "subdomain_hints", [])) if ct else 0
    ct_source = getattr(ct, "data_source", "disabled")

    rdap = getattr(bundle, "rdap", None)
    rdap_source = getattr(rdap, "data_source", "disabled")
    rdap_asn    = getattr(rdap, "asn", "") if rdap else ""

    obs_count  = len(surface.observations)
    high_count = sum(1 for o in surface.observations if o.risk_hint == "high")
    med_count  = sum(1 for o in surface.observations if o.risk_hint == "medium")
    prio_count = len(surface.priority_assets)

    summary_rows = [
        ["Data Point",                       "Value"],
        ["Subdomains discovered",             str(sub_count)],
        ["CT log subdomain hints",            str(ct_count) + (" (source: " + ct_source + ")" if ct_source != "ct_passive" else "")],
        ["RDAP/WHOIS/ASN data",               rdap_source if rdap_source != "rdap_passive" else "Available"],
        ["ASN identified",                    rdap_asn or "—"],
        ["HTTP assets identified",            str(http_count)],
        ["HTTP assets reachable",             str(http_alive)],
        ["Open ports detected",               str(port_count)],
        ["GitHub public hints",               str(gh_count) if gh_count else "—"],
        ["Surface observations total",        str(obs_count)],
        ["  High-priority observations",      str(high_count)],
        ["  Medium-priority observations",    str(med_count)],
        ["Priority review targets",           str(prio_count)],
    ]
    sum_ts = [
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND",   (0, 0), (-1, 0), C(*_ACCENT)),
        ("TEXTCOLOR",    (0, 0), (-1, 0), rl_colors.white),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [rl_colors.white, C(*_LIGHT_BG)]),
        ("FONTNAME",     (0, 1), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",    (0, 1), (0, -1), C(*_DARK)),
    ]
    if high_count > 0:
        # Find the high row index
        for ri, row in enumerate(summary_rows):
            if "High-priority" in row[0]:
                sum_ts.append(("TEXTCOLOR", (1, ri), (1, ri), C(*_WARN)))
    story.append(_tbl(summary_rows, ["55%", "45%"], sum_ts))
    story.append(spacer(0.2))

    # ================================================================
    # SECTION 5 — SURFACE ANALYSIS FINDINGS
    # ================================================================
    story += heading1("Surface Analysis Findings")

    if not surface.observations:
        story.append(body(
            "The current passive and light-active collection identified "
            "limited externally visible indicators for this target. "
            "No strong review targets were identified from the available data. "
            "This may indicate a low externally-visible footprint, or that "
            "additional collection methods would provide more context."
        ))
    else:
        story.append(body(
            str(obs_count) + " heuristic observation(s) were identified. "
            "All findings are pattern-based and require manual validation."
        ))
        story.append(spacer(0.1))

        find_header = [["Asset", "Category", "Risk", "Observation"]]
        find_rows = find_header[:]
        find_ts = [
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND",   (0, 0), (-1, 0), C(*_ACCENT)),
            ("TEXTCOLOR",    (0, 0), (-1, 0), rl_colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [rl_colors.white, C(*_LIGHT_BG)]),
            ("FONTSIZE",     (0, 0), (-1, -1), 8),
            ("WORDWRAP",     (0, 0), (-1, -1), True),
        ]
        for i, obs in enumerate(surface.observations, start=1):
            risk_str = obs.risk_hint.upper().replace("_", " ")
            find_rows.append([
                obs.asset[:40] + ("…" if len(obs.asset) > 40 else ""),
                obs.category,
                risk_str,
                obs.observation[:120] + ("…" if len(obs.observation) > 120 else ""),
            ])
            risk_color = _RISK_COLORS.get(obs.risk_hint, _DARK)
            find_ts.append(("TEXTCOLOR", (2, i), (2, i), C(*risk_color)))
            find_ts.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
        story.append(_tbl(find_rows, ["22%", "16%", "12%", "50%"], find_ts))

        # Recommendations
        story.append(spacer(0.15))
        story += heading2("Recommendations")
        for rec in ai_report.review_recommendations:
            story.append(bullet(rec))

    story.append(spacer(0.2))

    # ================================================================
    # SECTION 6 — PRIORITY REVIEW TARGETS
    # ================================================================
    story += heading1("Priority Review Targets")

    if not surface.priority_assets:
        story.append(body(
            "No high-priority review targets were identified from the current "
            "evidence set. This does not indicate the target is free of risk — "
            "it reflects the limits of the current passive evidence."
        ))
    else:
        story.append(body(
            str(prio_count) + " asset(s) flagged for priority review "
            "based on heuristic pattern matching. Manual validation required."
        ))
        story.append(spacer(0.1))
        prio_rows = [["#", "Asset", "Priority"]]
        prio_ts = [
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), C(*_ACCENT)),
            ("TEXTCOLOR",  (0, 0), (-1, 0), rl_colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [rl_colors.white, C(*_LIGHT_BG)]),
        ]
        for i, pa in enumerate(ai_report.priority_assets, start=1):
            prio_rows.append([str(i), pa.get("asset", ""), pa.get("priority", "review")])
            prio_ts.append(("TEXTCOLOR", (2, i), (2, i), C(*_WARN)))
        story.append(_tbl(prio_rows, ["8%", "72%", "20%"], prio_ts))
    story.append(spacer(0.2))

    # ================================================================
    # SECTION 7 — INFRASTRUCTURE & OWNERSHIP CONTEXT
    # ================================================================
    story += heading1("Infrastructure & Ownership Context")

    rdap_rows = []
    if rdap and rdap_source not in ("disabled", "error", "skipped"):
        for field_name, attr in [
            ("Registrar",    "registrar"),
            ("Organization", "org"),
            ("Country",      "country"),
            ("Created",      "creation_date"),
            ("Expires",      "expiry_date"),
            ("Name Servers", "nameservers"),
            ("IP Address",   "ip_address"),
            ("ASN",          "asn"),
            ("ASN Org",      "asn_org"),
        ]:
            val = getattr(rdap, attr, None)
            if val:
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val[:5])
                rdap_rows.append([field_name, str(val)])

    if rdap_rows:
        rdap_ts = [
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR",     (0, 0), (0, -1), C(*_ACCENT)),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C(*_LIGHT_BG), rl_colors.white]),
        ]
        story.append(_tbl(rdap_rows, ["35%", "65%"], rdap_ts))
    else:
        story.append(body(
            "RDAP/WHOIS/ASN data was not available for this run. "
            "This may be due to network restrictions, RDAP service unavailability, "
            "or the target being an IP address without RDAP coverage."
        ))
    story.append(spacer(0.2))

    # ================================================================
    # SECTION 8 — HTTP EXPOSURE SUMMARY
    # ================================================================
    story += heading1("HTTP Exposure Summary")

    if bundle.http and bundle.http.assets:
        story.append(body(
            str(http_count) + " HTTP asset(s) were identified. "
            + str(http_alive) + " responded as reachable."
        ))
        story.append(spacer(0.1))
        http_header = [["URL", "Status", "Title", "Server"]]
        http_rows = http_header[:]
        http_ts = [
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), C(*_ACCENT)),
            ("TEXTCOLOR",  (0, 0), (-1, 0), rl_colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [rl_colors.white, C(*_LIGHT_BG)]),
            ("FONTSIZE",   (0, 0), (-1, -1), 7.5),
        ]
        for asset in bundle.http.assets[:20]:
            url_short = asset.url[:45] + ("…" if len(asset.url) > 45 else "")
            title = (asset.title or "—")[:35] + ("…" if (asset.title or "") and len(asset.title) > 35 else "")
            server = (asset.server or asset.webserver or "—")[:20]
            status = str(asset.status_code) if asset.status_code else "—"
            http_rows.append([url_short, status, title, server])
        story.append(_tbl(http_rows, ["38%", "10%", "32%", "20%"], http_ts))
    else:
        story.append(body(
            "No HTTP assets were identified or verified during this run. "
            "This may indicate the target has no web-facing services, "
            "httpx was unavailable, or the subdomain list was empty."
        ))
    story.append(spacer(0.2))

    # ================================================================
    # SECTION 9 — PUBLIC EXPOSURE HINTS
    # ================================================================
    story += heading1("Public Exposure Hints")

    if bundle.github and bundle.github.hits:
        story.append(body(
            str(gh_count) + " public GitHub reference(s) found for this target. "
            "These are low-confidence passive observations from public repositories. "
            "Manual validation is required."
        ))
        story.append(spacer(0.1))
        gh_rows = [["Repository", "Type", "Notes"]]
        for hit in bundle.github.hits[:10]:
            gh_rows.append([
                hit.repo[:40],
                hit.hint_type,
                (hit.snippet or "")[:40] if hit.snippet else "—",
            ])
        gh_ts = [
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), C(*_ACCENT)),
            ("TEXTCOLOR",  (0, 0), (-1, 0), rl_colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [rl_colors.white, C(*_LIGHT_BG)]),
        ]
        story.append(_tbl(gh_rows, ["45%", "20%", "35%"], gh_ts))
    else:
        story.append(body(
            "No GitHub public exposure hints were identified or this check was not enabled. "
            "Use --enable-github-check to include this in future runs."
        ))
    story.append(spacer(0.2))

    # ================================================================
    # SECTION 10 — LIMITATIONS & NOTES
    # ================================================================
    story += heading1("Limitations & Notes")

    limitations = [
        "This report is based on passive OSINT and lightweight active collection. "
        "It does not represent a comprehensive security assessment.",
        "Passive collection cannot observe internal systems, authenticated endpoints, "
        "or assets that do not appear in public data sources.",
        "Certificate Transparency logs and RDAP data reflect public registry information "
        "and may lag behind real-world changes by hours or days.",
        "Subdomain discovery is limited to public resolution and passive databases — "
        "private or recently provisioned subdomains may not appear.",
        "All findings are heuristic pattern indicators. None constitute confirmed "
        "vulnerabilities without further manual investigation.",
        "This PDF may be uploaded to ChatGPT or another AI assistant for manual "
        "interpretation of findings. The assistant will not have access to raw "
        "data beyond what is presented in this report.",
    ]
    if mock_used:
        limitations.insert(0,
            "CRITICAL: This run used MOCK/FALLBACK DATA. "
            "None of the findings represent real reconnaissance output."
        )
    for lim in limitations:
        story.append(bullet(lim))
    story.append(spacer(0.2))

    # ================================================================
    # SECTION 11 — APPENDIX
    # ================================================================
    story += heading1("Appendix — Output References")

    story.append(body("The following output files were generated during this run:"))
    output_dir_path = Path(output_dir)
    for fname, desc in [
        ("output.json",  "Structured JSON — full normalized data and surface findings"),
        ("report.md",    "Markdown report — human-readable summary of findings"),
        ("report.pdf",   "This PDF — primary deliverable for review and distribution"),
    ]:
        fpath = output_dir_path / fname
        exists = "Available" if fpath.exists() else "Not generated"
        story.append(bullet(fname + " — " + desc + " [" + exists + "]"))

    story.append(spacer(0.1))
    story.append(body(
        "Run ID " + run_id + " — Output directory: " + str(output_dir_path.resolve())
    ))

    # ================================================================
    # FOOTER — DISCLAIMER
    # ================================================================
    story.append(spacer(0.4))
    story.append(hr(0.5))
    story.append(spacer(0.1))
    story += heading2("Disclaimer")
    story.append(Paragraph(_safe_xml(_DISCLAIMER), s_small))
    story.append(spacer(0.15))
    story.append(Paragraph(
        "Generated by ALR — Availability Low Reconnaissance  |  Run ID: " +
        run_id + "  |  " + timestamp,
        s_center,
    ))

    # ================================================================
    # BUILD
    # ================================================================
    try:
        doc.build(story)
        logger.info("PDF report written: %s", out_path)
        return str(out_path)
    except Exception as exc:
        logger.error("PDF build failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_xml(text: str) -> str:
    """Escape XML special characters for reportlab Paragraph."""
    text = str(text)
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    # Remove non-ASCII (emoji, etc.) that reportlab can't render with Helvetica
    text = re.sub(r"[^\x20-\x7E]", " ", text)
    # Convert Markdown bold
    text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
    return text
