"""
reports/markdown_writer.py
===========================
Generates Markdown report with Data Reliability section.
"""
from __future__ import annotations
from datetime import datetime
from pathlib import Path
from models.schema import AIReport, ReconBundle, SurfaceReport
from utils.logger import get_logger

logger = get_logger(__name__)

_RISK_EMOJI = {
    "high": "🔴", "medium": "🟡", "low": "🟢", "review_recommended": "🔵",
}
_SOURCE_EMOJI = {
    "ok": "✅", "mock": "⚠️", "missing": "❌", "heuristic": "🔶",
    "error": "💥", "skipped": "⏭️", "disabled": "⏭️", "unknown": "❓",
}


def _risk_badge(risk: str) -> str:
    return (_RISK_EMOJI.get(risk, "⚪") + " **" +
            risk.upper().replace("_", " ") + "**")


def write_markdown_report(
    bundle: ReconBundle,
    surface: SurfaceReport,
    ai_report: AIReport,
    output_dir: str,
    module_status: dict = None,
    allow_mock: bool = False,
    passive_only: bool = True,
) -> str:
    module_status = module_status or {}
    mock_used = any(v == "mock" for v in module_status.values())
    target    = bundle.target.raw_input
    run_id    = bundle.target.run_id
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines: list = []

    lines += [
        "# 🔍 ALR Reconnaissance Report",
        "",
        "| Field        | Value |",
        "|--------------|-------|",
        "| **Target**   | `" + target + "` |",
        "| **Type**     | " + str(bundle.target.input_type) + " |",
        "| **Run ID**   | `" + run_id + "` |",
        "| **Generated**| " + timestamp + " |",
        "",
    ]

    # Mock warning banner
    if mock_used:
        lines += [
            "> ⚠️ **MOCK DATA WARNING**: This report includes mock or fallback data",
            "> and **should not be interpreted as a real reconnaissance result.**",
            "> Run `bash ./scripts/bootstrap_tools.sh` to install real tools.",
            "",
        ]
    elif passive_only:
        lines += [
            "> 🔍 **PASSIVE-ONLY REPORT**: All findings are from passive external intelligence.",
            "> Data may be incomplete or slightly outdated. Findings are clue-based",
            "> and require manual validation. No direct probing of the target was performed.",
            "",
        ]
    else:
        lines += [
            "> 🔬 **MIXED MODE**: Report includes passive + active verification data.",
            "> Manual validation is still required for all observations.",
            "",
        ]

    lines += ["---", ""]

    # Data Reliability section
    lines += ["## 🔒 Data Reliability", ""]
    for module, status in sorted(module_status.items()):
        emoji = _SOURCE_EMOJI.get(status, "❓")
        lines.append("- **" + module + "**: " + emoji + " `" + status + "`")
    lines += [""]

    if mock_used:
        lines += [
            "> ⚠️ **This report includes mock or fallback data and should not be",
            "> interpreted as a real reconnaissance result.**",
            "",
        ]

    lines += ["---", ""]

    # Executive Summary
    lines += [
        "## 📋 Executive Summary",
        "",
        ai_report.executive_summary or "_AI summary not available._",
        "",
        "---",
        "",
    ]

    # Key Findings
    if ai_report.key_findings:
        lines += ["## 🎯 Key Findings", ""]
        for i, f in enumerate(ai_report.key_findings, 1):
            lines.append(str(i) + ". " + f)
        lines += ["", "---", ""]

    # AI Priority Assets
    if ai_report.priority_assets:
        lines += ["## 🚨 AI Priority Assets", ""]
        for pa in ai_report.priority_assets:
            asset    = pa.get("asset", "?")
            priority = pa.get("priority", "low").upper()
            reasons  = pa.get("reason", [])
            lines.append("- **`" + asset + "`** — Priority: **" + priority + "**")
            for r in reasons:
                lines.append("  - " + r)
        lines += ["", "---", ""]

    # AI Analyst Notes
    if ai_report.analyst_notes:
        lines += ["## 🔎 Analyst Notes", ""]
        for note in ai_report.analyst_notes:
            lines.append("- " + note)
        lines += ["", "---", ""]

    # AI Review Recommendations
    if ai_report.review_recommendations:
        lines += ["## 📝 Review Recommendations", ""]
        for rec in ai_report.review_recommendations:
            lines.append("- " + rec)
        lines += ["", "---", ""]

    # AI Reliability Notes
    if ai_report.reliability_notes:
        lines += ["## 🔒 AI Reliability Notes", ""]
        for note in ai_report.reliability_notes:
            lines.append("- " + note)
        lines += ["", "---", ""]

    # AI Availability Impact Notes
    if ai_report.availability_impact_notes:
        lines += ["## ⚡ Availability Impact Notes", ""]
        for note in ai_report.availability_impact_notes:
            lines.append("- " + note)
        lines += ["", "---", ""]

    # Surface Analysis
    lines += [
        "## 🗺️ Attack Surface Observations",
        "",
        "**Total observations**: " + str(len(surface.observations)),
        "",
    ]

    if surface.priority_assets:
        lines += ["### 🚨 Priority Assets", ""]
        for asset in surface.priority_assets:
            lines.append("- `" + asset + "`")
        lines += [""]

    categories: dict = {}
    for obs in surface.observations:
        categories.setdefault(obs.category, []).append(obs)

    if categories:
        lines += ["### Observations by Category", ""]
        for cat, obs_list in sorted(categories.items()):
            lines += ["#### " + cat.replace("-", " ").title(), ""]
            for obs in obs_list:
                lines += [
                    "**Asset**: `" + obs.asset + "`  ",
                    "**Risk**: " + _risk_badge(obs.risk_hint) + "  ",
                    "**Observation**: " + obs.observation + "  ",
                    "**Recommendation**: _" + obs.recommendation + "_  ",
                    "",
                ]

    lines += ["---", ""]

    # Collection Summary
    lines += ["## 📊 Collection Summary", ""]

    if bundle.subdomains and bundle.subdomains.subdomains:
        subs = bundle.subdomains.subdomains
        src  = getattr(bundle.subdomains, "data_source", "?")
        lines += ["### Subdomains (" + str(len(subs)) + " | source: " + src + ")", ""]
        lines += ["| FQDN | Source |", "|------|--------|"]
        for sub in subs[:50]:
            lines.append("| `" + sub.fqdn + "` | " + sub.source + " |")
        if len(subs) > 50:
            lines.append("| ... and " + str(len(subs) - 50) + " more | |")
        lines += [""]

    if bundle.dns and bundle.dns.records:
        src = getattr(bundle.dns, "data_source", "?")
        lines += ["### DNS Records (" + str(len(bundle.dns.records)) + " | source: " + src + ")", ""]
        lines += ["| Hostname | Type | Value |", "|----------|------|-------|"]
        for rec in bundle.dns.records[:30]:
            lines.append("| `" + rec.hostname + "` | " + str(rec.record_type) + " | `" + rec.value + "` |")
        lines += [""]

    if bundle.http and bundle.http.assets:
        alive = [a for a in bundle.http.assets if a.alive]
        src   = getattr(bundle.http, "data_source", "?")
        lines += ["### HTTP Assets (" + str(len(alive)) + " alive | source: " + src + ")", ""]
        lines += ["| URL | Status | Title | Server |", "|-----|--------|-------|--------|"]
        for asset in alive[:30]:
            title  = (asset.title or "—")[:40]
            server = asset.server or "—"
            lines.append("| `" + asset.url + "` | " + str(asset.status_code or "?") +
                         " | " + title + " | " + server + " |")
        lines += [""]

    if bundle.ports and bundle.ports.open_ports:
        src = getattr(bundle.ports, "data_source", "?")
        lines += ["### Open Ports (" + str(len(bundle.ports.open_ports)) + " | source: " + src + ")", ""]
        lines += ["| Host | Port | Service |", "|------|------|---------|"]
        for op in bundle.ports.open_ports:
            lines.append("| `" + op.host + "` | " + str(op.port) + " | " + (op.service or "?") + " |")
        lines += [""]

    if bundle.tech and bundle.tech.detections:
        src = getattr(bundle.tech, "data_source", "?")
        lines += ["### Technology Stack (" + str(len(bundle.tech.detections)) + " | source: " + src + ")", ""]
        lines += ["| Technology | Confidence | Category |", "|-----------|------------|----------|"]
        for det in bundle.tech.detections:
            conf = str(int((det.confidence or 0) * 100)) + "%" if det.confidence else "?"
            lines.append("| " + det.name + " | " + conf + " | " + (det.category or "—") + " |")
        lines += [""]

    if bundle.github:
        lines += ["### GitHub Exposure Hints (" + str(len(bundle.github.hits)) + ")", ""]
        lines += ["> " + bundle.github.note, ""]
        if bundle.github.hits:
            lines += ["| Repository | File | Hint Type |", "|-----------|------|-----------|"]
            for hit in bundle.github.hits:
                lines.append("| `" + hit.repo + "` | `" + (hit.file_path or "?") + "` | " + hit.hint_type + " |")
        lines += [""]

    # CT findings
    ct = getattr(bundle, "ct", None)
    if ct and getattr(ct, "subdomain_hints", []):
        src = getattr(ct, "data_source", "ct_passive")
        lines += ["### CT Subdomain Hints (" + str(len(ct.subdomain_hints)) + " | source: " + src + ")", ""]
        for hint in ct.subdomain_hints[:30]:
            lines.append("- `" + hint + "`")
        if len(ct.subdomain_hints) > 30:
            lines.append("- _...and " + str(len(ct.subdomain_hints) - 30) + " more_")
        lines += [""]

    # RDAP
    rdap = getattr(bundle, "rdap", None)
    if rdap and getattr(rdap, "data_source", "disabled") not in ("disabled", "error", "skipped"):
        src = rdap.data_source
        lines += ["### RDAP / WHOIS / ASN (source: " + src + ")", ""]
        if rdap.registrar:
            lines.append("- **Registrar**: " + rdap.registrar)
        if rdap.registrant:
            lines.append("- **Registrant**: " + rdap.registrant)
        if rdap.asn:
            lines.append("- **ASN**: " + rdap.asn + " (" + rdap.asn_org + ")")
        if rdap.country:
            lines.append("- **Country**: " + rdap.country)
        if rdap.name_servers:
            lines.append("- **Name Servers**: " + ", ".join(rdap.name_servers[:4]))
        if rdap.created_date:
            lines.append("- **Created**: " + rdap.created_date)
        if rdap.expiry_date:
            lines.append("- **Expires**: " + rdap.expiry_date)
        lines += [""]


        lines += ["---", "", "## ⚠️ Collection Errors", ""]
        for module, err in bundle.errors.items():
            lines.append("- **" + module + "**: " + err)
        lines += [""]

    # Footer
    lines += [
        "---",
        "",
        "_Generated by ALR — Availability Low Reconnaissance_",
        "_Run ID: `" + run_id + "` | " + timestamp + "_",
        "",
        "> All observations require manual validation by a qualified security professional.",
        "> This report does not constitute a penetration test or security audit.",
    ]

    content  = "\n".join(lines)
    out_path = Path(output_dir) / "report.md"
    out_path.write_text(content, encoding="utf-8")
    logger.info("Markdown report written: %s", out_path)
    return str(out_path)
