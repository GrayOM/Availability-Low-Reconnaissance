"""
reports/json_writer.py
=======================
Writes normalized output.json with execution_metadata trust signals.
"""
from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from models.schema import AIReport, ReconBundle, SurfaceReport
from utils.logger import get_logger

logger = get_logger(__name__)


def _serialize(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(i) for i in obj]
    return obj


def write_json_output(
    bundle: ReconBundle,
    surface: SurfaceReport,
    ai_report: AIReport,
    output_dir: str,
    module_status: dict = None,
    allow_mock: bool = False,
    strict_tools: bool = False,
    passive_only: bool = True,
) -> str:
    module_status = module_status or {}
    mock_used = any(v == "mock" for v in module_status.values())
    mock_modules = [k for k, v in module_status.items() if v == "mock"]

    output = {
        "meta": {
            "schema_version": "2.0",
            "tool":           "ALR — Availability Low Reconnaissance",
            "run_id":         bundle.target.run_id,
            "target":         bundle.target.raw_input,
            "input_type":     bundle.target.input_type,
            "generated_at":   datetime.utcnow().isoformat(),
        },
        "execution_metadata": {
            "pipeline_mode": "passive-only" if passive_only else "passive+active",
            "mock_used":     mock_used,
            "allow_mock":    allow_mock,
            "strict_tools":  strict_tools,
            "mock_modules":  mock_modules,
            "module_status": module_status,
            "trust_level": (
                "DEMO_ONLY — contains mock data" if mock_used
                else "PASSIVE — data from passive external sources"
                if passive_only
                else "MIXED — passive + active verification data"
            ),
            "passive_only_note": (
                "All findings are from passive external intelligence. "
                "Passive data may be incomplete or slightly outdated. "
                "Findings are clue-based and require manual validation."
            ) if passive_only else None,
        },
        "target_context":  _serialize(bundle.target),
        "collected_data": {
            "subdomains":  _serialize(bundle.subdomains),
            "ct":          _serialize(bundle.ct),
            "rdap":        _serialize(bundle.rdap),
            "http_assets": _serialize(bundle.http),
            "tech_stack":  _serialize(bundle.tech),
            "github":      _serialize(bundle.github),
            "dns":         _serialize(bundle.dns),
            "open_ports":  _serialize(bundle.ports),
        },
        "collection_errors":  bundle.errors,
        "surface_analysis":   _serialize(surface),
        "ai_metadata": {
            "ai_enabled":   ai_report.ai_enabled,
            "ai_provider":  ai_report.ai_provider,
            "model_used":   ai_report.model_used,
            "generated_at": _serialize(ai_report.generated_at),
            "disclaimer":   ai_report.disclaimer,
        },
        "ai_report": {
            "executive_summary":          ai_report.executive_summary,
            "key_findings":               ai_report.key_findings,
            "priority_assets":            ai_report.priority_assets,
            "analyst_notes":              ai_report.analyst_notes,
            "review_recommendations":     ai_report.review_recommendations,
            "reliability_notes":          ai_report.reliability_notes,
            "availability_impact_notes":  ai_report.availability_impact_notes,
        },
    }

    out_path = Path(output_dir) / "output.json"
    out_path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    logger.info("JSON output written: %s", out_path)
    return str(out_path)
