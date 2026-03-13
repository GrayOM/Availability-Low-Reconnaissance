"""
tests/test_ai_layer.py
=======================
Tests for the structured report generator.

The AI API path has been removed from the default ALR workflow.
These tests verify:
- structured report generation without any AI API call
- fallback behavior remains consistent
- no external API keys required
- source labels correctly propagated
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_ctx(domain="example.com", enable_ai=False):
    from models.schema import TargetContext, InputType
    tmpdir = tempfile.mkdtemp()
    return TargetContext(
        raw_input=domain, input_type=InputType.DOMAIN,
        domain=domain, run_id="testabc", output_dir=tmpdir,
        timeout=10, enable_ai=enable_ai,
    )


def _make_bundle(ctx, with_subs=True, with_http=True):
    from models.schema import (
        ReconBundle, SubdomainResult, Subdomain, HTTPProfile, HTTPAsset,
    )
    subs = None
    if with_subs:
        subs = SubdomainResult(
            target=ctx.raw_input,
            subdomains=[
                Subdomain("admin.example.com"),
                Subdomain("api.example.com"),
                Subdomain("dev.example.com"),
            ],
        )
        subs.data_source = "passive"

    http = None
    if with_http:
        http = HTTPProfile(
            target=ctx.raw_input,
            assets=[
                HTTPAsset(
                    url="https://admin.example.com",
                    status_code=200, title="Admin Panel",
                    server="nginx", alive=True,
                ),
            ],
        )
        http.data_source = "light_active"

    return ReconBundle(target=ctx, subdomains=subs, http=http)


def _make_surface(bundle):
    from analyzers.surface_analyzer import run_surface_analysis
    return run_surface_analysis(bundle)


# ---------------------------------------------------------------------------
# Report generator tests
# ---------------------------------------------------------------------------

class TestStructuredReportGenerator(unittest.TestCase):

    def setUp(self):
        self.ctx     = _make_ctx()
        self.bundle  = _make_bundle(self.ctx)
        self.surface = _make_surface(self.bundle)

    def test_generate_returns_ai_report_instance(self):
        from models.schema import AIReport
        from ai.report_generator import generate_ai_report
        result = generate_ai_report(self.bundle, self.surface)
        self.assertIsInstance(result, AIReport)

    def test_ai_disabled_by_default(self):
        from ai.report_generator import generate_ai_report
        result = generate_ai_report(self.bundle, self.surface)
        self.assertFalse(result.ai_enabled)

    def test_ai_provider_is_none(self):
        from ai.report_generator import generate_ai_report
        result = generate_ai_report(self.bundle, self.surface)
        self.assertEqual(result.ai_provider, "none")

    def test_model_used_is_structured(self):
        from ai.report_generator import generate_ai_report
        result = generate_ai_report(self.bundle, self.surface)
        self.assertEqual(result.model_used, "structured-report")

    def test_executive_summary_nonempty(self):
        from ai.report_generator import generate_ai_report
        result = generate_ai_report(self.bundle, self.surface)
        self.assertGreater(len(result.executive_summary), 30)

    def test_key_findings_list(self):
        from ai.report_generator import generate_ai_report
        result = generate_ai_report(self.bundle, self.surface)
        self.assertIsInstance(result.key_findings, list)

    def test_review_recommendations_list(self):
        from ai.report_generator import generate_ai_report
        result = generate_ai_report(self.bundle, self.surface)
        self.assertIsInstance(result.review_recommendations, list)
        self.assertGreater(len(result.review_recommendations), 0)

    def test_reliability_notes_nonempty(self):
        from ai.report_generator import generate_ai_report
        result = generate_ai_report(self.bundle, self.surface)
        self.assertGreater(len(result.reliability_notes), 0)

    def test_no_openai_import_required(self):
        """Report generation must not import openai."""
        with patch.dict("sys.modules", {"openai": None}):
            from ai.report_generator import generate_ai_report
            result = generate_ai_report(self.bundle, self.surface)
            self.assertFalse(result.ai_enabled)

    def test_no_anthropic_import_required(self):
        """Report generation must not import anthropic."""
        with patch.dict("sys.modules", {"anthropic": None}):
            from ai.report_generator import generate_ai_report
            result = generate_ai_report(self.bundle, self.surface)
            self.assertFalse(result.ai_enabled)

    def test_disclaimer_present(self):
        from ai.report_generator import generate_ai_report
        result = generate_ai_report(self.bundle, self.surface)
        self.assertGreater(len(result.disclaimer), 10)

    def test_mock_noted_in_availability_notes(self):
        from ai.report_generator import generate_ai_report
        result = generate_ai_report(
            self.bundle, self.surface,
            module_status={"subdomains": "mock", "http": "mock"},
        )
        combined = " ".join(result.availability_impact_notes).lower()
        self.assertIn("mock", combined)

    def test_sparse_bundle_returns_complete_report(self):
        from models.schema import ReconBundle
        from ai.report_generator import generate_ai_report
        from analyzers.surface_analyzer import run_surface_analysis
        empty_bundle = ReconBundle(target=self.ctx)
        surface = run_surface_analysis(empty_bundle)
        result = generate_ai_report(empty_bundle, surface)
        self.assertGreater(len(result.executive_summary), 20)
        self.assertFalse(result.ai_enabled)

    def test_sparse_executive_summary_mentions_sparse(self):
        from models.schema import ReconBundle
        from ai.report_generator import generate_ai_report
        from analyzers.surface_analyzer import run_surface_analysis
        empty_bundle = ReconBundle(target=self.ctx)
        surface = run_surface_analysis(empty_bundle)
        result = generate_ai_report(empty_bundle, surface)
        self.assertIn("limited", result.executive_summary.lower())

    def test_priority_assets_from_surface(self):
        from ai.report_generator import generate_ai_report
        result = generate_ai_report(self.bundle, self.surface)
        # If surface found high-risk items, priority_assets should be populated
        if self.surface.priority_assets:
            self.assertGreater(len(result.priority_assets), 0)
        else:
            # Can be empty for sparse targets — that is acceptable
            self.assertIsInstance(result.priority_assets, list)


# ---------------------------------------------------------------------------
# Settings / config tests
# ---------------------------------------------------------------------------

class TestSettings(unittest.TestCase):

    def test_settings_loads_without_openai_key(self):
        from config.settings import Settings
        s = Settings.load()
        # Should not raise — openai_api_key can be empty
        self.assertIsInstance(s.openai_api_key, str)

    def test_settings_no_anthropic_key_field(self):
        from config.settings import Settings
        s = Settings.load()
        self.assertFalse(hasattr(s, "anthropic_api_key"),
                         "anthropic_api_key must not appear in Settings")

    def test_settings_has_github_token(self):
        from config.settings import Settings
        s = Settings.load()
        self.assertIsInstance(s.github_token, str)

    def test_settings_has_output_dir(self):
        from config.settings import Settings
        s = Settings.load()
        self.assertIsInstance(s.output_base_dir, str)


# ---------------------------------------------------------------------------
# resolve_ai_config tests (kept for ai_client backward compat)
# ---------------------------------------------------------------------------

class TestResolveAIConfig(unittest.TestCase):

    def test_returns_5_tuple(self):
        from ai.ai_client import resolve_ai_config
        result = resolve_ai_config()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 5)

    def test_returns_empty_key_without_env(self):
        with patch.dict("os.environ", {}, clear=False):
            import os
            saved = os.environ.pop("OPENAI_API_KEY", None)
            try:
                from ai.ai_client import resolve_ai_config
                api_key, *_ = resolve_ai_config()
                if not saved:
                    self.assertEqual(api_key, "")
            finally:
                if saved:
                    os.environ["OPENAI_API_KEY"] = saved

    def test_model_default(self):
        from ai.ai_client import resolve_ai_config
        _, model, *_ = resolve_ai_config()
        self.assertIsInstance(model, str)
        self.assertGreater(len(model), 0)

    def test_max_tokens_is_int(self):
        from ai.ai_client import resolve_ai_config
        _, _, _, max_tokens, _ = resolve_ai_config()
        self.assertIsInstance(max_tokens, int)
        self.assertGreater(max_tokens, 0)

    def test_timeout_is_int(self):
        from ai.ai_client import resolve_ai_config
        _, _, _, _, timeout = resolve_ai_config()
        self.assertIsInstance(timeout, int)
        self.assertGreater(timeout, 0)


# ---------------------------------------------------------------------------
# JSON output tests
# ---------------------------------------------------------------------------

class TestJSONOutput(unittest.TestCase):

    def setUp(self):
        self.ctx     = _make_ctx()
        self.bundle  = _make_bundle(self.ctx)
        self.surface = _make_surface(self.bundle)

    def test_json_output_written(self):
        from reports.json_writer import write_json_output
        from ai.report_generator import generate_ai_report
        report = generate_ai_report(self.bundle, self.surface)
        path = write_json_output(
            self.bundle, self.surface, report, self.ctx.output_dir,
            module_status={"subdomains": "passive"},
        )
        self.assertTrue(Path(path).exists())

    def test_json_ai_metadata_provider_none(self):
        from reports.json_writer import write_json_output
        from ai.report_generator import generate_ai_report
        report = generate_ai_report(self.bundle, self.surface)
        path = write_json_output(
            self.bundle, self.surface, report, self.ctx.output_dir,
        )
        data = json.loads(Path(path).read_text())
        self.assertIn("ai_metadata", data)
        self.assertEqual(data["ai_metadata"]["ai_provider"], "none")

    def test_json_has_surface_observations(self):
        from reports.json_writer import write_json_output
        from ai.report_generator import generate_ai_report
        report = generate_ai_report(self.bundle, self.surface)
        path = write_json_output(
            self.bundle, self.surface, report, self.ctx.output_dir,
        )
        data = json.loads(Path(path).read_text())
        self.assertIn("surface_analysis", data)
        self.assertIn("observations", data["surface_analysis"])

    def test_json_execution_metadata_present(self):
        from reports.json_writer import write_json_output
        from ai.report_generator import generate_ai_report
        report = generate_ai_report(self.bundle, self.surface)
        path = write_json_output(
            self.bundle, self.surface, report, self.ctx.output_dir,
            module_status={"subdomains": "passive", "http": "light_active"},
        )
        data = json.loads(Path(path).read_text())
        self.assertIn("module_status", data["execution_metadata"])


# ---------------------------------------------------------------------------
# Markdown output tests
# ---------------------------------------------------------------------------

class TestMarkdownOutput(unittest.TestCase):

    def setUp(self):
        self.ctx     = _make_ctx()
        self.bundle  = _make_bundle(self.ctx)
        self.surface = _make_surface(self.bundle)

    def test_markdown_written(self):
        from reports.markdown_writer import write_markdown_report
        from ai.report_generator import generate_ai_report
        report = generate_ai_report(self.bundle, self.surface)
        path = write_markdown_report(
            self.bundle, self.surface, report, self.ctx.output_dir,
        )
        self.assertTrue(Path(path).exists())

    def test_markdown_contains_target(self):
        from reports.markdown_writer import write_markdown_report
        from ai.report_generator import generate_ai_report
        report = generate_ai_report(self.bundle, self.surface)
        path = write_markdown_report(
            self.bundle, self.surface, report, self.ctx.output_dir,
        )
        content = Path(path).read_text()
        self.assertIn("example.com", content)

    def test_markdown_no_ai_provider_mention_in_header(self):
        from reports.markdown_writer import write_markdown_report
        from ai.report_generator import generate_ai_report
        report = generate_ai_report(self.bundle, self.surface)
        path = write_markdown_report(
            self.bundle, self.surface, report, self.ctx.output_dir,
        )
        content = Path(path).read_text()
        self.assertNotIn("ANTHROPIC_API_KEY", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
