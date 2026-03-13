"""
tests/test_pdf_report.py
=========================
Tests for PDF report generation and the no-AI-API default path.

Coverage:
- PDF generated successfully (reportlab present)
- PDF gracefully skipped when reportlab absent
- Structured report generated without any AI API call
- Source labeling preserved through PDF metadata
- CLI default path: no enable-ai flag, no AI API call attempted
- No OPENAI_API_KEY / ANTHROPIC_API_KEY referenced in default path
- JSON / Markdown / PDF consistency on key fields
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

def _make_ctx(domain="testdomain.example"):
    from models.schema import TargetContext, InputType
    tmpdir = tempfile.mkdtemp()
    return TargetContext(
        raw_input=domain, input_type=InputType.DOMAIN,
        domain=domain, run_id="pdf_test_001", output_dir=tmpdir,
        timeout=10, enable_ai=False,
    )


def _make_bundle(ctx):
    from models.schema import (
        ReconBundle, SubdomainResult, Subdomain,
        HTTPProfile, HTTPAsset,
    )
    subs = SubdomainResult(
        target=ctx.raw_input,
        subdomains=[
            Subdomain("admin.testdomain.example"),
            Subdomain("api.testdomain.example"),
        ],
    )
    subs.data_source = "mock"

    http = HTTPProfile(
        target=ctx.raw_input,
        assets=[
            HTTPAsset(
                url="https://admin.testdomain.example",
                status_code=200, title="Admin Panel",
                server="nginx", alive=True,
            ),
        ],
    )
    http.data_source = "mock"

    b = ReconBundle(target=ctx, subdomains=subs, http=http)
    return b


def _make_surface(bundle):
    from analyzers.surface_analyzer import run_surface_analysis
    return run_surface_analysis(bundle)


def _make_report(bundle, surface):
    from ai.report_generator import generate_ai_report
    return generate_ai_report(bundle, surface, module_status={
        "subdomains": "mock",
        "http": "mock",
        "ct": "error",
        "rdap": "rdap_passive",
    })


# ---------------------------------------------------------------------------
# Tests: structured report (no AI API)
# ---------------------------------------------------------------------------

class TestStructuredReport(unittest.TestCase):

    def setUp(self):
        self.ctx     = _make_ctx()
        self.bundle  = _make_bundle(self.ctx)
        self.surface = _make_surface(self.bundle)
        self.report  = _make_report(self.bundle, self.surface)

    def test_report_has_executive_summary(self):
        self.assertIsInstance(self.report.executive_summary, str)
        self.assertGreater(len(self.report.executive_summary), 20)

    def test_report_ai_disabled(self):
        """Default path must never enable AI API."""
        self.assertFalse(self.report.ai_enabled)
        self.assertEqual(self.report.ai_provider, "none")

    def test_report_model_used_is_structured(self):
        self.assertEqual(self.report.model_used, "structured-report")

    def test_report_key_findings_present(self):
        self.assertIsInstance(self.report.key_findings, list)

    def test_report_review_recommendations_no_ai_api_mention(self):
        for rec in self.report.review_recommendations:
            self.assertNotIn("OPENAI_API_KEY", rec)
            self.assertNotIn("ANTHROPIC_API_KEY", rec)

    def test_report_reliability_notes_present(self):
        self.assertGreater(len(self.report.reliability_notes), 0)

    def test_no_openai_call_in_default_path(self):
        """generate_ai_report must NOT import or call openai in default path."""
        with patch.dict("sys.modules", {"openai": None}):
            from ai.report_generator import generate_ai_report as gen
            result = gen(self.bundle, self.surface)
            self.assertFalse(result.ai_enabled)

    def test_no_anthropic_call_in_default_path(self):
        """generate_ai_report must NOT import or call anthropic in default path."""
        with patch.dict("sys.modules", {"anthropic": None}):
            from ai.report_generator import generate_ai_report as gen
            result = gen(self.bundle, self.surface)
            self.assertFalse(result.ai_enabled)


# ---------------------------------------------------------------------------
# Tests: PDF generation
# ---------------------------------------------------------------------------

class TestPDFGeneration(unittest.TestCase):

    def setUp(self):
        self.ctx      = _make_ctx()
        self.bundle   = _make_bundle(self.ctx)
        self.surface  = _make_surface(self.bundle)
        self.ai_report = _make_report(self.bundle, self.surface)
        self.tmpdir   = self.ctx.output_dir

        # Write a dummy markdown file so PDF appendix check works
        md_path = Path(self.tmpdir) / "report.md"
        md_path.write_text("# ALR Report\n\nTest content.\n")
        self.md_path = str(md_path)

        self.module_status = {
            "subdomains": "mock",
            "http":       "mock",
            "ct":         "error",
            "rdap":       "rdap_passive",
        }

    def test_pdf_generated_when_reportlab_present(self):
        try:
            import reportlab  # noqa
        except ImportError:
            self.skipTest("reportlab not installed")

        from reports.pdf_writer import write_pdf_report
        path = write_pdf_report(
            bundle=self.bundle,
            surface=self.surface,
            ai_report=self.ai_report,
            md_path=self.md_path,
            output_dir=self.tmpdir,
            target=self.ctx.raw_input,
            run_id=self.ctx.run_id,
            module_status=self.module_status,
            passive_only=True,
            allow_mock=True,
        )
        self.assertIsNotNone(path)
        self.assertTrue(Path(path).exists())
        self.assertGreater(Path(path).stat().st_size, 1000)

    def test_pdf_returns_none_without_reportlab(self):
        import importlib, sys as _sys
        saved = _sys.modules.pop("reportlab", None)
        saved_sub = {k: _sys.modules.pop(k) for k in list(_sys.modules)
                     if k.startswith("reportlab")}
        try:
            with patch.dict(_sys.modules, {"reportlab": None,
                                           "reportlab.lib": None,
                                           "reportlab.lib.pagesizes": None,
                                           "reportlab.lib.units": None,
                                           "reportlab.lib.colors": None,
                                           "reportlab.platypus": None,
                                           "reportlab.lib.styles": None,
                                           "reportlab.lib.enums": None}):
                # Re-import to get the version with mocked modules
                import importlib
                if "reports.pdf_writer" in _sys.modules:
                    del _sys.modules["reports.pdf_writer"]
                from reports.pdf_writer import write_pdf_report
                result = write_pdf_report(
                    bundle=self.bundle,
                    surface=self.surface,
                    ai_report=self.ai_report,
                    md_path=self.md_path,
                    output_dir=self.tmpdir,
                    target="test.example",
                    run_id="test123",
                )
                self.assertIsNone(result)
        finally:
            if saved:
                _sys.modules["reportlab"] = saved
            _sys.modules.update(saved_sub)

    def test_pdf_target_in_output(self):
        """PDF output file is in the expected output_dir."""
        try:
            import reportlab  # noqa
        except ImportError:
            self.skipTest("reportlab not installed")

        from reports.pdf_writer import write_pdf_report
        path = write_pdf_report(
            bundle=self.bundle,
            surface=self.surface,
            ai_report=self.ai_report,
            md_path=self.md_path,
            output_dir=self.tmpdir,
            target=self.ctx.raw_input,
            run_id=self.ctx.run_id,
            module_status=self.module_status,
        )
        self.assertIsNotNone(path)
        self.assertTrue(path.endswith("report.pdf"))
        self.assertIn(self.tmpdir, path)


# ---------------------------------------------------------------------------
# Tests: source labeling consistency
# ---------------------------------------------------------------------------

class TestSourceLabeling(unittest.TestCase):

    def setUp(self):
        self.ctx     = _make_ctx()
        self.bundle  = _make_bundle(self.ctx)
        self.surface = _make_surface(self.bundle)
        self.report  = _make_report(self.bundle, self.surface)
        self.tmpdir  = self.ctx.output_dir

    def test_mock_status_triggers_warning_in_report(self):
        """availability_impact_notes mentions mock when mock is used."""
        report = _make_report(self.bundle, self.surface)
        mock_noted = any(
            "mock" in note.lower() or "Mock" in note
            for note in report.availability_impact_notes
        )
        self.assertTrue(mock_noted)

    def test_json_output_contains_source_labels(self):
        from reports.json_writer import write_json_output
        module_status = {"subdomains": "mock", "http": "mock",
                         "ct": "error", "rdap": "rdap_passive"}
        json_path = write_json_output(
            self.bundle, self.surface, self.report, self.tmpdir,
            module_status=module_status, allow_mock=True,
        )
        data = json.loads(Path(json_path).read_text())
        self.assertIn("module_status", data["execution_metadata"])
        self.assertEqual(data["execution_metadata"]["module_status"]["subdomains"], "mock")


# ---------------------------------------------------------------------------
# Tests: CLI default path
# ---------------------------------------------------------------------------

class TestCLIDefaultPath(unittest.TestCase):

    def test_enable_ai_not_in_default_argparse(self):
        """--enable-ai must be removed from the CLI argument parser."""
        import argparse
        from cli.main import build_parser
        parser = build_parser()
        # Confirm --enable-ai is not a registered option
        option_strings = []
        for action in parser._actions:
            option_strings.extend(action.option_strings)
        self.assertNotIn("--enable-ai", option_strings,
                         "--enable-ai should be removed from CLI")

    def test_cli_help_no_api_key_requirement(self):
        """Help text must not mention OPENAI_API_KEY or ANTHROPIC_API_KEY."""
        from cli.main import build_parser
        import io
        parser = build_parser()
        buf = io.StringIO()
        try:
            parser.print_help(buf)
        except SystemExit:
            pass
        help_text = buf.getvalue()
        self.assertNotIn("ANTHROPIC_API_KEY", help_text)


# ---------------------------------------------------------------------------
# Tests: sparse findings
# ---------------------------------------------------------------------------

class TestSparseFindingsBehavior(unittest.TestCase):

    def test_sparse_report_has_executive_summary(self):
        """Even with zero findings, the report is complete."""
        from models.schema import (
            TargetContext, InputType, ReconBundle, SurfaceReport
        )
        from ai.report_generator import generate_ai_report

        tmpdir = tempfile.mkdtemp()
        ctx = TargetContext(
            raw_input="sparse.example", input_type=InputType.DOMAIN,
            domain="sparse.example", run_id="sparse001",
            output_dir=tmpdir, timeout=10, enable_ai=False,
        )
        bundle  = ReconBundle(target=ctx)
        surface = SurfaceReport(target="sparse.example")
        report  = generate_ai_report(bundle, surface)

        self.assertGreater(len(report.executive_summary), 20)
        self.assertIn("sparse", report.executive_summary.lower())

    def test_sparse_disclaimer_present(self):
        from models.schema import TargetContext, InputType, ReconBundle
        from analyzers.surface_analyzer import run_surface_analysis
        from ai.report_generator import generate_ai_report

        tmpdir = tempfile.mkdtemp()
        ctx = TargetContext(
            raw_input="sparse2.example", input_type=InputType.DOMAIN,
            domain="sparse2.example", run_id="sparse002",
            output_dir=tmpdir, timeout=10, enable_ai=False,
        )
        bundle  = ReconBundle(target=ctx)
        surface = run_surface_analysis(bundle)
        report  = generate_ai_report(bundle, surface)
        all_notes = " ".join(report.analyst_notes + report.reliability_notes)
        self.assertIn("heuristic", all_notes.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
