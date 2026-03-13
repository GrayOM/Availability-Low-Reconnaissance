"""
tests/test_runtime_and_modes.py
================================
Tests for runtime PATH injection, doctor, strict/mock mode, dnsx fix.
"""
import sys
import os
import json
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.runtime_env import get_runtime_env, resolve_tool, PROJECT_ROOT


class TestRuntimeEnv(unittest.TestCase):

    def test_get_runtime_env_returns_dict(self):
        env = get_runtime_env()
        self.assertIsInstance(env, dict)
        self.assertIn("PATH", env)

    def test_local_bin_prepended_when_exists(self):
        local_bin = str(PROJECT_ROOT / ".tools" / "bin")
        env = get_runtime_env()
        if Path(local_bin).is_dir():
            self.assertTrue(env["PATH"].startswith(local_bin))

    def test_resolve_tool_returns_none_for_fake_tool(self):
        self.assertIsNone(resolve_tool("__alr_fake_tool_xyz__"))

    def test_resolve_tool_finds_python(self):
        result = resolve_tool("python3") or resolve_tool("python")
        self.assertIsNotNone(result)


class TestToolChecker(unittest.TestCase):

    def test_required_tools_no_wappalyzer(self):
        from utils.tool_checker import REQUIRED_TOOLS, OPTIONAL_TOOLS
        self.assertNotIn("wappalyzer", REQUIRED_TOOLS)
        self.assertNotIn("wappalyzer", OPTIONAL_TOOLS)

    def test_required_tools_is_subfinder_only(self):
        from utils.tool_checker import REQUIRED_TOOLS, ACTIVE_TOOLS
        self.assertIn("subfinder", REQUIRED_TOOLS)
        # dnsx/naabu are secondary active tools
        for tool in ["dnsx", "naabu"]:
            self.assertIn(tool, ACTIVE_TOOLS)
            self.assertNotIn(tool, REQUIRED_TOOLS)

    def test_check_all_tools_returns_list(self):
        from utils.tool_checker import check_all_tools
        statuses = check_all_tools()
        self.assertIsInstance(statuses, list)

    def test_missing_required_returns_list(self):
        from utils.tool_checker import check_all_tools, missing_required
        statuses = check_all_tools()
        missing = missing_required(statuses)
        self.assertIsInstance(missing, list)


class TestPreflightCheck(unittest.TestCase):

    @patch("utils.tool_checker.missing_required", return_value=["subfinder", "dnsx"])
    def test_strict_mode_raises_systemexit(self, _):
        from utils.tool_checker import preflight_check
        with self.assertRaises(SystemExit):
            preflight_check(allow_mock=False, strict_tools=True)

    @patch("utils.tool_checker.missing_required", return_value=["subfinder"])
    def test_default_mode_raises_systemexit_when_missing(self, _):
        from utils.tool_checker import preflight_check
        with self.assertRaises(SystemExit):
            preflight_check(allow_mock=False, strict_tools=False)

    @patch("utils.tool_checker.missing_required", return_value=["subfinder"])
    @patch("utils.tool_checker._print_mock_warning")
    def test_allow_mock_does_not_raise(self, _warn, _miss):
        from utils.tool_checker import preflight_check
        result = preflight_check(allow_mock=True, strict_tools=False)
        self.assertIsInstance(result, dict)

    @patch("utils.tool_checker.missing_required", return_value=["subfinder"])
    @patch("utils.tool_checker._print_mock_warning")
    def test_preflight_always_sets_tech_as_heuristic(self, _warn, _miss):
        from utils.tool_checker import preflight_check
        result = preflight_check(allow_mock=True)
        self.assertEqual(result.get("tech"), "heuristic")

    @patch("utils.tool_checker.missing_required", return_value=["subfinder"])
    @patch("utils.tool_checker._print_mock_warning")
    def test_preflight_always_sets_github_as_disabled(self, _warn, _miss):
        from utils.tool_checker import preflight_check
        result = preflight_check(allow_mock=True)
        self.assertEqual(result.get("github"), "disabled")


class TestDNSCollectorInvocation(unittest.TestCase):
    """Verify dnsx is invoked with -l file, NOT -d flag."""

    def _make_ctx(self):
        from models.schema import TargetContext, InputType
        tmpdir = tempfile.mkdtemp()
        return TargetContext(
            raw_input="example.com", input_type=InputType.DOMAIN,
            domain="example.com", run_id="testdns", output_dir=tmpdir, timeout=5,
        )

    def test_dnsx_uses_list_file_not_d_flag(self):
        """
        When dnsx is available, the invocation must use -l <file>, not -d <domain>.
        This prevents the 'missing wordlist' error in newer dnsx versions.
        """
        from collectors.dns_collector import collect_dns
        captured_args = []

        def fake_run_tool(tool, args, **kwargs):
            if tool == "dnsx":
                captured_args.extend(args)
            from utils.subprocess_runner import ToolResult
            return ToolResult(tool=tool, command=[tool]+args, skipped=True,
                              skip_reason="test mock")

        with patch("collectors.dns_collector.run_tool", side_effect=fake_run_tool):
            ctx = self._make_ctx()
            collect_dns(ctx, allow_mock=True)

        self.assertIn("-l", captured_args, "dnsx must use -l flag for file input")
        self.assertNotIn("-d", captured_args, "dnsx must NOT use -d flag (requires wordlist)")

    def test_dnsx_input_file_written(self):
        """Input file must be written before dnsx is called."""
        from collectors.dns_collector import collect_dns

        with patch("collectors.dns_collector.run_tool") as mock_run:
            from utils.subprocess_runner import ToolResult
            mock_run.return_value = ToolResult(
                tool="dnsx", command=[], skipped=True, skip_reason="test")
            ctx = self._make_ctx()
            collect_dns(ctx, allow_mock=True)

        input_file = Path(ctx.output_dir) / "dnsx_input.txt"
        self.assertTrue(input_file.exists())
        content = input_file.read_text()
        self.assertIn("example.com", content)

    def test_dnsx_mock_returns_records(self):
        from collectors.dns_collector import collect_dns
        with patch("utils.subprocess_runner.resolve_tool", return_value=None):
            ctx = self._make_ctx()
            result = collect_dns(ctx, allow_mock=True)
        self.assertEqual(result.data_source, "mock")
        self.assertTrue(len(result.records) > 0)

    def test_dnsx_missing_without_mock(self):
        from collectors.dns_collector import collect_dns
        with patch("utils.subprocess_runner.resolve_tool", return_value=None):
            ctx = self._make_ctx()
            result = collect_dns(ctx, allow_mock=False)
        self.assertEqual(result.data_source, "missing")


class TestTechCollector(unittest.TestCase):
    """Tech collector must be heuristic-only, no wappalyzer."""

    def _make_ctx(self):
        from models.schema import TargetContext, InputType
        tmpdir = tempfile.mkdtemp()
        return TargetContext(
            raw_input="example.com", input_type=InputType.DOMAIN,
            domain="example.com", run_id="testtech", output_dir=tmpdir, timeout=5,
        )

    def test_tech_collector_no_wappalyzer_call(self):
        """Tech collector must never attempt to run wappalyzer."""
        from collectors.tech_collector import collect_tech
        from models.schema import HTTPProfile, HTTPAsset

        http = HTTPProfile(target="example.com", assets=[
            HTTPAsset(url="http://example.com", server="nginx", alive=True)
        ])
        ctx = self._make_ctx()

        with patch("utils.subprocess_runner.run_tool") as mock_run:
            collect_tech(ctx, http_profile=http)
            # run_tool should NEVER be called by tech_collector
            mock_run.assert_not_called()

    def test_tech_collector_data_source_is_heuristic(self):
        from collectors.tech_collector import collect_tech
        from models.schema import HTTPProfile, HTTPAsset

        http = HTTPProfile(target="example.com", assets=[
            HTTPAsset(url="https://example.com", server="nginx/1.20", alive=True)
        ])
        ctx = self._make_ctx()
        result = collect_tech(ctx, http_profile=http)
        self.assertEqual(result.data_source, "heuristic")

    def test_tech_collector_disabled_without_http(self):
        from collectors.tech_collector import collect_tech
        ctx = self._make_ctx()
        result = collect_tech(ctx, http_profile=None)
        self.assertEqual(result.data_source, "disabled")


class TestJSONMetadata(unittest.TestCase):

    def _base_objects(self):
        from models.schema import (ReconBundle, TargetContext, InputType,
                                   SurfaceReport, AIReport)
        tmpdir = tempfile.mkdtemp()
        ctx = TargetContext(raw_input="test.com", input_type=InputType.DOMAIN,
                            domain="test.com", run_id="abc", output_dir=tmpdir)
        return ReconBundle(target=ctx), SurfaceReport(target="test.com"), AIReport(), tmpdir

    def test_execution_metadata_present(self):
        from reports.json_writer import write_json_output
        bundle, surface, ai, tmpdir = self._base_objects()
        module_status = {"subdomains": "mock", "dns": "mock",
                         "http": "httpx", "ports": "naabu",
                         "tech": "heuristic", "github": "disabled"}
        path = write_json_output(bundle, surface, ai, tmpdir,
                                 module_status=module_status, allow_mock=True)
        data = json.loads(Path(path).read_text())
        self.assertIn("execution_metadata", data)
        self.assertTrue(data["execution_metadata"]["mock_used"])
        self.assertEqual(data["execution_metadata"]["module_status"]["tech"], "heuristic")

    def test_trust_level_passive_when_no_mock(self):
        from reports.json_writer import write_json_output
        bundle, surface, ai, tmpdir = self._base_objects()
        path = write_json_output(bundle, surface, ai, tmpdir,
                                 module_status={"subdomains": "passive",
                                                "tech": "heuristic"},
                                 allow_mock=False, passive_only=True)
        data = json.loads(Path(path).read_text())
        self.assertIn("PASSIVE", data["execution_metadata"]["trust_level"])


class TestMarkdownReliability(unittest.TestCase):

    def test_data_reliability_section_exists(self):
        from models.schema import (ReconBundle, TargetContext, InputType,
                                   SurfaceReport, AIReport)
        from reports.markdown_writer import write_markdown_report
        tmpdir = tempfile.mkdtemp()
        ctx = TargetContext(raw_input="test.com", input_type=InputType.DOMAIN,
                            domain="test.com", run_id="abc", output_dir=tmpdir)
        bundle  = ReconBundle(target=ctx)
        surface = SurfaceReport(target="test.com")
        ai      = AIReport()
        path = write_markdown_report(bundle, surface, ai, tmpdir,
                                     module_status={"subdomains": "mock",
                                                    "tech": "heuristic"},
                                     allow_mock=True)
        content = Path(path).read_text()
        self.assertIn("Data Reliability", content)
        self.assertIn("heuristic", content)
        self.assertIn("MOCK DATA WARNING", content)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Passive-first behavior tests
# ---------------------------------------------------------------------------

class TestPassiveFirstMode(unittest.TestCase):

    def test_required_tools_includes_subfinder_and_httpx(self):
        from utils.tool_checker import REQUIRED_TOOLS
        self.assertIn("subfinder", REQUIRED_TOOLS)
        self.assertIn("httpx", REQUIRED_TOOLS)

    def test_secondary_active_tools_not_required(self):
        from utils.tool_checker import REQUIRED_TOOLS, ACTIVE_TOOLS
        for tool in ["dnsx", "naabu"]:
            self.assertIn(tool, ACTIVE_TOOLS)
            self.assertNotIn(tool, REQUIRED_TOOLS)

    @patch("utils.tool_checker.missing_required", return_value=[])
    def test_preflight_passive_sets_disabled_for_active_tools(self, _):
        from utils.tool_checker import preflight_check
        with patch("utils.tool_checker.check_all_tools") as mock_check:
            s = MagicMock()
            s.name = "subfinder"; s.required = True; s.found = True
            mock_check.return_value = [s]
            result = preflight_check(allow_mock=False, enable_active=False)
        # Active tools should be disabled when not requested
        for mod in ["dns", "http", "ports"]:
            self.assertIn(result.get(mod), ["disabled", None])

    @patch("utils.tool_checker.missing_required", return_value=[])
    def test_preflight_tech_always_heuristic(self, _):
        from utils.tool_checker import preflight_check
        with patch("utils.tool_checker.check_all_tools") as mock_check:
            s = MagicMock()
            s.name = "subfinder"; s.required = True; s.found = True
            mock_check.return_value = [s]
            result = preflight_check(allow_mock=False)
        self.assertEqual(result.get("tech"), "heuristic")

    def test_censys_collector_disabled_without_credentials(self):
        """Censys must fail gracefully when no API credentials are set."""
        from collectors.censys_collector import collect_censys
        from models.schema import TargetContext, InputType

        tmpdir = tempfile.mkdtemp()
        ctx = TargetContext(
            raw_input="example.com", input_type=InputType.DOMAIN,
            domain="example.com", run_id="testcensys", output_dir=tmpdir, timeout=5,
        )

        with patch.dict("os.environ", {}, clear=True):
            # Remove any real credentials from env
            for k in ["CENSYS_API_ID", "CENSYS_API_SECRET", "CENSYS_API_KEY"]:
                if k in __import__("os").environ:
                    del __import__("os").environ[k]
            result = collect_censys(ctx)

        self.assertEqual(result.data_source, "disabled")
        self.assertFalse(result.queried)

    def test_censys_normalized_file_written(self):
        """censys_normalized.json must always be written, even when disabled."""
        from collectors.censys_collector import collect_censys
        from models.schema import TargetContext, InputType

        tmpdir = tempfile.mkdtemp()
        ctx = TargetContext(
            raw_input="example.com", input_type=InputType.DOMAIN,
            domain="example.com", run_id="testcensys2", output_dir=tmpdir, timeout=5,
        )

        with patch.dict("os.environ", {}, clear=True):
            collect_censys(ctx)

        out = Path(tmpdir) / "censys_normalized.json"
        self.assertTrue(out.exists())
        data = json.loads(out.read_text())
        self.assertIn("data_source", data)

    def test_json_output_has_pipeline_mode(self):
        from models.schema import (ReconBundle, TargetContext, InputType,
                                   SurfaceReport, AIReport)
        from reports.json_writer import write_json_output
        tmpdir = tempfile.mkdtemp()
        ctx = TargetContext(raw_input="t.com", input_type=InputType.DOMAIN,
                            domain="t.com", run_id="pm", output_dir=tmpdir)
        bundle  = ReconBundle(target=ctx)
        surface = SurfaceReport(target="t.com")
        ai      = AIReport()

        path = write_json_output(bundle, surface, ai, tmpdir,
                                 module_status={}, passive_only=True)
        data = json.loads(Path(path).read_text())
        self.assertEqual(data["execution_metadata"]["pipeline_mode"], "passive-only")

    def test_json_output_passive_trust_level(self):
        from models.schema import (ReconBundle, TargetContext, InputType,
                                   SurfaceReport, AIReport)
        from reports.json_writer import write_json_output
        tmpdir = tempfile.mkdtemp()
        ctx = TargetContext(raw_input="t.com", input_type=InputType.DOMAIN,
                            domain="t.com", run_id="tl", output_dir=tmpdir)
        bundle  = ReconBundle(target=ctx)
        surface = SurfaceReport(target="t.com")
        ai      = AIReport()
        path = write_json_output(bundle, surface, ai, tmpdir,
                                 module_status={"subdomains": "passive"},
                                 allow_mock=False, passive_only=True)
        data = json.loads(Path(path).read_text())
        self.assertIn("PASSIVE", data["execution_metadata"]["trust_level"])


# ---------------------------------------------------------------------------
# Final MVP pipeline tests
# ---------------------------------------------------------------------------

class TestMVPPipeline(unittest.TestCase):
    """Tests for the final MVP: subfinder + CT + RDAP + httpx default."""

    def test_required_tools_are_subfinder_and_httpx(self):
        from utils.tool_checker import REQUIRED_TOOLS
        self.assertIn("subfinder", REQUIRED_TOOLS)
        self.assertIn("httpx", REQUIRED_TOOLS)

    def test_secondary_active_tools_are_dnsx_and_naabu(self):
        from utils.tool_checker import ACTIVE_TOOLS
        self.assertIn("dnsx", ACTIVE_TOOLS)
        self.assertIn("naabu", ACTIVE_TOOLS)

    def test_dnsx_naabu_not_required(self):
        from utils.tool_checker import REQUIRED_TOOLS
        self.assertNotIn("dnsx", REQUIRED_TOOLS)
        self.assertNotIn("naabu", REQUIRED_TOOLS)


class TestCTCollector(unittest.TestCase):

    def _make_ctx(self, target="example.com"):
        from models.schema import TargetContext, InputType
        tmpdir = tempfile.mkdtemp()
        return TargetContext(
            raw_input=target, input_type=InputType.DOMAIN,
            domain=target, run_id="testct", output_dir=tmpdir, timeout=5,
        )

    def test_ct_skipped_for_ip_target(self):
        from collectors.ct_collector import collect_ct
        from models.schema import TargetContext, InputType
        tmpdir = tempfile.mkdtemp()
        ctx = TargetContext(
            raw_input="1.2.3.4", input_type=InputType.IP,
            ip="1.2.3.4", run_id="testctip", output_dir=tmpdir, timeout=5,
        )
        result = collect_ct(ctx)
        self.assertEqual(result.data_source, "skipped")

    def test_ct_handles_network_error_gracefully(self):
        from collectors.ct_collector import collect_ct
        import urllib.error
        ctx = self._make_ctx()
        with patch("collectors.ct_collector._fetch_crtsh",
                   side_effect=urllib.error.URLError("connection refused")):
            result = collect_ct(ctx)
        self.assertEqual(result.data_source, "error")
        self.assertFalse(result.queried if hasattr(result, 'queried') else False)

    def test_ct_normalized_file_written(self):
        from collectors.ct_collector import collect_ct
        ctx = self._make_ctx()
        with patch("collectors.ct_collector._fetch_crtsh",
                   side_effect=Exception("offline")):
            collect_ct(ctx)
        out = Path(ctx.output_dir) / "ct_normalized.json"
        self.assertTrue(out.exists())
        data = json.loads(out.read_text())
        self.assertIn("data_source", data)

    def test_ct_subdomain_extraction(self):
        from collectors.ct_collector import collect_ct
        fake_entries = [
            {"common_name": "example.com",
             "name_value": "api.example.com\nwww.example.com",
             "not_before": "2024-01-01", "not_after": "2025-01-01"},
            {"common_name": "*.example.com",
             "name_value": "*.example.com",
             "not_before": "2024-01-01", "not_after": "2025-01-01"},
        ]
        ctx = self._make_ctx()
        with patch("collectors.ct_collector._fetch_crtsh", return_value=fake_entries):
            result = collect_ct(ctx)
        self.assertEqual(result.data_source, "ct_passive")
        self.assertIn("api.example.com", result.subdomain_hints)
        self.assertIn("www.example.com", result.subdomain_hints)


class TestRDAPCollector(unittest.TestCase):

    def _make_ctx(self, target="example.com", itype="domain"):
        from models.schema import TargetContext, InputType
        tmpdir = tempfile.mkdtemp()
        it = InputType.DOMAIN if itype == "domain" else InputType.IP
        return TargetContext(
            raw_input=target, input_type=it,
            domain=target if itype == "domain" else None,
            ip=target if itype == "ip" else None,
            run_id="testrdap", output_dir=tmpdir, timeout=5,
        )

    def test_rdap_normalized_file_written(self):
        from collectors.rdap_collector import collect_rdap
        ctx = self._make_ctx()
        with patch("collectors.rdap_collector._fetch_json",
                   side_effect=Exception("offline")):
            with patch("collectors.rdap_collector._resolve_domain_ips", return_value=[]):
                collect_rdap(ctx)
        out = Path(ctx.output_dir) / "rdap_normalized.json"
        self.assertTrue(out.exists())

    def test_rdap_graceful_failure(self):
        from collectors.rdap_collector import collect_rdap
        ctx = self._make_ctx()
        with patch("collectors.rdap_collector._fetch_json",
                   side_effect=Exception("network error")):
            with patch("collectors.rdap_collector._resolve_domain_ips", return_value=[]):
                result = collect_rdap(ctx)
        # Should not crash, and should return something
        self.assertIsNotNone(result)
        self.assertIn(result.data_source, ("rdap_passive", "error"))

    def test_rdap_nameservers_parsed(self):
        from collectors.rdap_collector import collect_rdap, _parse_rdap_domain, RDAPResult
        fake_rdap_data = {
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"},
                            {"ldhName": "NS2.EXAMPLE.COM"}],
            "events": [{"eventAction": "registration", "eventDate": "2020-01-01"}],
            "entities": [],
        }
        result = RDAPResult(target="example.com")
        _parse_rdap_domain(fake_rdap_data, result)
        self.assertIn("ns1.example.com", result.name_servers)
        self.assertEqual(result.created_date, "2020-01-01")


class TestPDFWriter(unittest.TestCase):

    def test_pdf_writer_returns_none_without_reportlab(self):
        """If reportlab absent, should return None gracefully."""
        from reports.pdf_writer import write_pdf_report
        import sys
        tmpdir = tempfile.mkdtemp()
        md = Path(tmpdir) / "report.md"
        md.write_text("# Test Report\n\nHello world.")

        # Mock importerror for reportlab
        import builtins
        real_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name.startswith("reportlab"):
                raise ImportError("mocked absence")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = write_pdf_report(
                md_path=str(md), output_dir=tmpdir,
                target="example.com", run_id="test",
            )
        self.assertIsNone(result)

    def test_pdf_writer_creates_file_with_reportlab(self):
        """If reportlab is installed, should create a PDF file."""
        try:
            import reportlab  # noqa
        except ImportError:
            self.skipTest("reportlab not installed")

        from reports.pdf_writer import write_pdf_report
        tmpdir = tempfile.mkdtemp()
        md = Path(tmpdir) / "report.md"
        md.write_text("# Test Report\n\n## Findings\n\n- Finding one\n- Finding two")

        result = write_pdf_report(
            md_path=str(md), output_dir=tmpdir,
            target="test.com", run_id="abc123",
            module_status={"subdomains": "passive", "ct": "ct_passive",
                           "http": "httpx", "tech": "heuristic"},
            passive_only=True, ai_enabled=False,
        )
        self.assertIsNotNone(result)
        self.assertTrue(Path(result).exists())
        self.assertGreater(Path(result).stat().st_size, 1000)
