"""
tests/test_surface_analyzer.py
===============================
Unit tests for the heuristic surface analyzer.
"""

import sys
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models.schema import (
    DNSProfile, GitHubExposure, GitHubHit, HTTPAsset, HTTPProfile,
    InputType, OpenPort, PortSummary, ReconBundle, RiskHint,
    Subdomain, SubdomainResult, TargetContext, TechDetection, TechProfile,
)
from analyzers.surface_analyzer import SurfaceAnalyzer, run_surface_analysis


def _make_ctx(target: str = "example.com") -> TargetContext:
    return TargetContext(
        raw_input=target,
        input_type=InputType.DOMAIN,
        domain=target,
        run_id="testrun123",
        output_dir="/tmp",
    )


def _make_bundle(**kwargs) -> ReconBundle:
    ctx = _make_ctx()
    return ReconBundle(target=ctx, **kwargs)


class TestSubdomainAnalysis(unittest.TestCase):

    def test_admin_subdomain_flagged_high(self):
        subs = SubdomainResult(
            target="example.com",
            subdomains=[Subdomain(fqdn="admin.example.com")],
        )
        bundle = _make_bundle(subdomains=subs)
        report = run_surface_analysis(bundle)
        obs = [o for o in report.observations if "admin.example.com" in o.asset]
        self.assertTrue(len(obs) > 0)
        self.assertEqual(obs[0].risk_hint, "high")

    def test_api_subdomain_flagged(self):
        subs = SubdomainResult(
            target="example.com",
            subdomains=[Subdomain(fqdn="api.example.com")],
        )
        bundle = _make_bundle(subdomains=subs)
        report = run_surface_analysis(bundle)
        obs = [o for o in report.observations if "api.example.com" in o.asset]
        self.assertTrue(len(obs) > 0)

    def test_benign_subdomain_not_flagged(self):
        subs = SubdomainResult(
            target="example.com",
            subdomains=[Subdomain(fqdn="docs.example.com")],
        )
        bundle = _make_bundle(subdomains=subs)
        report = run_surface_analysis(bundle)
        obs = [o for o in report.observations if "docs.example.com" in o.asset]
        self.assertEqual(len(obs), 0)


class TestPortAnalysis(unittest.TestCase):

    def test_rdp_flagged_high(self):
        ports = PortSummary(
            target="1.2.3.4",
            open_ports=[OpenPort(host="1.2.3.4", port=3389)],
        )
        bundle = _make_bundle(ports=ports)
        report = run_surface_analysis(bundle)
        obs = [o for o in report.observations if "3389" in o.asset]
        self.assertTrue(len(obs) > 0)
        self.assertEqual(obs[0].risk_hint, "high")

    def test_mongodb_flagged(self):
        ports = PortSummary(
            target="1.2.3.4",
            open_ports=[OpenPort(host="1.2.3.4", port=27017)],
        )
        bundle = _make_bundle(ports=ports)
        report = run_surface_analysis(bundle)
        obs = [o for o in report.observations if "27017" in o.asset]
        self.assertTrue(len(obs) > 0)

    def test_non_risky_port_not_flagged(self):
        ports = PortSummary(
            target="1.2.3.4",
            open_ports=[OpenPort(host="1.2.3.4", port=80)],
        )
        bundle = _make_bundle(ports=ports)
        report = run_surface_analysis(bundle)
        obs = [o for o in report.observations if "category" == "open-port" and ":80" in o.asset]
        # Port 80 is not in the risky list
        self.assertEqual(len(obs), 0)


class TestHTTPAnalysis(unittest.TestCase):

    def test_jenkins_title_flagged(self):
        http = HTTPProfile(
            target="example.com",
            assets=[HTTPAsset(url="http://ci.example.com", title="Jenkins", alive=True)],
        )
        bundle = _make_bundle(http=http)
        report = run_surface_analysis(bundle)
        obs = [o for o in report.observations if "ci.example.com" in o.asset]
        self.assertTrue(len(obs) > 0)

    def test_no_title_flagged_low(self):
        http = HTTPProfile(
            target="example.com",
            assets=[HTTPAsset(url="http://example.com", title=None, alive=True)],
        )
        bundle = _make_bundle(http=http)
        report = run_surface_analysis(bundle)
        obs = [o for o in report.observations if "no-title" in o.tags]
        self.assertTrue(len(obs) > 0)
        self.assertEqual(obs[0].risk_hint, "low")


class TestGitHubAnalysis(unittest.TestCase):

    def test_github_hits_create_observations(self):
        github = GitHubExposure(
            target="example.com",
            hits=[GitHubHit(repo="user/repo", hint_type="credential_hint")],
            queried=True,
        )
        bundle = _make_bundle(github=github)
        report = run_surface_analysis(bundle)
        obs = [o for o in report.observations if "github" in o.category]
        self.assertTrue(len(obs) > 0)


class TestSummaryNotes(unittest.TestCase):

    def test_summary_notes_present(self):
        bundle = _make_bundle()
        report = run_surface_analysis(bundle)
        self.assertTrue(len(report.summary_notes) > 0)

    def test_disclaimer_in_notes(self):
        bundle = _make_bundle()
        report = run_surface_analysis(bundle)
        combined = " ".join(report.summary_notes)
        self.assertIn("DISCLAIMER", combined)


if __name__ == "__main__":
    unittest.main()
