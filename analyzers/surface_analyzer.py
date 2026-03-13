"""
analyzers/surface_analyzer.py
==============================
Heuristic-based attack surface analysis.

IMPORTANT WORDING POLICY:
- Use: "possible", "review recommended", "exposure candidate",
        "manual validation required", "pattern suggests"
- Avoid: "confirmed vulnerability", "definitely exploitable",
          "breach", "compromised"

The analyzer identifies patterns — it does NOT confirm exploitability.

PYTHON 3.10 COMPATIBILITY REQUIREMENTS (enforced in this file):
- No backslashes inside f-string expression parts  (use string variables)
- No f-string expressions with method calls involving escape chars
- All class methods indented at exactly 4 spaces inside SurfaceAnalyzer
- All 'break' statements only inside for/while loop bodies
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from models.schema import (
    ReconBundle,
    RiskHint,
    SurfaceObservation,
    SurfaceReport,
)
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Subdomain patterns that suggest sensitive assets
# Each tuple: (pattern, category, risk_hint, recommendation)
_SENSITIVE_SUB_PATTERNS: list = [
    (r"\badmin\b",       "administration",   RiskHint.HIGH,
     "Verify access controls; admin panels are common initial access targets"),
    (r"\blogin\b",       "authentication",   RiskHint.HIGH,
     "Review authentication mechanisms and brute-force protections"),
    (r"\bapi\b",         "api-surface",      RiskHint.MEDIUM,
     "Enumerate API endpoints; check for auth, rate limiting, and versioning"),
    (r"\bdev\b",         "development",      RiskHint.HIGH,
     "Development environments may contain debug interfaces or relaxed auth"),
    (r"\bstag(ing)?\b",  "staging",          RiskHint.MEDIUM,
     "Staging environments may expose pre-production features"),
    (r"\bold\b",         "legacy",           RiskHint.MEDIUM,
     "Legacy/old subdomains may run unpatched software"),
    (r"\btest\b",        "test-environment", RiskHint.MEDIUM,
     "Test environments may have reduced security controls"),
    (r"\bbeta\b",        "pre-release",      RiskHint.LOW,
     "Beta environments may expose unreleased features"),
    (r"\bvpn\b",         "remote-access",    RiskHint.HIGH,
     "VPN portals are high-value targets; review patch level and auth"),
    (r"\bgit(lab|hub)?\b", "source-control", RiskHint.HIGH,
     "Source control exposure candidate; verify requires authentication"),
    (r"\bjenkins\b",     "ci-cd",            RiskHint.HIGH,
     "CI/CD panels may expose build secrets or allow code execution"),
    (r"\bjira\b",        "project-mgmt",     RiskHint.MEDIUM,
     "Project management tools may expose internal roadmaps"),
    (r"\bconfluence\b",  "wiki",             RiskHint.MEDIUM,
     "Wiki tools may contain sensitive internal documentation"),
    (r"\binternal\b",    "internal-asset",   RiskHint.HIGH,
     "Possible internal asset exposed publicly"),
    (r"\bintranet\b",    "internal-asset",   RiskHint.HIGH,
     "Intranet exposure candidate; verify intended public access"),
    (r"\bmonitor\b",     "monitoring",       RiskHint.MEDIUM,
     "Monitoring dashboards may leak infrastructure topology"),
    (r"\bbackup\b",      "data",             RiskHint.HIGH,
     "Backup endpoints may expose sensitive data"),
    (r"\bftp\b",         "file-transfer",    RiskHint.MEDIUM,
     "FTP services — review if required; prefer SFTP"),
    (r"\bmail\b",        "email",            RiskHint.LOW,
     "Mail server exposure; review SPF/DKIM/DMARC configuration"),
    (r"\bsmtp\b",        "email",            RiskHint.LOW,
     "SMTP server; review open relay and authentication settings"),
    (r"\bdb\b|\bdatabase\b", "database",     RiskHint.HIGH,
     "Possible database endpoint exposure; manual validation required"),
]

# Port risk hints: port -> (description, risk_hint, recommendation)
_PORT_RISK_MAP: dict = {
    21:    ("FTP service",       RiskHint.MEDIUM,
            "FTP transmits credentials in plaintext; prefer SFTP"),
    22:    ("SSH service",       RiskHint.LOW,
            "SSH exposed; review key-only auth and fail2ban configuration"),
    23:    ("Telnet service",    RiskHint.HIGH,
            "Telnet transmits all data in plaintext; replace with SSH"),
    445:   ("SMB service",       RiskHint.HIGH,
            "SMB exposure candidate; review patch level and network segmentation"),
    1433:  ("MSSQL port",        RiskHint.HIGH,
            "Database port exposed; manual validation required"),
    1521:  ("Oracle port",       RiskHint.HIGH,
            "Database port exposed; manual validation required"),
    3306:  ("MySQL port",        RiskHint.HIGH,
            "Database port exposed; manual validation required"),
    3389:  ("RDP service",       RiskHint.HIGH,
            "RDP exposure candidate; NLA and access controls review recommended"),
    5432:  ("PostgreSQL port",   RiskHint.HIGH,
            "Database port exposed; manual validation required"),
    5900:  ("VNC service",       RiskHint.HIGH,
            "VNC exposure candidate; authentication and encryption review recommended"),
    6379:  ("Redis port",        RiskHint.HIGH,
            "Redis may lack authentication by default; review access controls"),
    8888:  ("Jupyter-like port", RiskHint.HIGH,
            "Possible Jupyter notebook; code execution review recommended"),
    9200:  ("Elasticsearch",     RiskHint.HIGH,
            "Elasticsearch may expose data without authentication; review"),
    27017: ("MongoDB port",      RiskHint.HIGH,
            "MongoDB may lack authentication; review access controls"),
}

# HTTP title/server patterns
_HTTP_TITLE_PATTERNS: list = [
    (r"phpmyadmin",       "database-admin",  RiskHint.HIGH,
     "phpMyAdmin exposure; review authentication and network access"),
    (r"adminer",          "database-admin",  RiskHint.HIGH,
     "Adminer exposure; review authentication"),
    (r"grafana",          "monitoring",      RiskHint.MEDIUM,
     "Grafana dashboard; review default credentials and access controls"),
    (r"kibana",           "monitoring",      RiskHint.MEDIUM,
     "Kibana dashboard; review authentication and data exposure"),
    (r"elasticsearch",    "search-engine",   RiskHint.HIGH,
     "Elasticsearch UI; review authentication"),
    (r"jenkins",          "ci-cd",           RiskHint.HIGH,
     "Jenkins interface; review anonymous access settings"),
    (r"gitlab",           "source-control",  RiskHint.MEDIUM,
     "GitLab instance; review registration settings and exposure"),
    (r"sonarqube",        "code-quality",    RiskHint.MEDIUM,
     "SonarQube; may expose code quality findings and source hints"),
    (r"swagger|api docs", "api-docs",        RiskHint.MEDIUM,
     "API documentation exposed; review intended public access"),
    (r"403 forbidden",    "access-control",  RiskHint.LOW,
     "Resource exists but access denied; directory structure exposed"),
    (r"404 not found",    "general",         RiskHint.LOW,
     "Endpoint returns 404; review server disclosure in error pages"),
]


# ---------------------------------------------------------------------------
# Module-level helpers — used by the class below
# ---------------------------------------------------------------------------

def _clean_pattern_label(pattern: str) -> str:
    """
    Return a human-readable label from a regex pattern string.

    Removes regex metacharacters without using backslashes in f-strings.
    This function exists specifically to solve the Python 3.10 restriction
    that forbids backslashes inside f-string expression parts.

    Safe for Python 3.10+.
    """
    label = pattern.replace("\\b", "")
    label = label.replace("\\B", "")
    label = label.replace("(ing)?", "")
    label = label.replace("(lab|hub)?", "")
    label = label.replace("|", "/")
    return label.strip()


# ---------------------------------------------------------------------------
# Analyzer class
# ---------------------------------------------------------------------------

class SurfaceAnalyzer:
    """
    Runs heuristic analysis on a ReconBundle and produces a SurfaceReport.

    Class invariants:
    - Every method is indented at exactly 4 spaces (inside class body)
    - No f-string expressions contain backslash characters
    - Every 'break' statement appears inside a for or while loop body
    """

    def __init__(self, bundle: ReconBundle) -> None:
        self.bundle = bundle
        self.report = SurfaceReport(target=bundle.target.raw_input)

    def analyze(self) -> SurfaceReport:
        """Run all heuristic checks and return the populated report."""
        logger.info("Surface analysis started for %s", self.bundle.target.raw_input)

        self._analyze_subdomains()
        self._analyze_ct()
        self._analyze_rdap()
        self._analyze_ports()
        self._analyze_http()
        self._analyze_tech()
        self._analyze_github()
        self._build_priority_list()
        self._build_summary_notes()

        logger.info(
            "Surface analysis complete: %d observations, %d priority assets",
            len(self.report.observations),
            len(self.report.priority_assets),
        )
        return self.report

    # ------------------------------------------------------------------
    # Individual sub-analyzers
    # ------------------------------------------------------------------

    def _analyze_subdomains(self) -> None:
        """
        Match discovered subdomains against sensitive-pattern list.

        Python 3.10-safe: uses _clean_pattern_label() helper and string
        concatenation instead of backslash-containing f-string expressions.
        """
        if not self.bundle.subdomains:
            return

        for sub in self.bundle.subdomains.subdomains:
            fqdn = sub.fqdn.lower()
            for pattern, category, risk_hint, recommendation in _SENSITIVE_SUB_PATTERNS:
                if re.search(pattern, fqdn, re.IGNORECASE):
                    label = _clean_pattern_label(pattern)
                    obs_text = (
                        "Subdomain pattern '" + label + "' detected — "
                        "possible " + category + " asset"
                    )
                    self.report.observations.append(
                        SurfaceObservation(
                            asset=fqdn,
                            observation=obs_text,
                            risk_hint=risk_hint,
                            category=category,
                            recommendation=recommendation,
                            tags=["subdomain", category],
                        )
                    )
                    break  # one observation per subdomain; break is inside the inner for loop

    def _analyze_ct(self) -> None:
        """
        Derive observations from Certificate Transparency data.

        CT data is passive — all findings are clue-based indicators only.
        Python 3.10-safe: no backslashes in f-string expressions.
        """
        ct = getattr(self.bundle, "ct", None)
        if not ct:
            return
        if getattr(ct, "data_source", "disabled") in ("disabled", "error", "skipped"):
            return

        hints = getattr(ct, "subdomain_hints", [])
        wildcards = getattr(ct, "wildcard_hints", [])
        count = len(hints)

        if wildcards:
            wild_count = str(len(wildcards))
            first_wild = wildcards[0]
            self.report.observations.append(SurfaceObservation(
                asset=self.bundle.target.raw_input,
                observation=(
                    wild_count + " wildcard certificate pattern(s) observed in CT logs "
                    "(e.g. " + first_wild + ") — wide subdomain issuance scope"
                ),
                risk_hint=RiskHint.LOW,
                category="ct-wildcard",
                recommendation=(
                    "Enumerate and review all subdomains "
                    "covered by wildcard certificates"
                ),
                tags=["ct", "wildcard"],
            ))

        if count > 0:
            for hint in hints:
                for pattern, category, risk, rec in _SENSITIVE_SUB_PATTERNS:
                    if re.search(pattern, hint, re.IGNORECASE):
                        label = _clean_pattern_label(pattern)
                        obs_text = (
                            "CT log hint '" + hint + "' matches '"
                            + label + "' pattern — "
                            + category + " exposure candidate"
                        )
                        self.report.observations.append(SurfaceObservation(
                            asset=hint,
                            observation=obs_text,
                            risk_hint=risk,
                            category="ct-" + category,
                            recommendation=rec,
                            tags=["ct", category],
                        ))
                        break  # one match per CT hint; break is inside inner for loop

        if count > 0 and not wildcards:
            count_str = str(count)
            self.report.observations.append(SurfaceObservation(
                asset=self.bundle.target.raw_input,
                observation=(
                    count_str + " subdomain hint(s) identified from public CT logs — "
                    "clue-based; validate each entry"
                ),
                risk_hint=RiskHint.LOW,
                category="ct-coverage",
                recommendation=(
                    "Review CT hints for overlooked or forgotten subdomains"
                ),
                tags=["ct", "passive"],
            ))

    def _analyze_rdap(self) -> None:
        """
        Derive observations from RDAP/WHOIS/ASN data.

        All RDAP data is passive registration data — context clues only.
        """
        rdap = getattr(self.bundle, "rdap", None)
        if not rdap:
            return
        if getattr(rdap, "data_source", "disabled") in ("disabled", "error", "skipped"):
            return

        # Domain expiry check
        expiry = getattr(rdap, "expiry_date", "")
        if expiry:
            try:
                exp_dt = datetime.strptime(expiry[:10], "%Y-%m-%d")
                days_left = (exp_dt - datetime.utcnow()).days
                if 0 < days_left < 60:
                    days_str = str(days_left)
                    self.report.observations.append(SurfaceObservation(
                        asset=self.bundle.target.raw_input,
                        observation=(
                            "Domain registration expires in " + days_str
                            + " days (" + expiry[:10]
                            + ") — monitor for expiry or transfer"
                        ),
                        risk_hint=RiskHint.MEDIUM,
                        category="rdap-expiry",
                        recommendation=(
                            "Confirm domain renewal is planned; "
                            "expiry may enable domain hijacking"
                        ),
                        tags=["rdap", "expiry"],
                    ))
            except (ValueError, TypeError):
                pass

        # ASN context — informational, low risk
        asn = getattr(rdap, "asn", "")
        asn_org = getattr(rdap, "asn_org", "")
        if asn:
            self.report.observations.append(SurfaceObservation(
                asset=self.bundle.target.raw_input,
                observation=(
                    "Target resolves to " + asn + " (" + asn_org + ") — "
                    "hosting/network context from public ASN records"
                ),
                risk_hint=RiskHint.LOW,
                category="rdap-asn",
                recommendation=(
                    "Note ASN for infrastructure mapping; "
                    "no action required unless shared hosting creates risk"
                ),
                tags=["rdap", "asn", "passive"],
            ))

    def _analyze_ports(self) -> None:
        """Check discovered open ports against risk map."""
        if not self.bundle.ports:
            return
        for op in self.bundle.ports.open_ports:
            if op.port in _PORT_RISK_MAP:
                service_desc, risk_hint, recommendation = _PORT_RISK_MAP[op.port]
                host_port = op.host + ":" + str(op.port)
                port_str = str(op.port)
                self.report.observations.append(
                    SurfaceObservation(
                        asset=host_port,
                        observation=(
                            service_desc + " open on port " + port_str
                            + " — review recommended"
                        ),
                        risk_hint=risk_hint,
                        category="open-port",
                        recommendation=recommendation,
                        tags=["port", port_str, op.service or "unknown"],
                    )
                )

    def _analyze_http(self) -> None:
        """Check HTTP assets against title/server pattern list."""
        if not self.bundle.http:
            return
        for asset in self.bundle.http.assets:
            title_lower = (asset.title or "").lower()

            for pattern, category, risk_hint, recommendation in _HTTP_TITLE_PATTERNS:
                if re.search(pattern, title_lower, re.IGNORECASE):
                    self.report.observations.append(
                        SurfaceObservation(
                            asset=asset.url,
                            observation=(
                                "HTTP title/content pattern suggests "
                                + category
                                + " exposure — manual validation required"
                            ),
                            risk_hint=risk_hint,
                            category=category,
                            recommendation=recommendation,
                            tags=["http", category],
                        )
                    )
                    break  # one match per HTTP asset; break is inside inner for loop

            if asset.alive and not asset.title:
                self.report.observations.append(
                    SurfaceObservation(
                        asset=asset.url,
                        observation=(
                            "Alive HTTP asset with no page title — "
                            "possible default or stripped response"
                        ),
                        risk_hint=RiskHint.LOW,
                        category="http-metadata",
                        recommendation=(
                            "Manually verify page content and intended exposure"
                        ),
                        tags=["http", "no-title"],
                    )
                )

    def _analyze_tech(self) -> None:
        """Check detected technologies against known risky tech list."""
        if not self.bundle.tech:
            return
        risky_techs = {
            "WordPress":     "CMS with broad attack surface; verify plugin patch level",
            "Drupal":        "CMS; verify patch level (Drupalgeddon history)",
            "Joomla":        "CMS; verify patch level",
            "PHP":           "Server-side PHP; verify version and configuration",
            "Apache Tomcat": (
                "Java application server; review version and manager app exposure"
            ),
            "Jenkins":       "CI/CD; review anonymous access and script console exposure",
            "GitLab":        "Source control; review registration settings",
        }
        for det in self.bundle.tech.detections:
            if det.name in risky_techs:
                tech_name = det.name
                conf_pct = str(int((det.confidence or 0) * 100))
                self.report.observations.append(
                    SurfaceObservation(
                        asset=self.bundle.target.raw_input,
                        observation=(
                            "Technology '" + tech_name + "' detected "
                            "(confidence: " + conf_pct + "%) — review recommended"
                        ),
                        risk_hint=RiskHint.REVIEW,
                        category="technology",
                        recommendation=risky_techs[det.name],
                        tags=["tech", tech_name.lower().replace(" ", "-")],
                    )
                )

    def _analyze_github(self) -> None:
        """Check GitHub public exposure hints."""
        if not self.bundle.github or not self.bundle.github.hits:
            return
        for hit in self.bundle.github.hits:
            repo_name = hit.repo
            hint_type = hit.hint_type
            self.report.observations.append(
                SurfaceObservation(
                    asset="github:" + repo_name,
                    observation=(
                        "Public GitHub exposure hint in repo '" + repo_name + "' "
                        "(type: " + hint_type + ") — manual validation required"
                    ),
                    risk_hint=RiskHint.REVIEW,
                    category="github-exposure",
                    recommendation=(
                        "Review repository content; "
                        "verify no credentials or secrets are exposed"
                    ),
                    tags=["github", hint_type],
                )
            )

    def _build_priority_list(self) -> None:
        """Collect high/review-risk observations into priority asset list."""
        for obs in self.report.observations:
            if obs.risk_hint in (RiskHint.HIGH, RiskHint.REVIEW):
                if obs.asset not in self.report.priority_assets:
                    self.report.priority_assets.append(obs.asset)

    def _build_summary_notes(self) -> None:
        """
        Produce top-level summary notes from observation counts.

        Sparse findings produce calm, factual notes — no exaggeration.
        Conservative language is enforced: no confirmed vulnerability claims.
        """
        obs    = self.report.observations
        highs  = [o for o in obs if o.risk_hint == RiskHint.HIGH]
        meds   = [o for o in obs if o.risk_hint == RiskHint.MEDIUM]
        review = [o for o in obs if o.risk_hint == RiskHint.REVIEW]

        cat_count = str(len(set(o.category for o in obs)))
        obs_count = str(len(obs))
        notes = [
            "Total observations: " + obs_count
            + " across " + cat_count + " categories.",
        ]

        if highs:
            notes.append(
                str(len(highs))
                + " high-priority observation(s) require manual review."
            )
        if meds:
            notes.append(
                str(len(meds)) + " medium-priority observation(s) identified."
            )
        if review:
            notes.append(
                str(len(review)) + " item(s) flagged for targeted review "
                "(manual validation required)."
            )

        if not obs:
            # Sparse findings — calm, informative, no false alarm
            notes.append(
                "Limited externally visible indicators observed "
                "from the current evidence set."
            )
            checked = []
            if self.bundle.subdomains:
                checked.append("passive subdomain enumeration")
            ct = getattr(self.bundle, "ct", None)
            if ct and getattr(ct, "data_source", "disabled") not in (
                "disabled", "error", "skipped"
            ):
                checked.append("Certificate Transparency logs")
            rdap = getattr(self.bundle, "rdap", None)
            if rdap and getattr(rdap, "data_source", "disabled") not in (
                "disabled", "error", "skipped"
            ):
                checked.append("RDAP/WHOIS/ASN records")
            if self.bundle.http:
                checked.append("lightweight HTTP verification")
            if checked:
                notes.append(
                    "Data checked: " + ", ".join(checked) + ". "
                    "No strong review targets identified from available passive data."
                )
            notes.append(
                "Consider enabling active modules or reviewing CT/RDAP data "
                "manually for additional context."
            )
        elif len(obs) <= 3:
            notes.append(
                "Evidence set is sparse. Confidence in observations is low. "
                "Manual validation is strongly recommended before any conclusions."
            )

        notes.append(
            "DISCLAIMER: All observations are heuristic-based. "
            "No confirmed vulnerabilities are asserted. "
            "Manual validation is required."
        )
        self.report.summary_notes = notes


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_surface_analysis(bundle: ReconBundle) -> SurfaceReport:
    """Convenience wrapper — instantiates SurfaceAnalyzer and runs full analysis."""
    return SurfaceAnalyzer(bundle).analyze()
