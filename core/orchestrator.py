"""
core/orchestrator.py
=====================
Recon pipeline orchestrator — final MVP design.

Default MVP pipeline (passive + light-active):
  1. subfinder  → passive subdomain discovery
  2. ct         → Certificate Transparency passive enrichment (crt.sh)
  3. rdap       → RDAP/WHOIS/ASN passive enrichment
  4. httpx      → lightweight HTTP asset verification (light_active)
  5. tech       → heuristic from HTTP metadata
  6. github     → optional public exposure hints

Secondary / non-default (--enable-secondary-active):
  + dns   → dnsx DNS resolution
  + ports → naabu port scan

Note: Censys is disabled — removed from default path (no API key required).
"""
from __future__ import annotations
import time
import traceback
from typing import Callable

from models.schema import ReconBundle, TargetContext
from collectors import (subdomain_collector, http_collector,
                        tech_collector, github_collector,
                        ct_collector, rdap_collector)
from utils.logger import get_logger

logger = get_logger(__name__)


class PipelineStep:
    def __init__(self, name: str, fn: Callable, enabled: bool = True):
        self.name    = name
        self.fn      = fn
        self.enabled = enabled


class ReconOrchestrator:
    def __init__(
        self,
        ctx: TargetContext,
        allow_mock: bool = False,
        enable_secondary: bool = False,  # enables dnsx + naabu
    ):
        self.ctx              = ctx
        self.allow_mock       = allow_mock
        self.enable_secondary = enable_secondary
        self.bundle           = ReconBundle(target=ctx)
        self.module_status:   dict[str, str] = {}

    def run(self) -> ReconBundle:
        mode = "passive+light-active+secondary" if self.enable_secondary else "passive+light-active"
        logger.info("=== ALR Pipeline START | run_id=%s | target=%s | mode=%s ===",
                    self.ctx.run_id, self.ctx.raw_input, mode)
        t_start = time.monotonic()

        for step in self._build_pipeline():
            if not step.enabled:
                logger.info("[SKIP] %s", step.name)
                self.module_status[step.name] = "skipped"
                continue

            logger.info("[START] %s", step.name)
            t = time.monotonic()
            try:
                result = step.fn()
                elapsed = time.monotonic() - t
                if result is not None:
                    setattr(self.bundle, step.name, result)
                    ds = getattr(result, "data_source", "ok")
                    self.module_status[step.name] = ds
                    logger.info("[OK] %s — %.1fs (source: %s)", step.name, elapsed, ds)
                else:
                    self.module_status[step.name] = "empty"
                    logger.warning("[WARN] %s returned None", step.name)
            except Exception as exc:
                elapsed = time.monotonic() - t
                err = type(exc).__name__ + ": " + str(exc)
                self.bundle.errors[step.name] = err
                self.module_status[step.name] = "error"
                logger.error("[FAIL] %s — %.1fs — %s\n%s",
                             step.name, elapsed, err, traceback.format_exc())

        total = time.monotonic() - t_start
        logger.info("=== Pipeline COMPLETE | %.1fs | errors=%d ===",
                    total, len(self.bundle.errors))

        mock_mods = [k for k, v in self.module_status.items() if v == "mock"]
        if mock_mods:
            print("")
            print("*" * 60)
            print("  WARNING: Mock data used for: " + ", ".join(mock_mods))
            print("  This report does NOT reflect real reconnaissance results.")
            print("*" * 60)
            print("")

        return self.bundle

    def _build_pipeline(self) -> list[PipelineStep]:
        ctx = self.ctx
        am  = self.allow_mock
        es  = self.enable_secondary

        steps = [
            # ---- Passive ----
            PipelineStep(
                name="subdomains",
                fn=lambda: subdomain_collector.collect_subdomains(ctx, allow_mock=am),
                enabled=(str(ctx.input_type) == "domain"),
            ),
            PipelineStep(
                name="ct",
                fn=lambda: ct_collector.collect_ct(ctx, timeout=ctx.timeout),
                enabled=(str(ctx.input_type) == "domain"),
            ),
            PipelineStep(
                name="rdap",
                fn=lambda: rdap_collector.collect_rdap(ctx),
            ),

            # ---- Light active ----
            PipelineStep(
                name="http",
                fn=lambda: http_collector.collect_http(
                    ctx, allow_mock=am, subdomains=self.bundle.subdomains),
            ),

            # ---- Heuristic ----
            PipelineStep(
                name="tech",
                fn=lambda: tech_collector.collect_tech(
                    ctx, http_profile=self.bundle.http),
            ),

            # ---- Optional ----
            PipelineStep(
                name="github",
                fn=lambda: github_collector.collect_github_exposure(ctx),
                enabled=getattr(ctx, "enable_github", False),
            ),

            # ---- Secondary active (non-default) ----
            PipelineStep(
                name="dns",
                fn=lambda: _lazy_dns(ctx, am, self.bundle.subdomains),
                enabled=es,
            ),
            PipelineStep(
                name="ports",
                fn=lambda: _lazy_ports(ctx, am),
                enabled=es,
            ),
        ]
        return steps


def _lazy_dns(ctx, allow_mock, subdomains):
    """Import dns_collector only when secondary active mode is enabled."""
    from collectors import dns_collector
    return dns_collector.collect_dns(ctx, allow_mock=allow_mock, subdomains=subdomains)


def _lazy_ports(ctx, allow_mock):
    """Import port_collector only when secondary active mode is enabled."""
    from collectors import port_collector
    return port_collector.collect_ports(ctx, allow_mock=allow_mock)
