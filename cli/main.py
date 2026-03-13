"""
cli/main.py
============
ALR — Availability Low Reconnaissance
Passive-first, no required external API.

Default MVP pipeline:
  subfinder (passive) + crt.sh CT (passive) + RDAP/ASN (passive)
  + httpx (light-active) + heuristic tech + optional GitHub

Usage:
    python3 -m cli.main --doctor
    python3 -m cli.main --domain example.com
    python3 -m cli.main --domain example.com --enable-github-check
    python3 -m cli.main --domain example.com --enable-secondary-active
    python3 -m cli.main --domain example.com --allow-mock
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Load .env before any module that reads os.getenv() (settings, ai_client, etc.)
# override=True ensures .env values win over any pre-existing shell env vars.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(_PROJECT_ROOT) / ".env", override=True)
except ImportError:
    pass  # python-dotenv absent — settings.py has a stdlib fallback

from utils.logger import configure_logging, get_logger
from utils.tool_checker import run_doctor, preflight_check
from core.target_manager import build_target_context
from core.orchestrator import ReconOrchestrator
from analyzers.surface_analyzer import run_surface_analysis
from ai.report_generator import generate_ai_report as _build_report
from reports.markdown_writer import write_markdown_report
from reports.json_writer import write_json_output
from reports.pdf_writer import write_pdf_report

logger = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alr",
        description=(
            "ALR — Availability Low Reconnaissance\n"
            "Passive-first OSINT framework. No paid API required.\n\n"
            "Default: subfinder + crt.sh CT + RDAP/ASN + httpx (light-active)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 -m cli.main --doctor
  python3 -m cli.main --domain example.com
  python3 -m cli.main --domain example.com --enable-ai
  python3 -m cli.main --domain example.com --enable-github-check
  python3 -m cli.main --domain example.com --enable-secondary-active
  python3 -m cli.main --domain example.com --allow-mock
  python3 -m cli.main --ip 203.0.113.10 --output-dir ./results
        """,
    )

    target = parser.add_mutually_exclusive_group()
    target.add_argument("--domain", "-d", metavar="DOMAIN")
    target.add_argument("--ip",     "-i", metavar="IP")

    parser.add_argument("--output-dir", "-o", default="data/outputs", metavar="DIR")
    parser.add_argument("--timeout",    "-t", type=int, default=60, metavar="SECONDS")
    parser.add_argument("--verbose",    "-v", action="store_true", default=False)

    # Feature toggles
    parser.add_argument("--enable-github-check", action="store_true", default=False,
                        help="Enable GitHub public exposure hints (optional)")
    parser.add_argument("--enable-secondary-active", action="store_true", default=False,
                        help="Add dnsx + naabu (non-default secondary active tools)")
    parser.add_argument("--no-pdf", action="store_true", default=False,
                        help="Skip PDF export")

    # Mode flags
    parser.add_argument("--allow-mock", action="store_true", default=False,
                        help="Allow mock/fallback data (demo/dev only)")
    parser.add_argument("--strict-tools", action="store_true", default=False,
                        help="Hard fail if any required tool is missing")
    parser.add_argument("--doctor", action="store_true", default=False,
                        help="Run tool diagnostics and exit")

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    configure_logging(verbose=args.verbose)

    if args.doctor:
        return run_doctor()

    if not args.domain and not args.ip:
        parser.error("One of --domain or --ip is required (or use --doctor)")

    # passive_only = no secondary active tools
    passive_only     = not args.enable_secondary_active
    enable_secondary = args.enable_secondary_active
    allow_mock       = args.allow_mock
    strict_tools     = args.strict_tools

    if strict_tools and allow_mock:
        logger.warning("--strict-tools overrides --allow-mock")
        allow_mock = False

    logger.info("=" * 60)
    logger.info("  ALR — Availability Low Reconnaissance")
    mode_label = "passive + light-active" + (" + secondary" if enable_secondary else "")
    logger.info("  Mode: %s", mode_label)
    logger.info("=" * 60)

    # Pre-flight
    try:
        module_status = preflight_check(
            allow_mock=allow_mock,
            strict_tools=strict_tools,
            enable_active=enable_secondary,
        )
    except SystemExit:
        return 1

    # Build context
    raw_input = args.domain or args.ip
    try:
        ctx = build_target_context(
            raw_input=raw_input,
            output_dir=args.output_dir,
            timeout=args.timeout,
            verbose=args.verbose,
            enable_ai=False,
            enable_github=args.enable_github_check,
        )
    except ValueError as exc:
        logger.error("Invalid target: %s", exc)
        return 1

    # Run pipeline
    orchestrator = ReconOrchestrator(
        ctx,
        allow_mock=allow_mock,
        enable_secondary=enable_secondary,
    )
    bundle = orchestrator.run()

    for k, v in orchestrator.module_status.items():
        module_status[k] = v

    # Surface analysis
    logger.info("Running surface analysis...")
    surface = run_surface_analysis(bundle)

    # Generate structured report (no AI API required)
    logger.info("Generating report outputs...")
    report = _build_report(bundle, surface,
                           module_status=module_status,
                           passive_only=passive_only)

    # Write outputs
    json_path = write_json_output(
        bundle, surface, report, ctx.output_dir,
        module_status=module_status,
        allow_mock=allow_mock,
        strict_tools=strict_tools,
        passive_only=passive_only,
    )
    md_path = write_markdown_report(
        bundle, surface, report, ctx.output_dir,
        module_status=module_status,
        allow_mock=allow_mock,
        passive_only=passive_only,
    )

    # PDF export
    pdf_path = None
    if not args.no_pdf:
        pdf_path = write_pdf_report(
            bundle=bundle,
            surface=surface,
            ai_report=report,
            md_path=md_path,
            output_dir=ctx.output_dir,
            target=ctx.raw_input,
            run_id=ctx.run_id,
            module_status=module_status,
            passive_only=passive_only,
            allow_mock=allow_mock,
        )

    # Summary
    mock_used = any(v == "mock" for v in module_status.values())
    logger.info("")
    logger.info("=" * 60)
    logger.info("  RUN COMPLETE")
    logger.info("  Target:       %s", ctx.raw_input)
    logger.info("  Mode:         %s", mode_label)
    logger.info("  Run ID:       %s", ctx.run_id)
    logger.info("  Output dir:   %s", ctx.output_dir)
    logger.info("  JSON:         %s", json_path)
    logger.info("  Markdown:     %s", md_path)
    if pdf_path:
        logger.info("  PDF:          %s", pdf_path)
    logger.info("  Observations: %d", len(surface.observations))
    logger.info("  Mock used:    %s", mock_used)
    if bundle.errors:
        logger.warning("  Errors:       %d module(s)", len(bundle.errors))
    logger.info("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
