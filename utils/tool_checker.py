"""
utils/tool_checker.py
======================
Pre-flight tool availability checks and --doctor diagnostics.

Separates required tools (hard fail without --allow-mock)
from optional tools (warn only).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from utils.runtime_env import resolve_tool, get_local_bin_dirs, PROJECT_ROOT
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Tool registry — passive-first design
# ---------------------------------------------------------------------------
#
# Default passive pipeline only requires subfinder.
# Censys is API-key based (no binary), so not checked here.
# Active verification tools are optional and non-default.

# Default MVP pipeline tools
REQUIRED_TOOLS: list[str] = ["subfinder", "httpx"]

# Secondary active tools (non-default, future/optional)
ACTIVE_TOOLS: list[str] = ["dnsx", "naabu"]

# Legacy alias
OPTIONAL_TOOLS: list[str] = []

ALL_TOOLS: list[str] = REQUIRED_TOOLS + ACTIVE_TOOLS


@dataclass
class ToolStatus:
    name:      str
    required:  bool
    found:     bool
    path:      Optional[str] = None


def check_all_tools(include_active: bool = True) -> list[ToolStatus]:
    """Resolve every tool and return a list of ToolStatus objects."""
    statuses: list[ToolStatus] = []
    for name in REQUIRED_TOOLS:
        path = resolve_tool(name)
        statuses.append(ToolStatus(name=name, required=True,
                                   found=path is not None, path=path))
    if include_active:
        for name in ACTIVE_TOOLS:
            path = resolve_tool(name)
            statuses.append(ToolStatus(name=name, required=False,
                                       found=path is not None, path=path))
    return statuses


def missing_required(statuses: list[ToolStatus]) -> list[str]:
    """Return names of required tools that are NOT found."""
    return [s.name for s in statuses if s.required and not s.found]


# ---------------------------------------------------------------------------
# Doctor output
# ---------------------------------------------------------------------------

def run_doctor() -> int:
    """
    Print diagnostics table for passive-first pipeline.
    Returns 0 if all passive required tools found, 1 otherwise.
    """
    import os
    statuses = check_all_tools(include_active=True)

    print("")
    print("=" * 60)
    print("  ALR — Tool Diagnostics (--doctor)")
    print("  Mode: PASSIVE-FIRST")
    print("=" * 60)
    print("")
    print("Project root : " + str(PROJECT_ROOT))
    print("Local bin dirs:")
    for d in get_local_bin_dirs():
        print("  " + d)
    print("")

    # Passive required tools
    print("Passive pipeline tools (default):")
    print("")
    all_required_ok = True
    for s in statuses:
        if not s.required:
            continue
        indicator = "[OK]  " if s.found else "[MISS]"
        detail    = s.path if s.found else "not found"
        if not s.found:
            all_required_ok = False
        label = (s.name + "          ")[:12]
        print("  " + indicator + " " + label + " (PASSIVE/REQUIRED)  ->  " + detail)

    # Censys API key
    censys_id = os.getenv("CENSYS_API_ID", "") or os.getenv("CENSYS_API_KEY", "")
    if censys_id:
        print("  [OK]   censys       (PASSIVE/API-KEY)  ->  credentials found in env")
    else:
        print("  [MISS] censys       (PASSIVE/API-KEY)  ->  set CENSYS_API_ID + CENSYS_API_SECRET in .env")

    print("")

    # Active optional tools
    print("Active verification tools (--enable-active-verify, non-default):")
    print("")
    for s in statuses:
        if s.required:
            continue
        indicator = "[OK]  " if s.found else "[--]  "
        detail    = s.path if s.found else "not installed (optional)"
        label = (s.name + "          ")[:12]
        print("  " + indicator + " " + label + " (ACTIVE/OPTIONAL)  ->  " + detail)

    print("")
    if all_required_ok:
        print("  ✅  Passive pipeline ready.")
    else:
        missing = [s.name for s in statuses if s.required and not s.found]
        print("  ❌  Missing: " + ", ".join(missing))
        print("")
        print("  Remediation:  bash ./scripts/bootstrap_tools.sh")
        print("  Demo mode:    python3 -m cli.main --domain example.com --allow-mock")

    print("")
    print("=" * 60)
    print("")

    return 0 if all_required_ok else 1


# ---------------------------------------------------------------------------
# Pre-flight check used by orchestrator
# ---------------------------------------------------------------------------

def preflight_check(
    allow_mock: bool = False,
    strict_tools: bool = False,
    enable_active: bool = False,
) -> dict[str, str]:
    """
    Validate tool availability before the pipeline starts.

    Passive-first: only subfinder is required by default.
    Active tools (dnsx/httpx/naabu) are checked only when enable_active=True.

    Returns
    -------
    dict[str, str]
        Module name -> data source label
    """
    # Only check passive required tools in default mode
    statuses = check_all_tools(include_active=enable_active)
    missing  = missing_required(statuses)
    module_status: dict[str, str] = {}

    tool_module_map = {
        "subfinder": "subdomains",
        "dnsx":      "dns",
        "httpx":     "http",
        "naabu":     "ports",
    }

    for s in statuses:
        mod = tool_module_map.get(s.name, s.name)
        if s.found:
            module_status[mod] = "passive" if s.name == "subfinder" else "active"
        elif not s.required:
            module_status[mod] = "disabled"
        else:
            module_status[mod] = "mock" if allow_mock else "missing"

    # These are never tool-binary based
    module_status.setdefault("censys",  "disabled")  # updated at runtime if creds found
    module_status.setdefault("tech",    "heuristic")
    module_status.setdefault("github",  "disabled")

    # Active tools not requested → mark disabled
    if not enable_active:
        for t in ACTIVE_TOOLS:
            mod = tool_module_map.get(t, t)
            module_status.setdefault(mod, "disabled")

    # CT and RDAP are always passive (no binary needed)
    module_status.setdefault("ct", "ct_passive")
    module_status.setdefault("rdap", "rdap_passive")

    if missing and strict_tools:
        _print_missing_error(missing)
        raise SystemExit(1)

    if missing and not allow_mock:
        _print_missing_error(missing)
        raise SystemExit(1)

    if missing and allow_mock:
        _print_mock_warning(missing)

    return module_status


def _print_missing_error(missing: list[str]) -> None:
    print("")
    print("=" * 60)
    print("  ❌  ALR — Required tools not found")
    print("=" * 60)
    print("")
    print("  Missing: " + ", ".join(missing))
    print("")
    print("  ALR requires real tools to produce trustworthy results.")
    print("  Install them with:")
    print("")
    print("    bash ./scripts/bootstrap_tools.sh")
    print("")
    print("  Then verify with:")
    print("")
    print("    python3 -m cli.main --doctor")
    print("")
    print("  If you want to run in demo/mock mode (NOT for real assessments):")
    print("")
    print("    python3 -m cli.main --domain example.com --allow-mock")
    print("")
    print("=" * 60)
    print("")


def _print_mock_warning(missing: list[str]) -> None:
    print("")
    print("*" * 60)
    print("  ⚠️   WARNING: MOCK / FALLBACK MODE ENABLED")
    print("*" * 60)
    print("  The following tools are missing and will use MOCK data:")
    for m in missing:
        print("    - " + m)
    print("")
    print("  Mock data is NOT real reconnaissance output.")
    print("  Do NOT use this report for real security assessments.")
    print("*" * 60)
    print("")
