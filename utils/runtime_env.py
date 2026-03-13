"""
utils/runtime_env.py
=====================
Project-local runtime environment builder.

Prepends .tools/bin and .tools/node_modules/.bin to PATH so that
tools installed via scripts/bootstrap_tools.sh are discoverable by ALR
even when they are NOT on the system-wide $PATH.

Usage:
    from utils.runtime_env import get_runtime_env, resolve_tool

    env   = get_runtime_env()           # dict to pass as env= in subprocess
    path  = resolve_tool("subfinder")   # returns full path or None
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Project root detection
# ---------------------------------------------------------------------------

def _find_project_root() -> Path:
    """
    Walk upward from this file to find the ALR project root.
    Identified by the presence of 'cli/' and 'collectors/' directories.
    """
    here = Path(__file__).resolve().parent
    for candidate in [here, here.parent, here.parent.parent]:
        if (candidate / "cli").is_dir() and (candidate / "collectors").is_dir():
            return candidate
    # Fallback: current working directory
    return Path.cwd()


PROJECT_ROOT: Path = _find_project_root()

# Directories to inject into PATH (order matters — project-local first)
_LOCAL_BIN_DIRS: list[Path] = [
    PROJECT_ROOT / ".tools" / "bin",
    PROJECT_ROOT / ".tools" / "node_modules" / ".bin",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_runtime_env() -> dict[str, str]:
    """
    Return a copy of os.environ with project-local tool directories
    prepended to PATH.

    This environment dict should be passed as `env=` to every subprocess
    call that invokes external tools.
    """
    env  = os.environ.copy()
    existing_path = env.get("PATH", "")

    # Build prepend list (only existing directories)
    prepend_parts = [
        str(d) for d in _LOCAL_BIN_DIRS if d.is_dir()
    ]

    if prepend_parts:
        new_path = os.pathsep.join(prepend_parts + [existing_path])
        env["PATH"] = new_path

    return env


def resolve_tool(name: str) -> Optional[str]:
    """
    Resolve the full path to *name* using the ALR runtime PATH.

    Checks project-local directories first, then falls back to
    system PATH via shutil.which.

    Parameters
    ----------
    name : str
        Binary name (e.g. "subfinder").

    Returns
    -------
    str or None
        Absolute path to the binary, or None if not found anywhere.
    """
    # 1. Check project-local directories explicitly
    for local_dir in _LOCAL_BIN_DIRS:
        candidate = local_dir / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

        # Windows: try with .exe
        candidate_exe = local_dir / (name + ".exe")
        if candidate_exe.is_file() and os.access(candidate_exe, os.X_OK):
            return str(candidate_exe)

    # 2. Fall back to system PATH via shutil.which (uses current os.environ)
    return shutil.which(name)


def get_local_bin_dirs() -> list[str]:
    """Return the list of project-local bin directory paths (as strings)."""
    return [str(d) for d in _LOCAL_BIN_DIRS]
