"""
utils/subprocess_runner.py
==========================
Safe subprocess wrapper for external CLI tools.
- Uses project-local runtime PATH injection via runtime_env
- Enforces timeout
- Returns structured ToolResult — never raises
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional

from utils.logger import get_logger
from utils.runtime_env import get_runtime_env, resolve_tool

logger = get_logger(__name__)


@dataclass
class ToolResult:
    """Structured result from a single tool invocation."""
    tool:          str
    command:       list
    returncode:    int           = -1
    stdout:        str           = ""
    stderr:        str           = ""
    timed_out:     bool          = False
    skipped:       bool          = False
    skip_reason:   str           = ""
    error:         Optional[str] = None
    resolved_path: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.skipped


def is_tool_available(name: str) -> bool:
    """Return True if *name* is found via ALR runtime PATH."""
    return resolve_tool(name) is not None


def run_tool(
    tool: str,
    args: list,
    timeout: int = 60,
    stdin_input: Optional[str] = None,
    cwd: Optional[str] = None,
) -> ToolResult:
    """
    Execute *tool* with *args* using the ALR runtime environment.
    Project-local .tools/bin is checked before system PATH.
    Always returns a ToolResult — never raises.
    """
    resolved = resolve_tool(tool)

    if not resolved:
        logger.warning("Tool not found in runtime PATH: %s — skipping", tool)
        return ToolResult(
            tool=tool,
            command=[tool] + args,
            skipped=True,
            skip_reason="'" + tool + "' not found in runtime PATH (system or .tools/bin)",
        )

    cmd = [resolved] + args
    runtime_env = get_runtime_env()
    logger.debug("Running: %s", " ".join(str(c) for c in cmd))

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=runtime_env,
        )
        result = ToolResult(
            tool=tool,
            command=cmd,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            resolved_path=resolved,
        )
        if proc.returncode != 0:
            logger.warning("%s exited with code %d: %s",
                           tool, proc.returncode, proc.stderr[:200])
        return result

    except subprocess.TimeoutExpired:
        logger.error("Timeout (%ds) exceeded for: %s", timeout, tool)
        return ToolResult(tool=tool, command=cmd, timed_out=True,
                          error="Timed out after " + str(timeout) + "s",
                          resolved_path=resolved)
    except Exception as exc:
        logger.error("Unexpected error running %s: %s", tool, exc)
        return ToolResult(tool=tool, command=cmd, error=str(exc),
                          resolved_path=resolved)
