"""
core/target_manager.py
======================
Validates and classifies the recon target (domain / IP / CIDR),
then builds the TargetContext that flows through the entire pipeline.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from pathlib import Path

from models.schema import InputType, TargetContext
from utils.logger import get_logger

logger = get_logger(__name__)

# RFC-1123 hostname regex (permissive)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def _classify_input(raw: str) -> InputType:
    """Return the InputType for *raw* input string."""
    raw = raw.strip()

    # CIDR block
    try:
        ipaddress.ip_network(raw, strict=False)
        if "/" in raw:
            return InputType.CIDR
        return InputType.IP
    except ValueError:
        pass

    # Plain IP
    try:
        ipaddress.ip_address(raw)
        return InputType.IP
    except ValueError:
        pass

    # Domain
    if _DOMAIN_RE.match(raw):
        return InputType.DOMAIN

    return InputType.UNKNOWN


def build_target_context(
    raw_input: str,
    output_dir: str = "data/outputs",
    timeout: int = 60,
    verbose: bool = False,
    enable_ai: bool = False,
    enable_github: bool = False,
) -> TargetContext:
    """
    Validate *raw_input* and produce a :class:`TargetContext`.

    Raises
    ------
    ValueError
        If the input cannot be classified as a domain, IP, or CIDR.
    """
    raw = raw_input.strip().lower()
    input_type = _classify_input(raw)

    if input_type is InputType.UNKNOWN:
        raise ValueError(
            f"Cannot classify input '{raw}' as domain, IP, or CIDR. "
            "Please provide a valid target."
        )

    run_id = uuid.uuid4().hex[:12]
    run_output_dir = str(Path(output_dir) / run_id)
    Path(run_output_dir).mkdir(parents=True, exist_ok=True)

    ctx = TargetContext(
        raw_input=raw,
        input_type=input_type,
        domain=raw if input_type is InputType.DOMAIN else None,
        ip=raw if input_type in (InputType.IP, InputType.CIDR) else None,
        run_id=run_id,
        started_at=datetime.utcnow(),
        output_dir=run_output_dir,
        timeout=timeout,
        verbose=verbose,
        enable_ai=enable_ai,
        enable_github=enable_github,
    )

    logger.info(
        "Target context built | run_id=%s | type=%s | target=%s",
        run_id, input_type.value, raw,
    )
    return ctx
