"""
utils/logger.py
===============
Centralised logging configuration for ALR.
"""

from __future__ import annotations

import logging
import sys

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
_ROOT_LOGGER  = "alr"
_configured   = False


def configure_logging(verbose: bool = False) -> None:
    """Call once at startup to initialise root logger."""
    global _configured
    if _configured:
        return
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
    root = logging.getLogger(_ROOT_LOGGER)
    root.setLevel(level)
    root.addHandler(handler)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the *alr* namespace."""
    return logging.getLogger(f"{_ROOT_LOGGER}.{name}")
