from __future__ import annotations

import logging
import sys

_LOG: logging.Logger | None = None


def get_logger(name: str = "modelchain") -> logging.Logger:
    """Get the ModelChain logger.

    Returns a configured logger instance. Lazy-initialized on first call.
    """
    global _LOG
    if _LOG is not None:
        return _LOG

    _LOG = logging.getLogger(name)
    _LOG.setLevel(logging.INFO)

    if not _LOG.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.INFO)
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(fmt)
        _LOG.addHandler(handler)

    return _LOG


__all__ = ["get_logger"]
