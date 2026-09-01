"""Structured logging shared by every STOF layer (Layer 2).

All layers call `get_logger(__name__-ish label)` instead of touching the
`logging` module directly, so log formatting stays consistent with the
`[TAG] message` convention documented in CLAUDE.md's CLI output example.
"""
from __future__ import annotations

import logging
import sys
from typing import IO

_TAG_BY_PREFIX: dict[str, str] = {
    "core.orchestrator": "STOF",
    "config": "CONFIG",
    "recorder": "RECORD",
    "engine": "ENGINE",
    "auth": "AUTH",
    "session": "AUTH",
    "workflows": "WORKFLOW",
    "crawler": "CRAWL",
    "modules": "MOD",
    "findings": "FIND",
    "evidence": "EVIDENCE",
    "reporting": "REPORT",
}


class LayerTagFormatter(logging.Formatter):
    """Formats records as `[TAG] message`, deriving TAG from the logger
    name (e.g. logger `stof.auth.form_login` -> tag `AUTH`)."""

    def format(self, record: logging.LogRecord) -> str:
        name = record.name.removeprefix("stof.")
        tag = "STOF"
        for prefix, mapped in _TAG_BY_PREFIX.items():
            if name == prefix or name.startswith(prefix + "."):
                tag = mapped
                break
        record.tag = tag  # type: ignore[attr-defined]
        return super().format(record)


_configured = False


def configure_logging(level: int = logging.INFO, stream: IO[str] | None = None) -> None:
    """Install the console handler on the root `stof` logger. Safe to
    call more than once — only the first call attaches a handler; later
    calls just adjust the level."""
    global _configured
    root = logging.getLogger("stof")
    root.setLevel(level)

    if _configured:
        return

    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(LayerTagFormatter("[%(tag)s] %(message)s"))
    root.addHandler(handler)
    root.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the shared `stof` namespace, e.g.
    `get_logger("core.orchestrator")` or `get_logger("auth.form_login")`.
    """
    return logging.getLogger(f"stof.{name}")
