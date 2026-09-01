"""Layer 3B — screenshot on assertion / finding.

Called by vulnerability modules only when a finding is confirmed —
never called speculatively during normal replay.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from playwright.async_api import Page

_log = get_logger("engine.screenshot")

DEFAULT_SCREENSHOT_DIR = Path("data/evidence")

_UNSAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9_-]+")


def _safe_filename(label: str) -> str:
    return _UNSAFE_CHARS_RE.sub("_", label).strip("_") or "screenshot"


async def capture(
    page: "Page",
    output_dir: str | Path = DEFAULT_SCREENSHOT_DIR,
    label: str = "finding",
) -> Path:
    """Take a full-page screenshot of `page` and save it under
    `output_dir`, returning the written path."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    path = directory / f"{_safe_filename(label)}_{timestamp}.png"

    await page.screenshot(path=str(path), full_page=True)
    _log.info(f"captured screenshot -> {path}")
    return path
