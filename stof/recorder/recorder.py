"""Layer 3A — Browser Recorder.

Attaches to a Chrome/Edge instance the tester already has open (started
with `--remote-debugging-port=9222`) via Playwright's CDP client — it
does NOT launch a new browser. The tester interacts with the site
manually; `EventHandler` captures those interactions; `exporter` writes
them out as a neutral JSON workflow in `data/workflows/`.

The recorder is a standalone, optional command (`stof record`, once
Layer 15/CLI wiring exists) — it never runs as part of a scan. Scans
replay pre-recorded workflows instead (Layer 3B/6).
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path

from playwright.async_api import async_playwright

from stof.config import UsersConfig
from stof.core.logger import get_logger

from . import exporter
from .event_handler import EventHandler

DEFAULT_CDP_ENDPOINT = "http://localhost:9222"

_log = get_logger("recorder")


async def _wait_for_enter() -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, input, "Recording... press Enter here to stop.\n")


async def record(
    output_path: str | Path,
    cdp_endpoint: str = DEFAULT_CDP_ENDPOINT,
    users: UsersConfig | None = None,
    workflow_id: str | None = None,
    wait_for_stop: Callable[[], Awaitable[None]] | None = None,
) -> Path:
    """Record a workflow from a running, CDP-debuggable browser.

    Attaches to the first existing browser context/page found at
    `cdp_endpoint` (Chrome must already be running with
    `--remote-debugging-port=9222` and have the target page open).
    Recording stops when `wait_for_stop` resolves (defaults to waiting
    for Enter on stdin). The resulting workflow is written to
    `output_path` with credentials tokenised via `users`, if provided.
    """
    async with async_playwright() as playwright:
        browser = await playwright.chromium.connect_over_cdp(cdp_endpoint)
        _log.info(f"attached to browser over CDP at {cdp_endpoint}")

        context = browser.contexts[0] if browser.contexts else await browser.new_context()
        page = context.pages[0] if context.pages else await context.new_page()

        handler = EventHandler()
        await handler.attach(page)

        await (wait_for_stop() if wait_for_stop is not None else _wait_for_enter())

        await handler.detach()
        target_url = page.url
        # Do not call browser.close() here: for a CDP-attached browser
        # that would tear down the tester's own Chrome session, not just
        # disconnect Playwright's client.

    tokenized_actions = exporter.tokenize_credentials(handler.actions, users)
    workflow = exporter.build_workflow(
        target_url=target_url, actions=tokenized_actions, workflow_id=workflow_id
    )
    path = exporter.write_workflow(workflow, output_path)
    _log.info(
        f"saved workflow -> {path} "
        f"({len(tokenized_actions)} actions, {len(handler.network_events)} XHR/fetch calls seen)"
    )
    return path
