#!/usr/bin/env python3
"""Standalone workflow recorder — no STOF install required.

Copy this ONE file to the tester's own machine, then:

    pip install playwright
    playwright install chromium
    google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/stof-chrome-debug &
    python3 record_workflow.py --output checkout-flow.json

Attaches to that already-open, already-visible Chrome/Edge over CDP (the
same technique `stof/recorder/recorder.py` uses inside the full package)
and captures clicks, form fills, and navigations while the tester drives
the target application by hand. Because Playwright stays connected to
the browser across page loads, a single run captures a full multi-step
business workflow (login, checkout, an admin wizard, ...) with no
manual re-trigger per page.

The output is the same neutral-action JSON `WorkflowRunner` already
replays (see CLAUDE.md Layer 3A) — upload it to the STOF console's
Workflows panel ("Upload workflow") or drop it straight into
`data/workflows/` on the STOF server. Nothing here talks to a STOF
server; recording is fully offline and local to whichever machine runs
this script.

Credentials: pass --username/--password to have matching `fill` values
tokenised as {{user.username}} / {{user.password}} instead of being
written to the output file verbatim. A password-type field that is
captured but does not match --password is redacted rather than stored.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_CDP_ENDPOINT = "http://localhost:9222"
REDACTED_PLACEHOLDER = "{{REDACTED}}"

_BINDING_NAME = "__stofRecordEvent"

_CAPTURE_SCRIPT = f"""
(() => {{
  function stofCssSelector(el) {{
    if (!(el instanceof Element)) return '';
    if (el.id) return '#' + CSS.escape(el.id);
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && parts.length < 6) {{
      if (node.id) {{ parts.unshift('#' + CSS.escape(node.id)); break; }}
      let selector = node.tagName.toLowerCase();
      let nth = 1;
      let sibling = node;
      while (sibling.previousElementSibling) {{
        sibling = sibling.previousElementSibling;
        if (sibling.tagName === node.tagName) nth++;
      }}
      selector += ':nth-of-type(' + nth + ')';
      parts.unshift(selector);
      node = node.parentElement;
    }}
    return parts.join(' > ');
  }}

  document.addEventListener('click', (event) => {{
    const el = event.target;
    if (!(el instanceof Element)) return;
    window.{_BINDING_NAME}({{ type: 'click', selector: stofCssSelector(el) }});
  }}, true);

  document.addEventListener('change', (event) => {{
    const el = event.target;
    if (!el || !('value' in el)) return;
    const tag = el.tagName;
    if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT') return;
    window.{_BINDING_NAME}({{
      type: 'fill',
      selector: stofCssSelector(el),
      value: el.value,
      field_type: el.type || '',
    }});
  }}, true);
}})();
"""


class EventHandler:
    def __init__(self) -> None:
        self.actions: list[dict[str, Any]] = []
        self._page = None

    async def attach(self, page) -> None:
        self._page = page
        await page.expose_binding(_BINDING_NAME, self._on_browser_event)
        await page.add_init_script(_CAPTURE_SCRIPT)
        page.on("framenavigated", self._on_navigated)
        if page.url and page.url != "about:blank":
            self._record_navigate(page.url)
        print(f"[record] attached, initial url={page.url!r}")

    async def detach(self) -> None:
        if self._page is None:
            return
        self._page.remove_listener("framenavigated", self._on_navigated)
        print(f"[record] detached, captured {len(self.actions)} action(s)")

    def _on_browser_event(self, source: Any, event: dict[str, Any]) -> None:
        if event.get("type") == "click":
            self.actions.append({"type": "click", "selector": event["selector"]})
        elif event.get("type") == "fill":
            self.actions.append({
                "type": "fill", "selector": event["selector"],
                "value": event.get("value", ""), "field_type": event.get("field_type", ""),
            })

    def _on_navigated(self, frame) -> None:
        if self._page is not None and frame == self._page.main_frame:
            self._record_navigate(frame.url)

    def _record_navigate(self, url: str) -> None:
        if not url or url == "about:blank":
            return
        if self.actions and self.actions[-1] == {"type": "navigate", "url": url}:
            return
        self.actions.append({"type": "navigate", "url": url})


def tokenize_credentials(
    actions: list[dict[str, Any]], username: str | None, password: str | None
) -> list[dict[str, Any]]:
    tokenized: list[dict[str, Any]] = []
    for action in actions:
        action = dict(action)
        field_type = action.pop("field_type", None)
        if action.get("type") == "fill":
            value = action.get("value", "")
            if password and value == password:
                action["value"] = "{{user.password}}"
            elif username and value == username:
                action["value"] = "{{user.username}}"
            elif field_type == "password":
                print(
                    f"[record] WARNING: password field '{action.get('selector')}' did not match "
                    "--password; redacting instead of storing it in plain text.",
                    file=sys.stderr,
                )
                action["value"] = REDACTED_PLACEHOLDER
        tokenized.append(action)
    return tokenized


async def record(cdp_endpoint: str, output_path: Path, username: str | None, password: str | None) -> Path:
    from playwright.async_api import async_playwright

    async with async_playwright() as playwright:
        try:
            browser = await playwright.chromium.connect_over_cdp(cdp_endpoint)
        except Exception as exc:
            raise SystemExit(
                f"could not connect to a browser at {cdp_endpoint} -- start one first with "
                f"remote debugging enabled (see the top of this file for the exact command). "
                f"Original error: {exc}"
            ) from exc
        print(f"[record] attached to browser over CDP at {cdp_endpoint}")

        context = browser.contexts[0] if browser.contexts else await browser.new_context()
        page = context.pages[0] if context.pages else await context.new_page()

        handler = EventHandler()
        await handler.attach(page)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, input, "Recording... walk through the workflow, then press Enter here to stop.\n")

        await handler.detach()
        target_url = page.url
        # No browser.close(): this is the tester's own real browser,
        # CDP-attached -- closing it here would end their whole
        # browsing session, not just disconnect this script.

    tokenized = tokenize_credentials(handler.actions, username, password)
    workflow = {
        "workflow_id": f"wf-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:6]}",
        "target_url": target_url,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "actions": tokenized,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(workflow, indent=2) + "\n", encoding="utf-8")
    print(f"[record] saved workflow -> {output_path} ({len(tokenized)} action(s))")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", required=True, help="path to write the workflow JSON to, e.g. checkout-flow.json")
    parser.add_argument("--cdp-endpoint", default=DEFAULT_CDP_ENDPOINT, help=f"CDP endpoint of the already-running browser (default: {DEFAULT_CDP_ENDPOINT})")
    parser.add_argument("--username", default=None, help="value to tokenise as {{user.username}} wherever it's typed")
    parser.add_argument("--password", default=None, help="value to tokenise as {{user.password}} wherever it's typed")
    args = parser.parse_args()

    asyncio.run(record(args.cdp_endpoint, Path(args.output), args.username, args.password))


if __name__ == "__main__":
    main()
