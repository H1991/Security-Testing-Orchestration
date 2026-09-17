"""Layer 3A — captures click / input / XHR / navigation events from a
page the tester is manually driving in an attached browser.

Real user clicks and keystrokes are not visible to Playwright's own page
API (that surface is for driving the browser programmatically), so click
and input capture works by injecting a listener script into every
document via `add_init_script` + `expose_binding` — the same technique
Playwright's own inspector/codegen uses. Navigation and XHR/fetch capture
use Playwright's native `framenavigated` / `request` events instead,
since those ARE visible over CDP without any injection.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from playwright.async_api import Frame, Page, Request

_log = get_logger("recorder.event_handler")

_BINDING_NAME = "__stofRecordEvent"

# Internal browser pages a fresh (or mid-navigation) tab can sit on that
# were never a real step the tester took -- a brand-new tab starts on
# "chrome://new-tab-page/", not "about:blank", so excluding only
# "about:blank" let that internal URL slip through as a spurious first
# `navigate` action. Replaying it later fails outright: browsers refuse
# a `Page.goto()` to their own internal chrome:// pages under automation.
_INTERNAL_URL_PREFIXES = ("chrome://", "chrome-error://", "chrome-extension://", "devtools://", "edge://", "about:")


def _is_recordable_url(url: str) -> bool:
    return bool(url) and not url.startswith(_INTERNAL_URL_PREFIXES)

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
    // A <select> needs Playwright's `select_option()`, not `fill()` --
    // `fill()` only ever works on a text-enterable INPUT/TEXTAREA and
    // hangs until its own timeout on anything else.
    window.{_BINDING_NAME}({{
      type: tag === 'SELECT' ? 'select' : 'fill',
      selector: stofCssSelector(el),
      value: el.value,
      field_type: el.type || '',
    }});
  }}, true);
}})();
"""


class EventHandler:
    """Captures `navigate` / `fill` / `click` actions (for workflow
    replay) plus XHR/fetch requests (`network_events`, informational
    only — not part of the exported workflow schema)."""

    def __init__(self) -> None:
        self.actions: list[dict[str, Any]] = []
        self.network_events: list[dict[str, Any]] = []
        self._page: "Page | None" = None

    async def attach(self, page: "Page") -> None:
        self._page = page
        await page.expose_binding(_BINDING_NAME, self._on_browser_event)
        await page.add_init_script(_CAPTURE_SCRIPT)
        page.on("framenavigated", self._on_navigated)
        page.on("request", self._on_request)

        if _is_recordable_url(page.url):
            self._record_navigate(page.url)

        _log.info(f"attached to page, initial url={page.url!r}")

    async def detach(self) -> None:
        if self._page is None:
            return
        self._page.remove_listener("framenavigated", self._on_navigated)
        self._page.remove_listener("request", self._on_request)
        _log.info(f"detached, captured {len(self.actions)} actions")

    # -- Playwright/browser callbacks ------------------------------------

    def _on_browser_event(self, source: Any, event: dict[str, Any]) -> None:
        event_type = event.get("type")
        if event_type == "click":
            self.actions.append({"type": "click", "selector": event["selector"]})
        elif event_type in ("fill", "select"):
            self.actions.append(
                {
                    "type": event_type,
                    "selector": event["selector"],
                    "value": event.get("value", ""),
                    "field_type": event.get("field_type", ""),
                }
            )

    def _on_navigated(self, frame: "Frame") -> None:
        if self._page is not None and frame == self._page.main_frame:
            self._record_navigate(frame.url)

    def _on_request(self, request: "Request") -> None:
        if request.resource_type in ("xhr", "fetch"):
            self.network_events.append({"method": request.method, "url": request.url})

    # -- internal ----------------------------------------------------------

    def _record_navigate(self, url: str) -> None:
        if not _is_recordable_url(url):
            return
        if self.actions and self.actions[-1] == {"type": "navigate", "url": url}:
            return
        self.actions.append({"type": "navigate", "url": url})
