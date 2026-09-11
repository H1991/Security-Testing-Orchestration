#!/usr/bin/env python3
"""All-in-one workflow recorder — no manual setup, no STOF install required.

Copy this ONE file to the tester's own machine (it needs a real screen —
this launches a real, visible browser window for a human to click
through), then just:

    python3 record_workflow.py --name admin_login

That single command handles everything a tester used to have to do by
hand across four separate steps: it creates its own local virtual
environment (`.stof_recorder_env`, next to this file — reused on every
later run, so only the FIRST run ever pays the install cost), installs
Playwright and the Chromium build it drives, launches that Chromium
with remote debugging enabled, and attaches to it to start recording.
Walk through the real flow in the window that opens — login, checkout,
an admin wizard, whatever the workflow needs — then press Enter in this
terminal to stop. The browser this script launched closes automatically
when it's done (pass --keep-browser-open to leave it running instead).

Already have your own debuggable browser open (e.g. your normal daily
Chrome, restarted once with remote debugging on)? Pass --cdp-endpoint
to attach to that instead of having this script launch its own.

The output is the same neutral-action JSON `WorkflowRunner` already
replays (see CLAUDE.md Layer 3A) — saved as `<name>.json` — upload it to
the STOF console's Workflows panel ("Upload workflow") or drop it
straight into `data/workflows/` on the STOF server. Nothing here talks
to a STOF server; recording is fully offline and local to whichever
machine runs this script.

Credentials: pass --username/--password to have matching `fill` values
tokenised as {{user.username}} / {{user.password}} instead of being
written to the output file verbatim. A password-type field that is
captured but does not match --password is redacted rather than stored.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
import venv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DEBUG_PORT = 9222
REDACTED_PLACEHOLDER = "{{REDACTED}}"

# Marks a re-exec'd invocation (see `_ensure_venv_and_bootstrap`) so the
# bootstrap step never loops on itself.
_BOOTSTRAP_FLAG = "--_bootstrapped"
_VENV_DIR_NAME = ".stof_recorder_env"

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


# ---------------------------------------------------------------------------
# Bootstrap: venv + Playwright + Chromium install, then re-exec inside it.
# EVERYTHING above and including this section must run with only the
# standard library available -- nothing here may `import playwright`,
# since a first-ever run has neither the venv nor the package yet.
# ---------------------------------------------------------------------------


def _venv_python(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _ensure_venv_and_bootstrap(argv: list[str]) -> None:
    """Creates (or reuses) a local venv with Playwright + its Chromium
    build installed, then re-execs THIS SAME FILE inside that venv's own
    interpreter with `_BOOTSTRAP_FLAG` appended so the next run of
    `main()` skips straight to recording instead of bootstrapping again.
    `os.execv` replaces this process outright (never returns on
    success) -- there is deliberately no second Python process left
    running once this hands off."""
    script_path = Path(__file__).resolve()
    venv_dir = script_path.parent / _VENV_DIR_NAME
    py = _venv_python(venv_dir)

    if not py.exists():
        print(f"[setup] creating a virtual environment at '{venv_dir}' (one-time) ...")
        venv.EnvBuilder(with_pip=True).create(venv_dir)

    # Cheap "is this already set up" probe -- keeps every run AFTER the
    # first one fast (no pip/playwright-install round trip just to
    # confirm nothing changed). Every subprocess call in this function
    # runs a FIXED argument list (this script's own venv interpreter,
    # literal pip/playwright sub-commands) -- never shell=True, never a
    # string built from user input -- the exact shape ruff's S603 exists
    # to flag as a *possibility* elsewhere, not an actual risk here.
    probe = subprocess.run([str(py), "-c", "import playwright.sync_api"], capture_output=True, check=False)  # noqa: S603
    if probe.returncode != 0:
        print("[setup] installing playwright (one-time) ...")
        subprocess.run([str(py), "-m", "pip", "install", "--quiet", "playwright"], check=True)  # noqa: S603
        print("[setup] installing the Chromium build playwright drives (one-time download) ...")
        subprocess.run([str(py), "-m", "playwright", "install", "chromium"], check=True)  # noqa: S603

    print("[setup] ready\n")
    os.execv(str(py), [str(py), str(script_path), *argv, _BOOTSTRAP_FLAG])  # noqa: S606 -- fixed argv, not a shell command


# ---------------------------------------------------------------------------
# Recording (only ever runs inside the bootstrapped venv, above)
# ---------------------------------------------------------------------------


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


def _launch_debug_chromium(debug_port: int, user_data_dir: Path) -> subprocess.Popen:
    """Starts Playwright's OWN installed Chromium build (not a system
    `google-chrome` this script has no control over the presence of)
    with remote debugging enabled, and waits for that debug port to
    actually answer before returning -- the exact same
    `--remote-debugging-port`/`--user-data-dir` shape the STOF console's
    own "Record live" feature (and this script's own older, manual
    instructions) already document, just launched automatically instead
    of requiring the tester to type it into a second terminal."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        executable = playwright.chromium.executable_path

    user_data_dir.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen([  # noqa: S603 -- fixed argv (playwright's own resolved executable path + literal flags), never shell=True or user input
        executable,
        f"--remote-debugging-port={debug_port}",
        f"--user-data-dir={user_data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
    ])

    import urllib.error
    import urllib.request

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"http://localhost:{debug_port}/json/version", timeout=1)
            return process
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.4)
    process.terminate()
    raise SystemExit(f"Chromium started but its debug port never came up at localhost:{debug_port} within 30s.")


async def record(cdp_endpoint: str, output_path: Path, username: str | None, password: str | None) -> Path:
    from playwright.async_api import async_playwright

    async with async_playwright() as playwright:
        try:
            browser = await playwright.chromium.connect_over_cdp(cdp_endpoint)
        except Exception as exc:
            raise SystemExit(
                f"could not connect to a browser at {cdp_endpoint} -- if you passed --cdp-endpoint "
                f"yourself, start that browser first with remote debugging enabled. "
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
        # No browser.close(): whether this is the tester's own real
        # browser (--cdp-endpoint) or one this script launched itself,
        # closing it here would end the whole session out from under
        # whichever caller owns cleanup -- `main()` below handles
        # terminating a self-launched browser explicitly, after this
        # returns.

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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", required=True, help="a short name for this workflow, e.g. admin_login -- also becomes the output filename (<name>.json)")
    parser.add_argument("--output", default=None, help="override the output path (defaults to '<name>.json')")
    parser.add_argument("--cdp-endpoint", default=None, help="attach to an already-running debuggable browser instead of launching one (e.g. http://localhost:9222)")
    parser.add_argument("--debug-port", type=int, default=DEFAULT_DEBUG_PORT, help=f"port to launch the self-managed Chromium's remote debugging on (default: {DEFAULT_DEBUG_PORT}) -- ignored with --cdp-endpoint")
    parser.add_argument("--keep-browser-open", action="store_true", help="leave the browser this script launched running after recording stops (ignored with --cdp-endpoint, which never closes a browser it didn't launch)")
    parser.add_argument("--username", default=None, help="value to tokenise as {{user.username}} wherever it's typed")
    parser.add_argument("--password", default=None, help="value to tokenise as {{user.password}} wherever it's typed")
    return parser


def main() -> None:
    argv = sys.argv[1:]
    if _BOOTSTRAP_FLAG not in argv:
        _ensure_venv_and_bootstrap(argv)
        return  # os.execv() above never returns on success; this is just belt-and-suspenders

    argv = [a for a in argv if a != _BOOTSTRAP_FLAG]
    args = _build_parser().parse_args(argv)
    output_path = Path(args.output) if args.output else Path(f"{args.name}.json")

    if args.cdp_endpoint:
        asyncio.run(record(args.cdp_endpoint, output_path, args.username, args.password))
        return

    user_data_dir = Path(tempfile.gettempdir()) / "stof-chrome-debug"
    print("[record] launching a debuggable Chromium (a real, visible window should appear) ...")
    chrome_process = _launch_debug_chromium(args.debug_port, user_data_dir)
    try:
        asyncio.run(record(f"http://localhost:{args.debug_port}", output_path, args.username, args.password))
    finally:
        if args.keep_browser_open:
            print("[record] leaving the browser open (--keep-browser-open)")
        else:
            chrome_process.terminate()
            try:
                chrome_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                chrome_process.kill()
            print("[record] closed the browser this script launched")


if __name__ == "__main__":
    main()
