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
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
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
    // A <select> needs Playwright's `select_option()`, not `fill()` --
    // `fill()` only ever works on a text-enterable INPUT/TEXTAREA and
    // hangs until its own timeout on anything else (confirmed live: a
    // recorded dropdown pick made every later replay of that workflow
    // time out on that one step, never actually failing the *element*,
    // just waiting forever for it to become "fillable").
    window.{_BINDING_NAME}({{
      type: tag === 'SELECT' ? 'select' : 'fill',
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


# Internal browser pages a fresh (or mid-navigation) Chromium can sit on
# that were never a real step the tester took -- a brand-new tab starts
# on "chrome://new-tab-page/", not "about:blank", so excluding only
# "about:blank" (the old check) let that internal URL slip through as a
# spurious first `navigate` action. Replaying it later fails outright:
# browsers refuse a `Page.goto()` to their own internal chrome:// pages
# under automation (net::ERR_ABORTED, landing on
# chrome-error://chromewebdata/) -- confirmed live, this was corrupting
# every fresh recording's first step.
_INTERNAL_URL_PREFIXES = ("chrome://", "chrome-error://", "chrome-extension://", "devtools://", "edge://", "about:")


def _is_recordable_url(url: str) -> bool:
    return bool(url) and not url.startswith(_INTERNAL_URL_PREFIXES)


class EventHandler:
    def __init__(self) -> None:
        self.actions: list[dict[str, Any]] = []
        self._page = None

    async def attach(self, page) -> None:
        self._page = page
        await page.expose_binding(_BINDING_NAME, self._on_browser_event)
        await page.add_init_script(_CAPTURE_SCRIPT)
        page.on("framenavigated", self._on_navigated)
        if _is_recordable_url(page.url):
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
        elif event.get("type") in ("fill", "select"):
            self.actions.append({
                "type": event["type"], "selector": event["selector"],
                "value": event.get("value", ""), "field_type": event.get("field_type", ""),
            })

    def _on_navigated(self, frame) -> None:
        if self._page is not None and frame == self._page.main_frame:
            self._record_navigate(frame.url)

    def _record_navigate(self, url: str) -> None:
        if not _is_recordable_url(url):
            return
        if self.actions and self.actions[-1] == {"type": "navigate", "url": url}:
            return
        self.actions.append({"type": "navigate", "url": url})


def _read_line_in_daemon_thread(loop: asyncio.AbstractEventLoop, prompt: str) -> asyncio.Future:
    """Like `loop.run_in_executor(None, input, prompt)`, but on a thread
    that can never block `asyncio.run()`'s shutdown or interpreter exit
    -- see the call site in `record()` for why that distinction matters
    here specifically."""
    future: asyncio.Future = loop.create_future()

    def worker() -> None:
        try:
            line = input(prompt)
        except EOFError:
            line = ""
        if not future.cancelled():
            loop.call_soon_threadsafe(future.set_result, line)

    threading.Thread(target=worker, daemon=True).start()
    return future


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


async def record(cdp_endpoint: str, output_path: Path, username: str | None, password: str | None) -> tuple[Path, bool]:
    """Returns (output_path, browser_closed_early) -- the caller (`main`)
    needs browser_closed_early to know whether it must hard-exit after
    its own cleanup runs (see the comment on that flag below)."""
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

        # Closing the browser window is a normal way to end a recording,
        # not just pressing Enter in the terminal -- the tester's flow
        # often IS "finish, then close the window". Without watching for
        # `disconnected`, closing the window instead of pressing Enter
        # left `input()` blocked forever with nothing ever saved (the
        # bug reported live: actions were captured in `handler.actions`
        # the whole time, but the script never reached the code that
        # writes them out).
        loop = asyncio.get_event_loop()
        disconnected: asyncio.Future[None] = loop.create_future()
        browser.once("disconnected", lambda: not disconnected.done() and disconnected.set_result(None))

        # Deliberately NOT `loop.run_in_executor(None, input, ...)`: that
        # submits to the loop's DEFAULT executor, and `asyncio.run()`
        # unconditionally waits for that executor to fully shut down
        # before it returns -- which hangs forever here, since the
        # `input()` call this thread is stuck on never gets data or EOF
        # when the browser closes early instead of Enter being pressed
        # (confirmed live: the file saves correctly, but the whole
        # process then hangs indefinitely on process exit). A `daemon`
        # thread we manage ourselves is invisible to that shutdown wait
        # and is killed automatically at interpreter exit either way.
        input_future = _read_line_in_daemon_thread(
            loop, "Recording... walk through the workflow, then press Enter here to stop "
            "(or just close the browser window).\n"
        )
        done, _pending = await asyncio.wait({input_future, disconnected}, return_when=asyncio.FIRST_COMPLETED)

        browser_closed_early = disconnected in done and input_future not in done
        target_url = None
        if browser_closed_early:
            print("\n[record] browser window closed -- stopping and saving what was captured so far.")
            # page.url is a cached client-side property, not a live round
            # trip -- safe to read even after the underlying connection
            # dropped. Still guarded: fall back to the last recorded
            # navigation rather than lose the whole recording over one
            # unreadable property on a fully torn-down connection.
            with contextlib.suppress(Exception):
                target_url = page.url
        else:
            await handler.detach()
            target_url = page.url
        if not _is_recordable_url(target_url):
            target_url = next((a["url"] for a in reversed(handler.actions) if a["type"] == "navigate"), "")
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
    # If the browser closed early, the `input()` executor thread from
    # above is still blocked reading stdin (no clean, cross-platform way
    # to interrupt a blocking read from here) -- left alone, the
    # interpreter would hang on process exit waiting to join it, right
    # back to the "looks stuck" symptom this whole branch exists to
    # avoid. `main()` runs its own cleanup first, then hard-exits.
    return output_path, browser_closed_early


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", required=True, help="a short name for this workflow, e.g. admin_login -- also becomes the output filename (<name>.json)")
    parser.add_argument("--output", default=None, help="override the output path (defaults to '<name>.json')")
    parser.add_argument("--cdp-endpoint", default=None, help="attach to an already-running debuggable browser instead of launching one (e.g. http://localhost:9222)")
    parser.add_argument("--debug-port", type=int, default=DEFAULT_DEBUG_PORT, help=f"port to launch the self-managed Chromium's remote debugging on (default: {DEFAULT_DEBUG_PORT}) -- ignored with --cdp-endpoint")
    parser.add_argument("--keep-browser-open", action="store_true", help="leave the browser this script launched running after recording stops (ignored with --cdp-endpoint, which never closes a browser it didn't launch)")
    parser.add_argument("--username", default=None, help="value to tokenise as {{user.username}} wherever it's typed")
    parser.add_argument("--password", default=None, help="value to tokenise as {{user.password}} wherever it's typed")
    parser.add_argument(
        "--purge-env", action="store_true",
        help="delete this script's own virtual environment (.stof_recorder_env) after the workflow is "
        "saved, leaving no trace on this machine -- the next run pays the one-time setup cost again",
    )
    return parser


def _cleanup_after_recording(venv_dir: Path, *, purge_env: bool) -> None:
    if purge_env and venv_dir.exists():
        shutil.rmtree(venv_dir, ignore_errors=True)
        print(f"[cleanup] removed {venv_dir}")


def _exit_if_browser_closed_early(browser_closed_early: bool) -> None:
    if browser_closed_early:
        sys.stdout.flush()
        os._exit(0)


def main() -> None:
    argv = sys.argv[1:]
    if _BOOTSTRAP_FLAG not in argv:
        _ensure_venv_and_bootstrap(argv)
        return  # os.execv() above never returns on success; this is just belt-and-suspenders

    argv = [a for a in argv if a != _BOOTSTRAP_FLAG]
    args = _build_parser().parse_args(argv)
    output_path = Path(args.output) if args.output else Path(f"{args.name}.json")
    venv_dir = Path(__file__).resolve().parent / _VENV_DIR_NAME

    if args.cdp_endpoint:
        _, browser_closed_early = asyncio.run(record(args.cdp_endpoint, output_path, args.username, args.password))
        _cleanup_after_recording(venv_dir, purge_env=args.purge_env)
        _exit_if_browser_closed_early(browser_closed_early)
        return

    user_data_dir = Path(tempfile.gettempdir()) / "stof-chrome-debug"
    print("[record] launching a debuggable Chromium (a real, visible window should appear) ...")
    chrome_process = _launch_debug_chromium(args.debug_port, user_data_dir)
    browser_closed_early = False
    try:
        _, browser_closed_early = asyncio.run(
            record(f"http://localhost:{args.debug_port}", output_path, args.username, args.password)
        )
    finally:
        if args.keep_browser_open:
            print("[record] leaving the browser open (--keep-browser-open)")
        else:
            # A no-op if the tester already closed the window themselves
            # (browser_closed_early) -- terminate()/wait() on an already-
            # exited process just return immediately.
            chrome_process.terminate()
            try:
                chrome_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                chrome_process.kill()
            print("[record] closed the browser this script launched")
            shutil.rmtree(user_data_dir, ignore_errors=True)
    _cleanup_after_recording(venv_dir, purge_env=args.purge_env)
    _exit_if_browser_closed_early(browser_closed_early)


if __name__ == "__main__":
    main()
