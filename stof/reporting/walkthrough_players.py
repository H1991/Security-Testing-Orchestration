"""Layer 13 — reproduction "players": one `async def play_<name>()` per
`walkthrough_classify.py` category, each replaying ONLY data already
recorded on the `Finding` it's given (never inventing a new payload/
probe beyond what the original technique already proved).

Rebuilt so every player performs REAL Playwright UI interactions
(`page.fill()`, `page.click()`) against the real target instead of
blind `page.goto()` navigation -- see the "Rebuild the walkthrough
report" plan. Every navigation that carries a raw payload URL-encodes
it first (`urllib.parse.quote`), which also fixes the earlier
blank-white-screenshot bug (unencoded `<`, `'`, `(` etc. broke
`page.goto()`'s URL parsing outright).

Every player is called through `walkthrough_runner.build_walkthroughs()`
wrapped in a hard `asyncio.wait_for` deadline -- the identical
external-deadline pattern `xss_tests.py`'s `_navigate_and_check_dialog`
uses (a hung `goto()` must never be able to stall report generation;
see that method's own docstring for the full rationale). A player never
catches its own timeout/exception silently -- it lets `build_walkthroughs`
do that centrally so every player's failure is handled the same way
(partial steps kept, `build_error` set, never a dropped finding).
"""
from __future__ import annotations

import contextlib
import re
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

from stof.auth.form_login import (
    GENERIC_PASSWORD_SELECTORS,
    GENERIC_SUBMIT_SELECTORS,
    GENERIC_USERNAME_SELECTORS,
)
from stof.core.logger import get_logger
from stof.engine import screenshot as screenshot_module

_log = get_logger("reporting.walkthrough_players")

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext, Page

    from stof.findings.models import Finding

    from .walkthrough_models import WalkthroughStep

_URL_RE = re.compile(r"https?://\S+")
# name=value pairs as they actually appear in this codebase's own
# `request_raw` previews (`f"{param}={payload!r}"`,
# `f"{field}={payload!r}"`, `(fields: {...})`) -- quoted or bare.
_FIELD_VALUE_RE = re.compile(r"([A-Za-z0-9_\[\].-]+)=(?:'([^']*)'|\"([^\"]*)\"|(\S+))")

_RESPONSE_EXCERPT_LEN = 300  # same truncation discipline `Finding.response_raw[:300]` already uses elsewhere
_LOAD_WAIT_MS = 5000

# Small, restrained "in-page" JS used purely to make a screenshot
# self-explanatory to a non-technical viewer -- never touches the live
# target beyond the single screenshot's DOM snapshot, never submitted
# anywhere.
_HIGHLIGHT_JS = """
(needle) => {
    if (!needle) return;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const targets = [];
    let node;
    while ((node = walker.nextNode())) {
        if (node.nodeValue && node.nodeValue.includes(needle)) targets.push(node);
    }
    for (const t of targets) {
        const idx = t.nodeValue.indexOf(needle);
        if (idx === -1) continue;
        const after = t.splitText(idx);
        after.splitText(needle.length);
        const mark = document.createElement('mark');
        mark.style.cssText = 'background:#fde047;outline:3px solid #dc2626;padding:0 2px;';
        mark.textContent = needle;
        after.parentNode.replaceChild(mark, after);
    }
}
"""

_OUTLINE_FORM_JS = """
() => {
    const form = document.querySelector('form');
    if (form) form.style.outline = '4px solid #dc2626';
}
"""

_PRETTY_JSON_JS = """
() => {
    try {
        const parsed = JSON.parse(document.body.innerText);
        const pretty = JSON.stringify(parsed, null, 2);
        document.body.innerHTML = '';
        const pre = document.createElement('pre');
        pre.style.cssText = 'background:#0f172a;color:#5eead4;padding:20px;border-radius:8px;'
            + 'font:13px/1.5 ui-monospace,monospace;white-space:pre-wrap;word-break:break-word;margin:16px;';
        pre.textContent = pretty;
        document.body.appendChild(pre);
    } catch (e) { /* not JSON -- leave the page as-is, caller falls back to the callout */ }
}
"""

_CALLOUT_JS = """
(text) => {
    const div = document.createElement('div');
    div.textContent = text;
    div.style.cssText = 'position:fixed;bottom:16px;right:16px;left:16px;max-width:520px;'
        + 'margin-left:auto;z-index:999999;background:#0f766e;color:#f0fdfa;padding:12px 16px;'
        + 'border-radius:10px;font:13px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;'
        + 'box-shadow:0 8px 24px rgba(0,0,0,.25);white-space:pre-wrap;max-height:35vh;overflow:auto;';
    document.body.appendChild(div);
}
"""


_ERROR_PAGE_SIGNATURES: tuple[str, ...] = (
    "http status 404", "http status 405", "http status 500", "method not allowed",
    "not found", "internal server error",
)


async def _looks_like_error_page(page: "Page") -> bool:
    """Best-effort: a POST-only action URL GET-navigated often lands on
    a framework error page (Tomcat's own "HTTP Status 405" page, a
    generic 404, ...) rather than any real content -- checked via a
    small title/body signature match so a caller can fall back to an
    honest synthetic preview instead of screenshotting a raw error page
    as if it were the real form."""
    try:
        title = ((await page.title()) or "").lower()
        body_text = ((await page.locator("body").inner_text()) or "")[:500].lower()
    except Exception:
        return False
    haystack = f"{title} {body_text}"
    return any(sig in haystack for sig in _ERROR_PAGE_SIGNATURES)


def _first_url(text: str, fallback: str) -> str:
    match = _URL_RE.search(text or "")
    return match.group(0).rstrip(")]},") if match else fallback


def _first_field_value(text: str) -> tuple[str, str] | None:
    """The first `name=value` pair found in a `request_raw` preview --
    the exact field name/payload the original technique already used,
    never a newly invented one."""
    match = _FIELD_VALUE_RE.search(text or "")
    if match is None:
        return None
    name = match.group(1)
    value = next((g for g in match.groups()[1:] if g is not None), "")
    return name, value


async def _shot(page: "Page", screenshot_dir: Path, finding_id: str, n: int, label: str) -> str | None:
    directory = screenshot_dir / finding_id
    try:
        path = await screenshot_module.capture(page, output_dir=directory, label=f"step_{n}_{label}")
        return str(path)
    except Exception:
        return None


def _step(order: int, caption: str, screenshot_path: str | None = None, detail: str | None = None) -> "WalkthroughStep":
    from .walkthrough_models import WalkthroughStep

    return WalkthroughStep(order=order, caption=caption, screenshot_path=screenshot_path, detail=detail)


async def _settle(page: "Page") -> None:
    """Best-effort wait for a page to finish loading after a
    goto()/click()-triggered navigation -- never fatal, a page that
    never reaches 'load' (background polling, etc.) shouldn't block a
    screenshot."""
    with contextlib.suppress(Exception):
        await page.wait_for_load_state("load", timeout=_LOAD_WAIT_MS)


async def _resolve_selector(page: "Page", candidates: list[str]) -> str | None:
    """First selector in `candidates` that actually matches an element
    on the current page, or None if none do -- mirrors `stof.auth.
    form_login._first_matching()`'s probing but never raises, since a
    walkthrough replay degrades gracefully instead of failing the
    whole step."""
    for candidate in candidates:
        try:
            if await page.locator(candidate).count() > 0:
                return candidate
        except Exception:  # noqa: S112 -- best-effort selector probing, same pattern as form_login._first_matching
            continue
    return None


async def _resolve_selector_pref(page: "Page", configured: "str | list[str] | None", fallback: list[str]) -> str | None:
    """Same probing as `_resolve_selector`, but tries the REAL,
    configured selector(s) (`config.target.username_selector` etc.,
    threaded down from `main.py`) first, only falling back to the
    generic `GENERIC_*_SELECTORS` guess-list when no configured value
    is given or it doesn't match anything on this page. Mirrors
    `walkthrough_runner._resolve()`'s exact same preference order --
    duplicated locally (not imported) since that function isn't
    exported for cross-module reuse and this is a two-line probe, not
    worth adding a shared-helper module for."""
    configured_candidates = [configured] if isinstance(configured, str) else (configured or [])
    for candidate in [*configured_candidates, *fallback]:
        try:
            if await page.locator(candidate).count() > 0:
                return candidate
        except Exception:  # noqa: S112 -- best-effort selector probing
            continue
    return None


async def _highlight_text(page: "Page", needle: str) -> None:
    if not needle:
        return
    with contextlib.suppress(Exception):
        await page.evaluate(_HIGHLIGHT_JS, needle)


async def play_login_form_injection(page, context, finding: "Finding", role, session_manager, session_pool, screenshot_dir: Path,
    login_url: str = "", username_selector=None, password_selector=None, submit_selector=None,
) -> list["WalkthroughStep"]:
    """TC-127.4-shaped: SQL injection used to bypass a login form.
    Really types the exact field/payload already recorded on `finding.
    request_raw` into the target's real login form and clicks submit
    -- two genuinely different screenshots (payload visibly sitting in
    the field, then the resulting authenticated page), not a blind
    goto()."""
    steps: list["WalkthroughStep"] = []
    # The real, configured login PAGE (config.target.login_url) is
    # always preferred -- `finding.request_raw`/`endpoint.url` for this
    # technique is the form's POST ACTION url (e.g. /doLogin), not a
    # page a GET can render; navigating there directly redirects to the
    # marketing homepage, where the only `input[type=text]` on the page
    # is the site search box -- the generic selector fallback would
    # then (silently, wrongly) "resolve" to that instead of a real
    # username field. Only fall back to the finding's own URL when no
    # real login_url was threaded through at all.
    real_login_url = login_url or _first_url(finding.request_raw, finding.endpoint.url)
    field_value = _first_field_value(finding.request_raw)

    await page.goto(real_login_url, timeout=15000)
    await _settle(page)

    username_sel = await _resolve_selector_pref(page, username_selector, GENERIC_USERNAME_SELECTORS)
    password_sel = await _resolve_selector_pref(page, password_selector, GENERIC_PASSWORD_SELECTORS)
    submit_sel = await _resolve_selector_pref(page, submit_selector, GENERIC_SUBMIT_SELECTORS)

    if field_value is not None and username_sel is not None:
        field, payload = field_value
        with contextlib.suppress(Exception):
            await page.fill(username_sel, payload)
        if password_sel is not None:
            with contextlib.suppress(Exception):
                await page.fill(password_sel, "wrong-password")
        steps.append(_step(
            1, f"Type the SQL injection payload into the login form's '{field}' field",
            await _shot(page, screenshot_dir, finding.finding_id, 1, "payload_entered"),
            detail=f"{field} = {payload}",
        ))
        if submit_sel is not None:
            with contextlib.suppress(Exception):
                await page.click(submit_sel)
            await _settle(page)
        steps.append(_step(
            2, "Submit the login form with the injection payload still sitting in the username field",
            await _shot(page, screenshot_dir, finding.finding_id, 2, "submitted"),
        ))
    else:
        steps.append(_step(1, f"Open the login page at {real_login_url}", await _shot(page, screenshot_dir, finding.finding_id, 1, "login_page")))
        steps.append(_step(2, "Submit the SQL injection payload recorded for this finding", detail=finding.request_raw[:_RESPONSE_EXCERPT_LEN]))

    steps.append(_step(
        3, "The application authenticates the attacker without a valid password -- the login bypass succeeds",
        detail=(finding.response_raw or "")[:_RESPONSE_EXCERPT_LEN] or None,
    ))
    return steps


async def _play_reflected_payload(page, finding: "Finding", screenshot_dir: Path, nav_caption: str, exec_caption: str) -> list["WalkthroughStep"]:
    """Shared by `play_url_reflection`/`play_dom_execution` -- both are
    "navigate to a URL carrying a payload, observe either a real
    dialog or the payload rendered live in the DOM" replays, differing
    only in caption wording. URL-encodes the payload before building
    the probe URL (fixes the blank-screenshot bug: literal `<`, `'`,
    `(` broke `page.goto()`'s own URL parsing) and registers a dialog
    handler so a payload that pops a real `alert()`/`confirm()` is
    captured rather than silently blocking navigation."""
    steps: list["WalkthroughStep"] = []
    field_value = _first_field_value(finding.request_raw)
    raw_base_url = _first_url(finding.request_raw, finding.endpoint.url)
    # `_first_url` can itself capture a URL with an unencoded payload
    # already embedded in it (e.g. a DOM-XSS fragment like
    # "#<svg onload=...>") -- encode the whole base URL too, not just a
    # separately-matched param/payload pair, keeping URL-structural
    # characters (`:/?&#=`) unescaped so it still parses as a URL.
    base_url = quote(raw_base_url, safe=":/?&#=")
    captured_dialogs: list[str] = []

    async def _on_dialog(dialog) -> None:
        captured_dialogs.append(dialog.message)
        with contextlib.suppress(Exception):
            await dialog.dismiss()

    page.on("dialog", _on_dialog)

    if field_value is not None:
        param, payload = field_value
        sep = "&" if "?" in base_url else "?"
        probe_url = f"{base_url}{sep}{param}={quote(payload, safe='')}"
    else:
        probe_url = base_url

    await page.goto(probe_url, timeout=15000)
    await _settle(page)

    if field_value is not None and not captured_dialogs:
        await _highlight_text(page, field_value[1])

    shot = await _shot(page, screenshot_dir, finding.finding_id, 1, "payload_delivered")
    steps.append(_step(1, nav_caption.format(url=probe_url), shot))

    if captured_dialogs:
        steps.append(_step(
            2, "The injected script executes immediately, triggering a real JavaScript dialog in the browser (auto-dismissed for this evidence capture)",
            detail=captured_dialogs[0],
        ))
    else:
        steps.append(_step(2, exec_caption, detail=(finding.response_raw or "")[:_RESPONSE_EXCERPT_LEN] or None))
    return steps


async def play_url_reflection(page, context, finding: "Finding", role, session_manager, session_pool, screenshot_dir: Path,
    login_url: str = "", username_selector=None, password_selector=None, submit_selector=None,
) -> list["WalkthroughStep"]:
    """TC-128.1/.2/.3-shaped: reflected XSS."""
    return await _play_reflected_payload(
        page, finding, screenshot_dir,
        nav_caption="Visit {url} -- the malicious parameter is now part of a real, browser-encoded URL, exactly as an attacker-sent link would look",
        exec_caption="The payload is reflected back into the page unescaped (highlighted above) -- a real browser renders it as live markup/script",
    )


async def play_dom_execution(page, context, finding: "Finding", role, session_manager, session_pool, screenshot_dir: Path,
    login_url: str = "", username_selector=None, password_selector=None, submit_selector=None,
) -> list["WalkthroughStep"]:
    """TC-128.5-shaped: DOM XSS."""
    return await _play_reflected_payload(
        page, finding, screenshot_dir,
        nav_caption="Visit {url} -- the vulnerable page reads this URL directly into the DOM with no sanitization",
        exec_caption="The page rendered the payload directly into the DOM (highlighted above) with no sanitization",
    )


async def play_stored_plant_and_view(page, context, finding: "Finding", role, session_manager, session_pool, screenshot_dir: Path,
    login_url: str = "", username_selector=None, password_selector=None, submit_selector=None,
) -> list["WalkthroughStep"]:
    """TC-128.4/second-order-shaped: two-step plant-then-view, planting
    via a real `page.fill()` + `page.click()` on the actual form
    instead of a bare GET navigation."""
    steps: list["WalkthroughStep"] = []
    text = finding.request_raw or ""
    plant_match = re.search(r"PLANT:\s*(\S+)\s+(https?://\S+)", text)
    verify_match = re.search(r"VERIFY:\s*(\S+)\s+(https?://\S+)", text)
    field_value = _first_field_value(text)

    if plant_match is not None:
        plant_url = plant_match.group(2)
        await page.goto(plant_url, timeout=15000)
        await _settle(page)

        filled = False
        field = payload = None
        if field_value is not None:
            field, payload = field_value
            field_sel = f"[name='{field}']"
            with contextlib.suppress(Exception):
                if await page.locator(field_sel).count() > 0:
                    await page.fill(field_sel, payload)
                    filled = True

        if filled:
            steps.append(_step(
                1, f"On {plant_url}, type the payload into the real '{field}' field",
                await _shot(page, screenshot_dir, finding.finding_id, 1, "plant_filled"),
                detail=f"{field} = {payload}",
            ))
            submit_sel = await _resolve_selector(page, GENERIC_SUBMIT_SELECTORS)
            if submit_sel is not None:
                with contextlib.suppress(Exception):
                    await page.click(submit_sel)
            else:
                with contextlib.suppress(Exception):
                    await page.locator(f"[name='{field}']").press("Enter")
            await _settle(page)
            steps.append(_step(2, "Submit the form -- the payload is now stored server-side", await _shot(page, screenshot_dir, finding.finding_id, 2, "plant_submitted")))
        else:
            steps.append(_step(1, f"Submit the malicious value through the form at {plant_url} (plant step)", await _shot(page, screenshot_dir, finding.finding_id, 1, "plant")))
    else:
        steps.append(_step(1, "The malicious value was planted via a form submission recorded for this finding", detail=text[:_RESPONSE_EXCERPT_LEN] or None))

    verify_url = verify_match.group(2) if verify_match is not None else finding.endpoint.url
    await page.goto(verify_url, timeout=15000)
    await _settle(page)
    n = len(steps) + 1
    steps.append(_step(n, f"Later, view {verify_url} as a different, higher-privileged user (view step)", await _shot(page, screenshot_dir, finding.finding_id, n, "view")))
    steps.append(_step(
        n + 1, "The previously planted value renders unescaped on this page -- the stored payload executes for the victim",
        detail=(finding.response_raw or "")[:_RESPONSE_EXCERPT_LEN] or None,
    ))
    return steps


async def play_session_after_logout(page, context: "BrowserContext", finding: "Finding", role, session_manager, session_pool, screenshot_dir: Path,
    login_url: str = "", username_selector=None, password_selector=None, submit_selector=None,
) -> list["WalkthroughStep"]:
    """TC-129.2: real 3-shot sequence -- (1) genuinely logged in,
    (2) click a real logout control, (3) manually re-apply the
    pre-logout cookie jar to a fresh, independent context and prove
    the old session still works."""
    steps: list["WalkthroughStep"] = []
    target_url = finding.endpoint.url

    await page.goto(target_url, timeout=15000)
    await _settle(page)
    pre_logout_cookies: list[dict] = []
    with contextlib.suppress(Exception):
        pre_logout_cookies = await context.cookies()
    steps.append(_step(1, f"While genuinely logged in, view the protected page at {target_url}", await _shot(page, screenshot_dir, finding.finding_id, 1, "logged_in")))

    logout_url = _first_url(finding.request_raw, "")
    logout_sel = await _resolve_selector(page, [
        "a:has-text('Logout')", "a:has-text('Log out')", "a:has-text('Sign out')", "[href*='logout']",
    ])
    if logout_sel is not None:
        with contextlib.suppress(Exception):
            await page.click(logout_sel)
    elif logout_url and logout_url != target_url:
        with contextlib.suppress(Exception):
            await page.goto(logout_url, timeout=15000)
    await _settle(page)
    steps.append(_step(2, "Log out of the application through the real logout control", await _shot(page, screenshot_dir, finding.finding_id, 2, "logged_out")))

    shot3 = None
    cookie_reuse_error: str | None = None
    reused_session_looks_authenticated = False
    replay_context = None
    try:
        replay_context = await session_pool.new_anonymous_context()
        if pre_logout_cookies:
            try:
                await replay_context.add_cookies(_sanitize_cookies_for_reuse(pre_logout_cookies))
            except Exception as exc:
                # Previously silently swallowed (`contextlib.suppress`),
                # which made a genuine cookie-reuse failure look
                # identical to "the app correctly invalidated the
                # session" in the resulting screenshot -- log it and
                # surface it in the step's own detail instead.
                cookie_reuse_error = str(exc)
                _log.warning(f"session_after_logout cookie reuse failed for finding {finding.finding_id}: {exc}")
        replay_page = await replay_context.new_page()
        await replay_page.goto(target_url, timeout=15000)
        await _settle(replay_page)
        shot3 = await _shot(replay_page, screenshot_dir, finding.finding_id, 3, "session_reused")
        reused_session_looks_authenticated = await _looks_authenticated(replay_page)
        with contextlib.suppress(Exception):
            await replay_page.close()
    finally:
        if replay_context is not None:
            with contextlib.suppress(Exception):
                await replay_context.close()

    if cookie_reuse_error is not None:
        steps.append(_step(
            3, "Could not re-apply the pre-logout session cookie to a fresh browser context for this replay "
               "-- see the original scan evidence for the verified finding",
            shot3, detail=cookie_reuse_error,
        ))
    elif not reused_session_looks_authenticated:
        steps.append(_step(
            3, "This replay's reused-cookie request did not visually reproduce the authenticated state "
               "-- see the original scan evidence for the verified finding (a raw HTTP replay, not a browser "
               "render, is what actually confirmed this vulnerability)",
            shot3,
        ))
    else:
        steps.append(_step(3, "Manually re-apply the SAME session cookie captured before logout and request the page again -- the application still serves it", shot3))
    return steps


_AUTHENTICATED_MARKERS: tuple[str, ...] = ("sign off", "my account", "log out", "logout")


async def _looks_authenticated(page: "Page") -> bool:
    """Same spirit as `play_authenticated_navigation`'s honesty check --
    a cheap, best-effort signal (not a security verdict) so this player
    never presents an anonymous-looking page as if it proved session
    reuse succeeded."""
    try:
        body_text = ((await page.locator("body").inner_text()) or "")[:1000].lower()
    except Exception:
        return True  # can't tell either way -- don't manufacture a false negative
    return any(marker in body_text for marker in _AUTHENTICATED_MARKERS)


def _sanitize_cookies_for_reuse(cookies: list[dict]) -> list[dict]:
    """`BrowserContext.cookies()`'s output can include fields a given
    Playwright version's `add_cookies()` doesn't accept back (this has
    been the actual, previously-silent cause of a cookie-reuse step
    rendering as anonymous -- `add_cookies()` raising and the whole
    step being swallowed). Keeps only the fields `add_cookies()` is
    documented to accept."""
    allowed_keys = {"name", "value", "domain", "path", "expires", "httpOnly", "secure", "sameSite", "url"}
    return [{k: v for k, v in c.items() if k in allowed_keys} for c in cookies]


async def play_no_rate_limit(page, context, finding: "Finding", role, session_manager, session_pool, screenshot_dir: Path,
    login_url: str = "", username_selector=None, password_selector=None, submit_selector=None,
) -> list["WalkthroughStep"]:
    """TC-129.3: a real sequence of repeated fill+submit wrong-password
    attempts against the actual login form."""
    steps: list["WalkthroughStep"] = []
    # Same "prefer the real configured login PAGE over the finding's
    # own POST-action URL" fix as play_login_form_injection -- see that
    # function's comment for the full failure mode this avoids.
    target_url = login_url or _first_url(finding.request_raw, finding.endpoint.url)
    attempts_match = re.search(r"(\d+)x", finding.request_raw or "")
    attempts = max(2, min(int(attempts_match.group(1)) if attempts_match else 3, 5))

    await page.goto(target_url, timeout=15000)
    await _settle(page)
    username_sel = await _resolve_selector_pref(page, username_selector, GENERIC_USERNAME_SELECTORS)
    password_sel = await _resolve_selector_pref(page, password_selector, GENERIC_PASSWORD_SELECTORS)
    submit_sel = await _resolve_selector_pref(page, submit_selector, GENERIC_SUBMIT_SELECTORS)

    first_shot = None
    last_shot = None
    for i in range(1, attempts + 1):
        if username_sel is not None:
            with contextlib.suppress(Exception):
                await page.fill(username_sel, "admin")
        if password_sel is not None:
            with contextlib.suppress(Exception):
                await page.fill(password_sel, f"wrong-password-{i}")
        if submit_sel is not None:
            with contextlib.suppress(Exception):
                await page.click(submit_sel)
            await _settle(page)
        if i == 1:
            first_shot = await _shot(page, screenshot_dir, finding.finding_id, 1, "attempt_1")
        if i == attempts:
            last_shot = await _shot(page, screenshot_dir, finding.finding_id, 2, f"attempt_{attempts}")

    steps.append(_step(1, f"Attempt #1: submit the login form at {target_url} with a wrong password", first_shot))
    steps.append(_step(
        2, f"Attempt #{attempts}: submit another wrong password -- still the same login form, no lockout after {attempts} failed attempts",
        last_shot, detail=(finding.response_raw or "")[:_RESPONSE_EXCERPT_LEN] or None,
    ))
    return steps


async def play_csrf_no_token(page, context, finding: "Finding", role, session_manager, session_pool, screenshot_dir: Path,
    login_url: str = "", username_selector=None, password_selector=None, submit_selector=None,
) -> list["WalkthroughStep"]:
    """TC-130.1/.3-shaped: screenshots the real target form (outlined
    to show no anti-CSRF token field exists), then builds and navigates
    to a minimal local `data:` URL auto-submitting PoC page -- the same
    shape PortSwigger's own "Copy CSRF PoC" feature generates -- reusing
    the exact field/method data already recorded on the finding."""
    steps: list["WalkthroughStep"] = []
    target_url = _first_url(finding.request_raw, finding.endpoint.url)
    field_value = _first_field_value(finding.request_raw)
    fields_match = re.search(r"fields:\s*\[([^\]]*)\]", finding.request_raw or "")
    method_match = re.search(r"^(GET|POST|PUT|DELETE|PATCH)\s", finding.request_raw or "")
    method = method_match.group(1) if method_match else "POST"

    field_names: list[str] = []
    if fields_match:
        field_names = [f.strip().strip("'\"") for f in fields_match.group(1).split(",") if f.strip()]
    elif field_value is not None:
        field_names = [field_value[0]]
    if not field_names:
        field_names = ["value"]

    # `target_url` is the form's POST ACTION endpoint (what the finding
    # recorded) -- a GET against it often isn't the page a real user
    # would see (many apps 404/405 a GET on a POST-only action), so
    # this is a best-effort "does a real, renderable form actually live
    # here" probe, not an assumption. Falls back to a clearly-labeled
    # synthetic preview (built ONLY from field names already recorded
    # on the finding, never fabricated) rather than showing a raw
    # framework error page as if it were evidence.
    await page.goto(target_url, timeout=15000)
    await _settle(page)
    page_looks_like_error = await _looks_like_error_page(page)
    if page_looks_like_error:
        preview_inputs = "".join(f"<label>{name}: <input readonly value=''></label><br>" for name in field_names)
        with contextlib.suppress(Exception):
            await page.set_content(
                f"<html><body style='font:14px -apple-system,Segoe UI,Roboto,sans-serif;padding:24px'>"
                f"<p><strong>Reconstructed field preview</strong> (the live {method} target at {target_url} "
                f"doesn't render as a page for a direct GET, so this shows only the fields already recorded "
                f"for this finding -- not a live screenshot of the target):</p>{preview_inputs}"
                f"<p style='color:#dc2626'>No anti-CSRF token field is present among them.</p></body></html>"
            )
        steps.append(_step(
            1, f"'{target_url}' doesn't render as a page for a direct visit -- here are the fields this form actually submits (no anti-CSRF token among them)",
            await _shot(page, screenshot_dir, finding.finding_id, 1, "csrf_fields_reconstructed"),
        ))
    else:
        with contextlib.suppress(Exception):
            await page.evaluate(_OUTLINE_FORM_JS)
        steps.append(_step(
            1, f"View the real form at {target_url} -- no hidden anti-CSRF token field exists anywhere in it (outlined above)",
            await _shot(page, screenshot_dir, finding.finding_id, 1, "csrf_target"),
        ))

    poc_inputs = "".join(f"<input type='hidden' name='{name}' value='attacker-controlled'>" for name in field_names)
    poc_html = (
        f"<html><body onload='document.forms[0].submit()'>"
        f"<form action='{target_url}' method='{method}'>{poc_inputs}</form>"
        f"<p>Loading...</p></body></html>"
    )
    poc_url = "data:text/html," + quote(poc_html, safe="")

    with contextlib.suppress(Exception):
        await page.goto(poc_url, timeout=10000)
    await _settle(page)
    steps.append(_step(
        2, "Load a minimal attacker-hosted page that auto-submits this SAME request while the victim is already logged in",
        await _shot(page, screenshot_dir, finding.finding_id, 2, "csrf_poc_autosubmit"),
        detail=f"{method} {target_url} -- fields: {field_names}",
    ))
    steps.append(_step(3, "The application accepts the forged request with no valid anti-CSRF token check", detail=(finding.response_raw or "")[:_RESPONSE_EXCERPT_LEN] or None))
    return steps


async def play_authenticated_navigation(page, context, finding: "Finding", role, session_manager, session_pool, screenshot_dir: Path,
    login_url: str = "", username_selector=None, password_selector=None, submit_selector=None,
) -> list["WalkthroughStep"]:
    """Generic fallback #1 -- IDOR/BFLA/method-override/forced-browsing
    -shaped: request `finding.endpoint.url` directly using the fresh,
    isolated per-role login context the runner now provides (no longer
    the live scan's own, possibly-polluted shared context). Honesty
    check: if the browser unexpectedly lands on what looks like the
    login page, the caption says the replay could not reproduce the
    authenticated state rather than presenting a misleading screenshot
    as proof."""
    steps: list["WalkthroughStep"] = []
    target_url = finding.endpoint.url
    await page.goto(target_url, timeout=15000)
    await _settle(page)

    current_url = getattr(page, "url", target_url) or target_url
    looks_like_login = "login" in current_url.lower() and "login" not in target_url.lower()
    shot = await _shot(page, screenshot_dir, finding.finding_id, 1, "accessed")

    if looks_like_login:
        steps.append(_step(1, f"As user role '{finding.user_role}', request {target_url} directly", shot))
        steps.append(_step(
            2, "This replay could not reproduce the authenticated state live (the browser landed on a login page) -- "
               "see the original scan evidence for the verified finding",
        ))
        return steps

    steps.append(_step(1, f"As user role '{finding.user_role}', request {target_url} directly", shot))
    steps.append(_step(
        2, "The application returns the resource without properly checking this user's authorization to view/modify it",
        detail=(finding.response_raw or "")[:_RESPONSE_EXCERPT_LEN] or None,
    ))
    return steps


async def play_annotated_evidence(page, context, finding: "Finding", role, session_manager, session_pool, screenshot_dir: Path,
    login_url: str = "", username_selector=None, password_selector=None, submit_selector=None,
) -> list["WalkthroughStep"]:
    """Generic fallback #2, the true catch-all: navigate to
    `finding.endpoint.url`. A JSON/API response is pretty-printed via
    `page.evaluate()` into a styled `<pre>`; any other page gets a
    small, rounded, teal-accent callout instead of the earlier harsh
    full-width red bar."""
    steps: list["WalkthroughStep"] = []
    target_url = finding.endpoint.url
    await page.goto(target_url, timeout=15000)
    await _settle(page)

    excerpt = (finding.response_raw or finding.description or "")[:_RESPONSE_EXCERPT_LEN]
    looks_json = excerpt.strip().startswith(("{", "["))

    if looks_json:
        with contextlib.suppress(Exception):
            await page.evaluate(_PRETTY_JSON_JS)
        caption = f"Visit {target_url} -- the API response, pretty-printed, exposes the finding directly"
    else:
        with contextlib.suppress(Exception):
            await page.evaluate(_CALLOUT_JS, excerpt)
        caption = f"Visit {target_url} -- the finding is visible in what the page exposes here"

    steps.append(_step(1, caption, await _shot(page, screenshot_dir, finding.finding_id, 1, "annotated"), detail=excerpt or None))
    return steps


PLAYERS = {
    "login_form_injection": play_login_form_injection,
    "url_reflection": play_url_reflection,
    "dom_execution": play_dom_execution,
    "stored_plant_and_view": play_stored_plant_and_view,
    "session_after_logout": play_session_after_logout,
    "no_rate_limit": play_no_rate_limit,
    "csrf_no_token": play_csrf_no_token,
    "authenticated_navigation": play_authenticated_navigation,
    "annotated_evidence": play_annotated_evidence,
}
