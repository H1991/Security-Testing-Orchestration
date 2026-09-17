"""Layer 7 — BFS crawl via Playwright (authenticated).

After authentication, maps the target's attack surface. Runs as its own
phase before any vulnerability modules (Layer 9) execute.

Deviation from CLAUDE.md, done at explicit user instruction: CLAUDE.md
states twice that the crawler is "passive discovery only" and "does not
send attack payloads." `CrawlerConfig.submit_forms_with_test_data`
(on by default, also at explicit user instruction) fills every
discovered POST form with clearly-tagged placeholder data
(`stof-test-...`) and submits it, to prove the endpoint is real and see
what it does -- e.g. `doTransfer` on this project's demo target really
does attempt a transfer. That is active testing, not passive discovery.
Still a per-`CrawlerConfig` override, not hardcoded True: pass
`submit_forms_with_test_data=False` for a target/engagement where blind
form submission would have real consequences you don't want.

Same deviation, same reasoning, for `CrawlerConfig.explore_clickable_navigation`
(also on by default): many modern SPAs (confirmed live against Juice
Shop, a stock Angular app) put their whole nav behind `<button>`/icon
elements with `routerLink`/`onclick`, not `<a href>` -- a login or
search route that's only reachable by clicking one of these is
completely invisible to link-only crawling, no matter how well hash-
routes are followed. `_discover_clickable_routes()` clicks these on a
dedicated probe page (never the main BFS page) and records where the
click actually navigated to, skipping anything whose visible text
looks destructive (delete/buy/logout/etc. -- see `_DANGER_CLICK_TEXT`).
Pass `explore_clickable_navigation=False` to opt back out.

Signature note: CLAUDE.md shows `crawl(start_url, session, config)`.
This takes an already-authenticated `BrowserContext` instead of a raw
`Session` -- "uses the authenticated browser context from the session
manager" describes a Playwright `BrowserContext`, and turning a
`Session` into one is `engine.multi_session.SessionPool.apply_session()`'s
job (Layer 3B), not something this module should reach into `stof.engine`
to do itself. The caller (eventually the orchestrator) is expected to
call `pool.apply_session(session, start_url)` and hand the resulting
context in here -- the same dependency-injection pattern used for every
other cross-layer handoff in this build (e.g. `WorkflowRunner`,
`PlaywrightEngine`).
"""
from __future__ import annotations

import asyncio
import contextlib
import random
import string
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

from stof.core.logger import get_logger
from stof.passive.models import RequestExchange, ResponseExchange

from .api_sniffer import ApiSniffer
from .endpoint_store import Endpoint, dedupe
from .form_detector import detect_forms

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext, Page

    from stof.passive.engine import PassiveEngine

_log = get_logger("crawler.crawler")

_EXTRACT_LINKS_SCRIPT = (
    "() => Array.from(document.querySelectorAll('a[href]')).map((a) => a.getAttribute('href'))"
)
_IGNORED_HREF_PREFIXES = ("javascript:", "mailto:", "tel:")
# Angular/Vue/etc. apps using hash-based client routing (Juice Shop
# included) render their entire nav as `<a href="#/search">`,
# `<a href="#/login">` -- a bare "#" prefix used to be blanket-ignored
# here on the assumption a hash href is always a same-page anchor jump,
# which silently meant the crawler never discovered a single route on
# this whole class of SPA (confirmed live: 8 endpoints total on Juice
# Shop, all of them the bare root page). Only a *route-shaped* hash
# ("#/...", or Angular's older "#!/..." hashbang form) is treated as
# navigable; a bare "#" or "#section"-style anchor still leads nowhere
# new and is still skipped.
_HASH_ROUTE_PREFIXES = ("#/", "#!/")
# Navigating to these triggers a browser download rather than a page
# load, which can leave the page mid-transition for the *next* goto().
# Skip them proactively rather than relying solely on the per-page
# try/except to recover after the fact.
_SKIP_FILE_EXTENSIONS = (
    ".pdf", ".zip", ".exe", ".dmg", ".pkg", ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".csv", ".tar", ".gz", ".rar", ".mp3", ".mp4", ".avi",
)
# A crawl runs on one shared authenticated page/context for its whole
# duration (see module docstring). Following a logout link mid-crawl
# silently kills that session server-side for every page visited
# afterward -- confirmed against this project's own demo target: after
# visiting logout.jsp, previously-working authenticated pages silently
# redirect to the login page instead of erroring, so nothing here would
# otherwise notice. Passive discovery has no reason to ever click
# "log off" anyway.
_LOGOUT_HREF_PATTERNS = ("logout", "log-out", "logoff", "log-off", "signout", "sign-out")
# If a page redirects somewhere containing one of these, it's very
# likely an auth wall -- worth a warning even when nothing "failed".
_AUTH_WALL_URL_HINTS = ("login", "signin", "sign-in", "auth")
# Structural signals a JS-routed SPA tends to put on an element that
# triggers client-side navigation without ever being a real `<a href>`
# -- an Angular Material icon button with `routerLink`, a raw `onclick`
# handler, anything exposing itself as `role="button"`, or a plain
# `<button>`. Deliberately framework-generic (no target-specific
# selector, no hardcoded route name) so the same heuristic applies to
# a target this project has never seen before, not just the one that
# motivated it (Juice Shop's own login/search icons render exactly
# this way -- neither has a plain anchor tag anywhere in the DOM).
_CURSOR_POINTER_MARKER_ATTR = "data-stof-cursor-click"
_CLICKABLE_SELECTOR = f"button, [role='button'], [routerlink], [ng-click], [onclick], [{_CURSOR_POINTER_MARKER_ATTR}]"
# `_mark_cursor_pointer_elements()` stamps this attribute onto any
# element whose COMPUTED cursor style is 'pointer' but that matches
# none of the structural attribute selectors above -- confirmed live
# against a real target whose entire sidebar-expand toggle was a plain
# `<div><img></div>` with a JS-bound click listener and zero matching
# HTML attribute (no `onclick`, no `role="button"`, nothing): every
# screen behind that collapsed sidebar (Category Management, Workflow
# Management, User Management, ...) was structurally unreachable, not
# because of any keyword-matching gap, but because the very first
# click needed to reveal the labels never had a selector that could
# find it. `cursor: pointer` is the same framework-agnostic signal the
# `browse` dev-tooling in this project's own toolchain already uses
# for exactly this class of problem.
_CURSOR_POINTER_MARKER_JS = """
(markerAttr) => {
  const els = document.querySelectorAll('*');
  let marked = 0;
  const cap = 60;
  for (const el of els) {
    if (marked >= cap) break;
    if (el.hasAttribute(markerAttr)) continue;
    const tag = el.tagName;
    if (tag === 'HTML' || tag === 'BODY' || tag === 'SCRIPT' || tag === 'STYLE') continue;
    if (el.matches("button, [role='button'], [routerlink], [ng-click], [onclick]")) continue;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) continue;
    // Skip large containers -- a whole-page wrapper occasionally
    // inherits `cursor: pointer` from an ancestor's CSS; this isn't a
    // real, individually-clickable UI control.
    if (rect.width > 400 || rect.height > 400) continue;
    if (getComputedStyle(el).cursor !== 'pointer') continue;
    el.setAttribute(markerAttr, '1');
    marked += 1;
  }
  return marked;
}
"""
# Clicking is active exploration (see module docstring's existing form-
# submission deviation) -- these candidates are skipped outright rather
# than clicked, since "prove this route exists" is not worth "maybe
# delete a real resource" or fire a real purchase/account action.
_DANGER_CLICK_TEXT = (
    "delete", "remove", "logout", "log out", "sign out", "signout",
    "buy", "purchase", "pay", "checkout", "unsubscribe", "confirm order",
    "place order", "cancel account", "deactivate", "empty cart", "clear cart",
)
# Independent of `CrawlerConfig.timeout_ms` (a page navigation budget)
# -- see the two-stage click in `_discover_clickable_routes` for why a
# short first attempt matters here specifically.
_CLICK_ACTIONABLE_TIMEOUT_MS = 2500
_CLICK_FORCE_TIMEOUT_MS = 2000
# Actions worth reaching first within a bounded per-page click budget
# -- see `_discover_clickable_routes`'s own two-phase scan/click split
# for why. Two distinct high-value families, both kept in the SAME
# priority tier deliberately: commerce actions (adding an item is
# reversible/non-destructive, unlike "buy"/"checkout" in
# `_DANGER_CLICK_TEXT` above) unlock IDOR/BOLA testing against whatever
# resource they create (a basket, a wishlist entry, ...), and
# auth-entry actions reveal the single most security-relevant surface
# on almost any target (a login/registration form). Confirmed live
# against Juice Shop that these two families genuinely compete for the
# same limited budget on the root page (a header icon each) -- ranking
# only one of them first just traded one blind spot for another, so
# both get equal priority rather than one crowding out the other.
_HIGH_VALUE_CLICK_HINTS = (
    "add to cart", "add to basket", "add to bag", "add to wishlist",
    "account", "sign in", "log in", "login", "register", "sign up",
    # Generic enterprise/admin/CMS-console vocabulary -- confirmed live
    # against a real target (a CMS admin console) whose entire attack
    # surface (category management, workflow management, user
    # management, content types) sat behind a collapsible sidebar menu:
    # clicking the parent menu item produces no URL change (an
    # in-place accordion expand, not a navigation), so it always fell
    # into this exact "revealed item" follow-up path -- but none of the
    # revealed sub-items ("Category Management", "Workflow Management",
    # ...) matched the commerce/auth-only vocabulary above, so the
    # entire admin surface was structurally unreachable no matter how
    # well everything else worked. This vocabulary names the SHAPE of
    # sidebar nav common to admin/CMS/back-office apps generically, not
    # any one target's specific labels.
    "settings", "configuration", "management", "admin", "manage",
    "dashboard", "workflow", "category", "categories", "content type",
    "users", "user management", "roles", "permissions",
)
# How much wider than the actual click budget the cheap scan phase
# looks -- bounded so a page with hundreds of clickable elements still
# can't make one page's exploration arbitrarily expensive.
_CLICK_SCAN_MULTIPLIER = 3
# Generic pagination-control shapes -- a bare page number ("2", "10"),
# a "Next"/">>"/"chevron-right" style advance control, or a common ARIA/rel
# convention. Deliberately framework-agnostic (no target-specific
# selector): confirmed live against a real target's Category
# Management table (335 rows, ~10 per page, numbered "1 2 3 ... 10 >
# L" pagination) where every row past page 1 -- and the paginated
# API's own `pageNumber` request-parameter shape, which vulnerability
# modules need to test for IDOR/data-boundary issues -- was completely
# invisible: the crawler only ever saw whatever page 1 happened to
# render.
_PAGINATION_NEXT_HINTS = ("next", "next page", ">>", "»")
_PAGINATION_ARIA_HINTS = ("next page", "go to next page", "pagination")
# Bounded -- this exists to capture the SHAPE of a paginated API (its
# request parameters), not to exhaustively page through potentially
# hundreds of rows. 2 additional pages is enough to confirm the
# pattern and get a second, real `pageNumber=1`-shaped request the
# sniffer can record.
_MAX_PAGINATION_CLICKS = 2


@dataclass
class CrawlerConfig:
    max_depth: int = 3
    max_pages: int = 100
    timeout_ms: int = 10000
    # Real sites (and this project's own demo target) are flaky under
    # headless crawling -- transient network errors, interrupted
    # navigations, "execution context destroyed". One retry noticeably
    # improves how many real pages/forms get captured without much
    # extra crawl time, since it only fires on actual failures.
    retries_per_page: int = 1
    # On by default -- see module docstring. Every POST form discovered
    # is filled with placeholder data and submitted, so the endpoint it
    # actually leads to gets captured. Pass False to opt back out.
    submit_forms_with_test_data: bool = True
    # On by default -- see module docstring. Clicks button/icon-style
    # elements that aren't real `<a href>` links (Angular `routerLink`
    # on a `<button>`, a raw `onclick`, `role="button"`) on a dedicated
    # probe page and queues wherever the click actually navigated to.
    # This is what finds routes like a hash-routed SPA's login/search
    # page when they're only reachable by clicking a header icon --
    # the exact gap that left Juice Shop's `#/login` and `#/search`
    # undiscovered even after hash-route links themselves were fixed.
    explore_clickable_navigation: bool = True
    # Hard cap per page -- a real page can have dozens of buttons
    # (product "add to cart" grids, etc.); each candidate costs a full
    # page reload + click + settle wait, so this bounds worst-case
    # crawl time the same way `max_pages`/`max_depth` already do.
    max_click_candidates_per_page: int = 12
    # Hard backstop, independent of `timeout_ms` -- a page whose
    # client-side JS keeps firing competing navigations in the
    # background can wedge the underlying CDP connection such that
    # `page.goto()`'s own `timeout_ms` never fires at all.
    # `asyncio.wait_for()` around each page visit forces it to give up
    # in the common case. It is NOT a complete fix, and this project's
    # own demo target proved that live: asyncio cancellation is
    # cooperative, so if the CDP transport itself is wedged badly
    # enough that it never yields back to the event loop, even
    # `wait_for()`'s cancel() can hang past this deadline waiting for
    # the cancelled task to unwind. `exclude_path_patterns` below is
    # the actual, reliable mitigation for a specific page that does
    # this -- this timeout is defense in depth for everything else.
    page_watchdog_s: float = 30.0
    # Substrings checked against each candidate href before it's
    # enqueued (see `_extract_and_queue_links`) -- e.g. a target's own
    # careers/marketing page that fires background navigations and
    # destabilizes the browser. Empty by default: no target-specific
    # exclusion is hardcoded here, an operator sets this per-target
    # (via `TargetConfig.crawler_exclude_patterns` in config.json) for
    # whatever quirky, non-security-relevant page their own target has.
    exclude_path_patterns: tuple[str, ...] = ()
    # Opt-in, additive-only: `None` (the default) registers no extra
    # listeners at all, so a caller that doesn't pass this gets
    # byte-for-byte the same crawl behavior as before this existed.
    # When set, `crawl()` feeds it response headers, request headers,
    # and every discovered Endpoint as a normal side effect of crawling
    # -- no additional request is ever sent to produce an Observation.
    passive_engine: "PassiveEngine | None" = None


def _same_origin(url: str, base_url: str) -> bool:
    a, b = urlparse(url), urlparse(base_url)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def _is_hash_route_url(url: str) -> bool:
    _, _, fragment = url.partition("#")
    return fragment != "" and ("#" + fragment).startswith(_HASH_ROUTE_PREFIXES)


_GET_FORM_FIELDS_SCRIPT = """
(index) => {
    const form = document.querySelectorAll('form')[index];
    if (!form) return null;
    return {
        method: (form.getAttribute('method') || 'GET').toUpperCase(),
        fields: Array.from(form.querySelectorAll('input, select, textarea')).map((el) => ({
            name: el.getAttribute('name') || '',
            type: (el.getAttribute('type') || el.tagName.toLowerCase()).toLowerCase(),
            optionCount: el.tagName.toLowerCase() === 'select' ? el.options.length : null,
        })).filter((f) => f.name),
    };
}
"""
_UNFILLABLE_FIELD_TYPES = ("submit", "button", "hidden", "file", "image", "reset")


def _random_suffix(length: int = 6) -> str:
    # Just a placeholder-data tag suffix, not a security token -- no
    # need for `secrets`'s cryptographic randomness here.
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))  # noqa: S311


def _test_value_for(field_type: str, field_name: str) -> str:
    """Placeholder value for one form field, tagged `stof-test-` so it's
    identifiable in logs/data if this ever runs against a real target."""
    name = (field_name or "").lower()
    tag = f"stof-test-{_random_suffix()}"
    if field_type == "email" or "email" in name:
        return f"{tag}@example.com"
    if field_type == "password" or "pass" in name:
        return f"StofTest-{_random_suffix()}!1"
    if field_type in ("number", "range") or any(h in name for h in ("amount", "qty", "quantity")):
        return "1"
    if field_type == "tel" or "phone" in name:
        return "5555550100"
    if field_type == "date" or "date" in name:
        return "01/01/2026"
    return tag


async def _submit_form_with_test_data(
    probe_page: "Page", page_url: str, form_index: int, timeout_ms: int
) -> None:
    """Fill one discovered form's visible fields with placeholder data
    and submit it -- see module docstring for why this exists and why
    it's opt-in."""
    try:
        await probe_page.goto(page_url, timeout=timeout_ms)
        descriptor = await probe_page.evaluate(_GET_FORM_FIELDS_SCRIPT, form_index)
        if descriptor is None:
            return

        # Client-side validation (e.g. "From/To account can't match")
        # commonly blocks submission via window.confirm()/alert(),
        # which otherwise just hangs waiting for a human. Auto-dismiss
        # and log what it said -- that message is itself useful
        # diagnostic output about what the form rejected.
        dialog_messages: list[str] = []

        async def _on_dialog(dialog: Any) -> None:
            dialog_messages.append(dialog.message)
            await dialog.dismiss()

        probe_page.on("dialog", _on_dialog)

        form_locator = probe_page.locator("form").nth(form_index)
        select_count = 0
        try:
            for field in descriptor["fields"]:
                field_type = field["type"]
                if field_type in _UNFILLABLE_FIELD_TYPES:
                    continue
                field_locator = form_locator.locator(f'[name="{field["name"]}"]').first
                try:
                    if field_type in ("checkbox", "radio"):
                        await field_locator.check(timeout=2000)
                    elif field_type == "select":
                        # .fill() doesn't work on <select>. Vary the
                        # picked index across successive <select>s in
                        # the same form (option_count permitting) --
                        # two dropdowns that both default to index 0
                        # commonly trips "from/to can't be the same"
                        # style validation (confirmed against this
                        # project's own demo target's transfer form).
                        option_count = field.get("optionCount") or 1
                        index = select_count % option_count
                        select_count += 1
                        await field_locator.select_option(index=index, timeout=2000)
                    else:
                        value = _test_value_for(field_type, field["name"])
                        await field_locator.fill(value, timeout=2000)
                except Exception as exc:
                    _log.warning(f"could not fill field '{field['name']}' on '{page_url}': {exc}")

            status: dict[str, Any] = {}

            def _on_response(response: Any) -> None:
                if response.request.resource_type == "document" and "status" not in status:
                    status["status"] = response.status
                    status["url"] = response.url

            probe_page.on("response", _on_response)
            try:
                await form_locator.evaluate("(f) => (f.requestSubmit ? f.requestSubmit() : f.submit())")
                await probe_page.wait_for_load_state("load", timeout=timeout_ms)
            finally:
                probe_page.remove_listener("response", _on_response)
        finally:
            probe_page.remove_listener("dialog", _on_dialog)

        blocked_note = f" (blocked by dialog: {dialog_messages[0]!r})" if dialog_messages else ""
        _log.info(
            f"submitted form #{form_index} on '{page_url}' with test data -> "
            f"landed on '{probe_page.url}' (status={status.get('status')}){blocked_note}"
        )
    except Exception as exc:
        _log.warning(f"form submission probe failed for form #{form_index} on '{page_url}': {exc}")


def _looks_like_a_credentials_form(parameters: list[str]) -> bool:
    """A password-shaped field name is one of the strongest, most
    framework-agnostic signals that a form is meant to be submitted --
    stronger, in fact, than the declared HTML `method` attribute on a
    modern JS-rendered SPA. Confirmed live against Juice Shop (a stock
    Angular app): its login/register/reset-password forms carry no
    `method` attribute at all (Angular submits via `(ngSubmit)` calling
    its own HttpClient POST, not the raw HTML form-submission protocol
    `method`/`action` describe), so `detect_forms()` defaulted every one
    of them to `method="GET"` -- and a GET-classified form is exactly
    what this function's caller otherwise skips, silently leaving the
    single most security-relevant form type on the entire target never
    submitted, on any SPA built this way, not just this one target."""
    return any("pass" in name.lower() for name in parameters)


async def _probe_new_forms(
    probe_page: "Page | None", landed_url: str, new_forms: list[Endpoint],
    submitted_forms: set[tuple[str, str]], timeout_ms: int,
) -> None:
    """Submits every not-yet-probed form discovered on this page with
    placeholder data -- a POST form, or one that looks like a
    credentials form regardless of its declared method (see
    `_looks_like_a_credentials_form`). A no-op when `probe_page` is
    None (the default, passive-only crawl)."""
    if probe_page is None:
        return
    for form_index, form_endpoint in enumerate(new_forms):
        if form_endpoint.method != "POST" and not _looks_like_a_credentials_form(form_endpoint.parameters):
            continue
        key = (form_endpoint.method, form_endpoint.url)
        if key in submitted_forms:
            continue
        submitted_forms.add(key)
        await _submit_form_with_test_data(probe_page, landed_url, form_index, timeout_ms)


async def _extract_and_queue_links(
    page: "Page", landed_url: str, start_url: str, depth: int, max_depth: int,
    visited: set[str], queue: list[tuple[str, int]], exclude_path_patterns: tuple[str, ...] = (),
) -> None:
    """Extracts every same-origin `<a href>` on the current page not
    already visited/queued and appends it to the BFS `queue` -- a no-op
    once `depth` has reached `max_depth`, since nothing found here
    would ever be visited anyway."""
    if depth >= max_depth:
        return
    hrefs = await page.evaluate(_EXTRACT_LINKS_SCRIPT)
    for href in hrefs:
        if not href or href.startswith(_IGNORED_HREF_PREFIXES):
            continue
        is_hash_route = href.startswith(_HASH_ROUTE_PREFIXES)
        if href.startswith("#") and not is_hash_route:
            continue  # plain in-page anchor (e.g. "#section") -- no route semantics
        if href.lower().split("?", 1)[0].split("#", 1)[0].endswith(_SKIP_FILE_EXTENSIONS):
            continue
        if any(pattern in href.lower() for pattern in _LOGOUT_HREF_PATTERNS):
            continue
        if any(pattern.lower() in href.lower() for pattern in exclude_path_patterns):
            continue
        # Resolve against `landed_url` (where the page actually ended
        # up), not `url` (what was requested) -- a redirect means those
        # can differ, and resolving relative hrefs against the wrong
        # base silently produces bogus same-origin-*looking* URLs that
        # aren't real.
        absolute = urljoin(landed_url, href)
        if not is_hash_route:
            # A normal same-page anchor fragment (`page.html#foo`) isn't
            # a distinct resource -- strip it so it collapses onto the
            # page itself, same as before. A hash-*route* IS the
            # distinct resource, so its fragment is kept.
            absolute = absolute.split("#", 1)[0]
        _queue_if_new(absolute, depth + 1, start_url, visited, queue)


async def _mark_cursor_pointer_elements(page: "Page") -> None:
    """Best-effort: stamps `_CURSOR_POINTER_MARKER_ATTR` onto elements
    whose computed `cursor` style is `pointer` and that don't already
    match `_CLICKABLE_SELECTOR`'s structural attributes -- see that
    constant's own comment for the real gap this closes. Never raises:
    a page that blocks style computation (rare) just means no extra
    candidates are found, not a crawl failure."""
    with contextlib.suppress(Exception):
        await page.evaluate(_CURSOR_POINTER_MARKER_JS, _CURSOR_POINTER_MARKER_ATTR)


async def _click_first_newly_revealed_high_value_item(
    click_probe_page: "Page", page_url: str, timeout_ms: int,
) -> "str | None":
    """Bounded, one-level follow-up for the extremely common
    "menu/dropdown trigger" shape: a button that reveals OTHER
    clickable elements instead of navigating anywhere itself --
    confirmed live against Juice Shop, whose "Account" header button
    is exactly this (`aria-label="Show/hide account menu"`); the real
    login entry point is a "Login" menu item that doesn't exist as a
    *visible*, clickable element until the trigger is clicked. Without
    this, the primary click loop records "no URL change" and moves on,
    so a route gated behind any menu/dropdown -- not just this one
    target's -- was structurally unreachable no matter how well link-
    and hash-route-following worked.

    Deliberately ONE level, not recursive: re-scans the same clickable
    selector for a NOW-visible element whose text/aria-label matches
    `_HIGH_VALUE_CLICK_HINTS` (that vocabulary already covers both the
    commerce and auth-entry cases this matters for) and clicks the
    first one found, returning where it navigated to (or `None` if
    nothing matched or nothing navigated). Cheap: only runs after a
    click that produced no URL change, and a freshly-opened menu is a
    handful of items, not a full second page scan."""
    await _mark_cursor_pointer_elements(click_probe_page)
    try:
        count = await click_probe_page.locator(_CLICKABLE_SELECTOR).count()
    except Exception:
        return None

    for index in range(count):
        candidate = click_probe_page.locator(_CLICKABLE_SELECTOR).nth(index)
        try:
            if not await candidate.is_visible(timeout=300):
                continue
            text = ((await candidate.inner_text(timeout=300)) or "").strip().lower()
            if not text:
                text = (
                    (await candidate.get_attribute("aria-label")) or (await candidate.get_attribute("title")) or ""
                ).strip().lower()
        except Exception as exc:
            _log.info(f"revealed-item scan of candidate #{index} on '{page_url}' failed (skipping): {exc}")
            continue
        if not any(hint in text for hint in _HIGH_VALUE_CLICK_HINTS) or any(word in text for word in _DANGER_CLICK_TEXT):
            continue
        try:
            try:
                await candidate.click(timeout=_CLICK_ACTIONABLE_TIMEOUT_MS)
            except Exception:
                await candidate.click(timeout=_CLICK_FORCE_TIMEOUT_MS, force=True)
            await _settle_after_navigation(click_probe_page, page_url)
        except Exception as exc:
            _log.info(f"revealed-item follow-up click #{index} on '{page_url}' failed (skipping): {exc}")
            continue
        landed = click_probe_page.url
        if landed != page_url:
            return landed
    return None


async def _discover_clickable_routes(
    click_probe_page: "Page", page_url: str, timeout_ms: int, max_candidates: int,
) -> list[str]:
    """Best-effort discovery of routes reachable only by clicking a
    button/icon that triggers client-side routing -- not through a
    plain `<a href>` the BFS crawl (and `_extract_and_queue_links`)
    already follows. See `CrawlerConfig.explore_clickable_navigation`'s
    own docstring for why this exists.

    Runs entirely on its own dedicated page, re-navigated back to
    `page_url` before and after every single click so one candidate's
    side effects (a modal, a route change, a client-side state change)
    can never bleed into the next candidate's baseline. Returns
    same-origin URLs the click actually navigated to; the caller
    de-duplicates against `visited` the same way link-discovery does.
    """
    discovered: list[str] = []
    dialog_messages: list[str] = []

    async def _on_dialog(dialog: Any) -> None:
        dialog_messages.append(dialog.message)
        await dialog.dismiss()

    click_probe_page.on("dialog", _on_dialog)
    try:
        try:
            await click_probe_page.goto(page_url, timeout=timeout_ms)
        except Exception as exc:
            _log.warning(f"click-exploration probe couldn't load '{page_url}': {exc}")
            return discovered
        await _settle_after_navigation(click_probe_page, page_url)
        await _mark_cursor_pointer_elements(click_probe_page)

        try:
            count = await click_probe_page.locator(_CLICKABLE_SELECTOR).count()
        except Exception as exc:
            _log.info(f"click-exploration couldn't enumerate candidates on '{page_url}': {exc}")
            return discovered

        # Two-phase, not one: a page can have far more clickable elements
        # than the per-page click budget allows, and DOM order alone
        # (the old single-pass behavior) means unrelated nav icons
        # crowd out the handful of candidates that actually matter --
        # confirmed live against Juice Shop, where an "Add to Basket"
        # button never got a chance to be clicked within budget, so
        # `/rest/basket/...` was never discovered at all and IDOR
        # testing against it had nothing to work with. Scan (cheap:
        # visibility + text only) a wider net first, then click only
        # the top `max_candidates` -- commerce-shaped actions
        # (add-to-cart/basket/bag/wishlist -- adding an item is
        # reversible and non-destructive, unlike "buy"/"checkout",
        # still in `_DANGER_CLICK_TEXT`) ranked first, since reaching
        # them is what actually unlocks IDOR/BOLA testing against
        # whatever resource they create. Generic on purpose: this
        # vocabulary applies to any e-commerce-shaped SPA, not just
        # this one target.
        scan_cap = min(count, max_candidates * _CLICK_SCAN_MULTIPLIER)
        high_priority: list[tuple[int, str]] = []
        normal_priority: list[tuple[int, str]] = []
        for index in range(scan_cap):
            candidate = click_probe_page.locator(_CLICKABLE_SELECTOR).nth(index)
            try:
                if not await candidate.is_visible(timeout=500):
                    continue
                text = ((await candidate.inner_text(timeout=500)) or "").strip().lower()
                if not text:
                    text = (
                        (await candidate.get_attribute("aria-label")) or (await candidate.get_attribute("title")) or ""
                    ).strip().lower()
            except Exception as exc:
                _log.info(f"click-exploration scan of candidate #{index} on '{page_url}' failed (skipping): {exc}")
                continue
            if any(word in text for word in _DANGER_CLICK_TEXT):
                continue
            bucket = high_priority if any(hint in text for hint in _HIGH_VALUE_CLICK_HINTS) else normal_priority
            bucket.append((index, text))

        ranked = (high_priority + normal_priority)[:max_candidates]
        for position, (index, text) in enumerate(ranked):
            candidate = click_probe_page.locator(_CLICKABLE_SELECTOR).nth(index)
            try:
                # Two-stage click, short timeout on the first try: a
                # normal click waits for the element to actually receive
                # pointer events, which routinely never happens on a
                # real target when an unrelated overlay (a cookie-
                # consent/welcome banner, a Material CDK overlay
                # backdrop left in the DOM) sits on top of the whole
                # page -- confirmed live against Juice Shop, where every
                # single candidate on every page timed out this way,
                # burning the full 10s default each time for zero
                # discovery. `force=True` bypasses that hit-target
                # check specifically (still requires the element to be
                # attached/visible) -- exactly the case an invisible
                # full-viewport overlay represents, and generic enough
                # to help against any target with a similar overlay,
                # not just this one. A short first-attempt timeout means
                # a genuinely blocked page fails fast instead of eating
                # the whole per-candidate budget before even trying the
                # fallback.
                try:
                    await candidate.click(timeout=_CLICK_ACTIONABLE_TIMEOUT_MS)
                except Exception:
                    await candidate.click(timeout=_CLICK_FORCE_TIMEOUT_MS, force=True)
                try:
                    await click_probe_page.wait_for_load_state("networkidle", timeout=2000)
                except Exception as settle_exc:
                    _log.info(f"click on candidate #{index} ('{text}') on '{page_url}' never reached network-idle: {settle_exc}")
                landed = click_probe_page.url
                if landed == page_url:
                    landed = await _click_first_newly_revealed_high_value_item(click_probe_page, page_url, timeout_ms) or landed
                if landed != page_url and landed not in discovered:
                    discovered.append(landed)
            except Exception as exc:
                _log.info(f"click-exploration candidate #{index} on '{page_url}' failed (skipping): {exc}")
            finally:
                # Reset baseline for the NEXT candidate regardless of
                # what happened -- an earlier click may have navigated
                # away or opened a modal that would poison the next
                # check. Skipped on the last candidate: there is no
                # next one to protect, and this reset (a full
                # navigation plus, for a hash-routed page, a settle
                # wait up to `timeout_ms`) is the single most expensive
                # step in the whole per-candidate loop -- paying it
                # unconditionally, including after the final candidate
                # on every page, was pure waste that added up over a
                # full crawl.
                if position < len(ranked) - 1:
                    try:
                        await click_probe_page.goto(page_url, timeout=timeout_ms)
                    except Exception:
                        break  # page_url itself stopped loading -- no point continuing this page
                    await _settle_after_navigation(click_probe_page, page_url)
                    # A fresh navigation means a fresh DOM -- the marker
                    # attribute from the pre-loop scan doesn't survive
                    # it, and without re-marking, `_CLICKABLE_SELECTOR`'s
                    # cursor-pointer branch would match zero elements
                    # here, shifting every subsequent `.nth(index)` off
                    # the position `ranked` actually recorded.
                    await _mark_cursor_pointer_elements(click_probe_page)

        # Runs last, on whatever state `click_probe_page` is left in
        # (page_url's own baseline if `ranked` was empty, or wherever
        # the final candidate's own reset navigation landed) -- a
        # separate, bounded concern from the candidate loop above:
        # capturing a paginated table's real API shape, not discovering
        # a new page URL.
        await _explore_pagination(click_probe_page, page_url, timeout_ms)
    finally:
        click_probe_page.remove_listener("dialog", _on_dialog)

    if dialog_messages:
        _log.info(f"click-exploration on '{page_url}' dismissed {len(dialog_messages)} dialog(s): {dialog_messages[:3]}")
    return discovered


async def _explore_pagination(click_probe_page: "Page", page_url: str, timeout_ms: int) -> None:
    """Best-effort: clicks a "next page" style control up to
    `_MAX_PAGINATION_CLICKS` times so whatever paginated data-fetch API
    call it triggers gets captured by the shared `ApiSniffer` already
    attached to `click_probe_page` -- see `_PAGINATION_NEXT_HINTS`'s own
    comment for the real gap this closes.

    Deliberately returns nothing: unlike `_discover_clickable_routes`,
    there's no new page URL to report here -- pagination is client-
    state-only in every real SPA this was built against (the URL never
    changes), so the only observable effect worth capturing is the
    sniffer seeing a new, differently-paginated request. Never raises:
    a page with no pagination control at all is the overwhelmingly
    common case, not a failure."""
    for _ in range(_MAX_PAGINATION_CLICKS):
        try:
            count = await click_probe_page.locator(_CLICKABLE_SELECTOR).count()
        except Exception:
            return
        candidate = None
        for index in range(min(count, 40)):
            loc = click_probe_page.locator(_CLICKABLE_SELECTOR).nth(index)
            try:
                if not await loc.is_visible(timeout=200):
                    continue
                text = ((await loc.inner_text(timeout=200)) or "").strip().lower()
                aria = ((await loc.get_attribute("aria-label")) or "").strip().lower()
            except Exception:
                continue
            if text in _PAGINATION_NEXT_HINTS or any(hint in aria for hint in _PAGINATION_ARIA_HINTS):
                candidate = loc
                break
        if candidate is None:
            return
        try:
            try:
                await candidate.click(timeout=_CLICK_ACTIONABLE_TIMEOUT_MS)
            except Exception:
                await candidate.click(timeout=_CLICK_FORCE_TIMEOUT_MS, force=True)
            with contextlib.suppress(Exception):
                await click_probe_page.wait_for_load_state("networkidle", timeout=2000)
        except Exception as exc:
            _log.info(f"pagination exploration on '{page_url}' stopped: {exc}")
            return


async def _settle_after_navigation(page: "Page", url: str, timeout_ms: int = 3000) -> None:
    """Best-effort wait for a hash-routed SPA's async render to finish
    after navigating to `url` -- `goto()` to a hash-route resolves as
    soon as the history/hash entry itself changes, before the app's own
    JS has actually reacted to the hashchange event and rendered the
    new view. Every caller that navigates somewhere and then
    immediately inspects the DOM (link/form extraction, clickable-
    candidate scanning) needs this, not just the main BFS loop --
    omitting it from click-exploration's own navigation was a real,
    confirmed source of run-to-run flakiness against a real target:
    sometimes Angular's render finished before the scan, sometimes it
    hadn't, so the exact same page yielded a different candidate set
    (and therefore a different discovered-endpoint set) from one run
    to the next. No-op for a non-hash-route URL, where `goto()`'s own
    "load" wait already covers a normal full page load."""
    if not _is_hash_route_url(url):
        return
    try:
        await page.wait_for_load_state("networkidle", timeout=timeout_ms)
    except Exception as exc:
        _log.info(f"'{url}' never reached network-idle after a hash-route change (proceeding with whatever rendered): {exc}")
    # `networkidle` only means the NETWORK went quiet -- a framework's
    # own change-detection/render cycle (Angular's zone.js digest, a
    # React state update queued off the last response) can still be
    # finishing a beat after that, off-thread from any network activity
    # this wait would ever see. A short, fixed buffer here is the
    # standard, well-documented mitigation for exactly this class of
    # flakiness in Angular-style SPA testing -- confirmed as a real,
    # additional source of run-to-run variance on this project's own
    # Juice Shop benchmark target (the same page, same code, yielding a
    # different discovered-endpoint set from one run to the next even
    # after the networkidle fix above).
    with contextlib.suppress(Exception):
        await page.wait_for_timeout(250)


def _queue_if_new(url: str, depth: int, start_url: str, visited: set[str], queue: list[tuple[str, int]]) -> None:
    if url not in visited and _same_origin(url, start_url):
        queue.append((url, depth))


async def crawl(
    start_url: str, context: "BrowserContext", config: CrawlerConfig | None = None
) -> list[Endpoint]:
    """BFS crawl from `start_url` using an already-authenticated
    `context`. Returns a deduplicated list of Endpoints (pages, forms,
    and XHR/fetch API calls observed along the way)."""
    config = config or CrawlerConfig()
    sniffer = ApiSniffer(origin_url=start_url)
    page = await context.new_page()
    sniffer.attach(page)
    # Separate page for form-submission probing, so it never disrupts
    # the main BFS page's navigation/state. Only opened if actually needed.
    probe_page = await context.new_page() if config.submit_forms_with_test_data else None
    submitted_forms: set[tuple[str, str]] = set()  # (method, action_url) already probed
    # Separate again from both the main BFS page and the form-submission
    # probe page -- see CrawlerConfig.explore_clickable_navigation.
    click_probe_page = await context.new_page() if config.explore_clickable_navigation else None
    # The sniffer must watch every page that can fire the real XHR/fetch
    # call, not just the main BFS page -- a submitted form's actual
    # network request happens on `probe_page`, and a discovered nav
    # button's on `click_probe_page`. One shared `ApiSniffer` instance
    # attached to all three is a single `_seen` dict, so the same
    # dedup-by-(method,path) behavior holds regardless of which page
    # actually made the request. Missing this was a real, confirmed bug:
    # against Juice Shop, the login form was correctly identified and
    # genuinely submitted, but the resulting `POST /rest/user/login`
    # call landed on `probe_page` and was silently never recorded as an
    # endpoint at all.
    if probe_page is not None:
        sniffer.attach(probe_page)
    if click_probe_page is not None:
        sniffer.attach(click_probe_page)

    # Passive observation, entirely opt-in (see CrawlerConfig.passive_engine's
    # own docstring) -- sync handlers only, same reasoning `ApiSniffer` and
    # `_submit_form_with_test_data`'s own listener already follow: no
    # response-body read from inside a `page.on(...)` handler.
    passive_engine = config.passive_engine

    def _on_passive_response(response: Any) -> None:
        passive_engine.observe_response(ResponseExchange(url=response.url, status=response.status, headers=dict(response.headers)))

    def _on_passive_request(request: Any) -> None:
        passive_engine.observe_request(RequestExchange(url=request.url, method=request.method, headers=dict(request.headers)))

    if passive_engine is not None:
        page.on("response", _on_passive_response)
        page.on("request", _on_passive_request)

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(start_url, 0)]
    page_endpoints: list[Endpoint] = []
    form_endpoints: list[Endpoint] = []

    try:
        while queue and len(visited) < config.max_pages:
            url, depth = queue.pop(0)
            if url in visited or depth > config.max_depth:
                continue
            if not _same_origin(url, start_url):
                continue

            visited.add(url)
            # Wrap the whole per-page block, not just goto(): a page that
            # triggers a download/redirect can leave the browser mid-
            # transition such that a *subsequent* evaluate() call fails
            # with "Execution context was destroyed" even though goto()
            # itself raised no error. One bad page must not abort the
            # whole crawl regardless of which call inside it fails.
            #
            # Retried as a whole unit (not just the failing sub-step):
            # a half-processed page (e.g. goto succeeded but forms scan
            # didn't) should be re-attempted cleanly rather than resumed
            # partway, since page state after a failure is unreliable.
            last_exc: Exception | None = None
            for attempt in range(config.retries_per_page + 1):
                landed_url: str | None = None

                async def _visit_once(url: str = url, depth: int = depth) -> None:
                    # `url`/`depth` as default-arg values (evaluated
                    # once, at def time) rather than closed-over loop
                    # variables -- a fresh closure is created each
                    # attempt/iteration and always awaited before the
                    # next one is created, so capture-by-reference
                    # would in practice be safe here too, but binding
                    # explicitly removes any doubt and satisfies
                    # ruff's B023.
                    nonlocal landed_url
                    await page.goto(url, timeout=config.timeout_ms)

                    # Record what we actually ended up looking at, not
                    # just what we asked for -- a silent redirect (e.g.
                    # an auth-gated page bouncing to a login page) must
                    # never masquerade as a successful visit to `url`.
                    landed_url = page.url
                    if landed_url != url:
                        note = " (looks like an auth wall)" if any(
                            hint in landed_url.lower() for hint in _AUTH_WALL_URL_HINTS
                        ) else ""
                        _log.warning(f"'{url}' redirected to '{landed_url}'{note}")

                    if not _same_origin(landed_url, start_url):
                        # A same-origin link can still redirect off-site
                        # (e.g. Juice Shop's own `/redirect?to=...` open
                        # redirect). Never record third-party content as
                        # one of *this* target's endpoints -- vulnerability
                        # modules and Burp's Active Scan both treat
                        # everything in `endpoints.json` as fair game to
                        # send test/attack traffic to, and a stray
                        # `github.com` entry would mean probing a real
                        # third party without authorization.
                        _log.warning(f"'{url}' redirected off-origin to '{landed_url}' -- not recording as an endpoint")
                        return

                    await _settle_after_navigation(page, landed_url)

                    page_endpoints.append(Endpoint(url=landed_url, method="GET", endpoint_type="page"))
                    new_forms = await detect_forms(page)
                    form_endpoints.extend(new_forms)

                    await _probe_new_forms(probe_page, landed_url, new_forms, submitted_forms, config.timeout_ms)
                    await _extract_and_queue_links(page, landed_url, start_url, depth, config.max_depth, visited, queue, config.exclude_path_patterns)

                    if click_probe_page is not None and depth < config.max_depth:
                        clicked_urls = await _discover_clickable_routes(
                            click_probe_page, landed_url, config.timeout_ms, config.max_click_candidates_per_page
                        )
                        for clicked_url in clicked_urls:
                            _queue_if_new(clicked_url, depth + 1, start_url, visited, queue)

                try:
                    await asyncio.wait_for(_visit_once(), timeout=config.page_watchdog_s)
                    last_exc = None
                    break
                except Exception as exc:
                    last_exc = exc
                    is_final_attempt = attempt == config.retries_per_page
                    if is_final_attempt:
                        # No more retries left: keep whatever partial
                        # progress this last attempt made (e.g. goto
                        # succeeded even though the forms scan after it
                        # didn't) rather than throwing it away -- a page
                        # that was genuinely reached should still count.
                        break
                    # More retries coming: undo the partial
                    # page_endpoints append so the eventual successful
                    # attempt doesn't leave a stray duplicate behind.
                    # Compare against landed_url (what was actually
                    # appended), not url (what was requested) -- a
                    # redirect means those can differ.
                    if landed_url is not None and page_endpoints and page_endpoints[-1].url == landed_url:
                        page_endpoints.pop()
                    _log.warning(f"retrying '{url}' after failure: {exc}")

            if last_exc is not None:
                _log.warning(f"failed to process '{url}' after {config.retries_per_page + 1} attempt(s): {last_exc}")
    finally:
        sniffer.detach(page)
        if passive_engine is not None:
            page.remove_listener("response", _on_passive_response)
            page.remove_listener("request", _on_passive_request)
        await page.close()
        if probe_page is not None:
            sniffer.detach(probe_page)
            await probe_page.close()
        if click_probe_page is not None:
            sniffer.detach(click_probe_page)
            await click_probe_page.close()

    all_endpoints = page_endpoints + form_endpoints + sniffer.endpoints
    deduped = dedupe(all_endpoints)
    _log.info(f"crawl of '{start_url}': visited {len(visited)} page(s), found {len(deduped)} endpoint(s)")
    if passive_engine is not None:
        for endpoint in deduped:
            passive_engine.observe_endpoint(endpoint)
    return deduped


async def verify_auth_required(endpoints: list[Endpoint], anon_context: "BrowserContext", timeout_ms: int = 8000) -> None:
    """Mutates `endpoint.auth_required` in place for every GET endpoint,
    based on a real anonymous probe -- NOT "the crawl was authenticated,
    so everything it found must require auth", the assumption this
    project used to make. That's a non-sequitur (a public marketing
    page reached by a logged-in crawl is still public) and was
    live-verified to mass-false-positive `idor_tests.py`'s TC-050.3
    (forced browsing while unauthenticated): dozens of ordinary public
    content pages on a real target got reported as Critical findings
    simply because an authenticated crawl happened to walk through
    them, while curl with zero cookies against the same URLs returned
    a normal 200 the whole time.

    A GET endpoint is marked `auth_required=True` only when an
    anonymous request to it is actually denied -- a 401/403, or a
    redirect elsewhere (`max_redirects=0` so the redirect itself is
    observed, not silently followed). Confirmed against a real target:
    an authenticated-only page (e.g. a bank account page) 302s an
    anonymous visitor to the login page, while a public page returns
    200 either way -- exactly the same signal TC-050.3 itself already
    checks for at test time, just moved to where the fact actually
    belongs (Layer 7, the one place that should own it) instead of
    every consuming module re-deciding it under a wrong premise."""
    await asyncio.gather(*(
        _check_auth_required(endpoint, anon_context, timeout_ms)
        for endpoint in endpoints if endpoint.method.upper() == "GET"
    ))


async def _check_auth_required(endpoint: Endpoint, anon_context: "BrowserContext", timeout_ms: int) -> None:
    """One endpoint's own anonymous probe -- split out of
    `verify_auth_required`'s loop so every GET endpoint can be probed
    concurrently. Mutates only its own `endpoint.auth_required`, so
    concurrent calls never contend over shared state."""
    try:
        resp = await anon_context.request.get(endpoint.url, timeout=timeout_ms, max_redirects=0)
    except Exception as exc:
        _log.warning(f"auth-required probe failed for {endpoint.url}: {exc}")
        return
    endpoint.auth_required = resp.status in (401, 403) or 300 <= resp.status < 400
