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
_IGNORED_HREF_PREFIXES = ("javascript:", "mailto:", "tel:", "#")
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


async def _probe_new_forms(
    probe_page: "Page | None", landed_url: str, new_forms: list[Endpoint],
    submitted_forms: set[tuple[str, str]], timeout_ms: int,
) -> None:
    """Submits every not-yet-probed POST form discovered on this page
    with placeholder data -- a no-op when `probe_page` is None (the
    default, passive-only crawl)."""
    if probe_page is None:
        return
    for form_index, form_endpoint in enumerate(new_forms):
        if form_endpoint.method != "POST":
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
        if href.lower().split("?", 1)[0].endswith(_SKIP_FILE_EXTENSIONS):
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
        absolute = urljoin(landed_url, href).split("#", 1)[0]
        if absolute not in visited and _same_origin(absolute, start_url):
            queue.append((absolute, depth + 1))


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

                    page_endpoints.append(Endpoint(url=landed_url, method="GET", endpoint_type="page"))
                    new_forms = await detect_forms(page)
                    form_endpoints.extend(new_forms)

                    await _probe_new_forms(probe_page, landed_url, new_forms, submitted_forms, config.timeout_ms)
                    await _extract_and_queue_links(page, landed_url, start_url, depth, config.max_depth, visited, queue, config.exclude_path_patterns)

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
            await probe_page.close()

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
    for endpoint in endpoints:
        if endpoint.method.upper() != "GET":
            continue
        try:
            resp = await anon_context.request.get(endpoint.url, timeout=timeout_ms, max_redirects=0)
        except Exception as exc:
            _log.warning(f"auth-required probe failed for {endpoint.url}: {exc}")
            continue
        endpoint.auth_required = resp.status in (401, 403) or 300 <= resp.status < 400
