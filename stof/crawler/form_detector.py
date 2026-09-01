"""Layer 7 — form surface discovery.

On each crawled page, scans the DOM for `<form>` elements and extracts
the action URL, method, and every input's name/type. These become
priority targets for Layer 9's auth_tests module.
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urljoin

from .endpoint_store import Endpoint

if TYPE_CHECKING:
    from playwright.async_api import Page

_EXTRACT_FORMS_SCRIPT = """
() => Array.from(document.querySelectorAll('form')).map((form) => ({
    action: form.getAttribute('action') || '',
    method: (form.getAttribute('method') || 'GET').toUpperCase(),
    inputs: Array.from(form.querySelectorAll('input, select, textarea')).map((el) => ({
        name: el.getAttribute('name') || '',
        type: el.getAttribute('type') || el.tagName.toLowerCase(),
        value: el.value || el.getAttribute('value') || '',
    })).filter((i) => i.name),
}))
"""


async def detect_forms(page: "Page") -> list[Endpoint]:
    """Extract every `<form>` on the current page as a `form`-type
    Endpoint, with input names as its parameters, each tagged with
    where it's actually submitted: "body" for a POST form (the real
    submission target -- injection modules need to place a payload in
    the request body, not the URL), "query" for a GET form (a GET
    form's fields really do end up in the query string)."""
    raw_forms = await page.evaluate(_EXTRACT_FORMS_SCRIPT)
    endpoints: list[Endpoint] = []
    for form in raw_forms:
        action = form.get("action") or ""
        action_url = urljoin(page.url, action) if action else page.url
        # A `<form action="javascript:...">` (or `mailto:`/`tel:`) has
        # no real HTTP endpoint behind it -- `urljoin` leaves a URL with
        # its own scheme untouched, so this only catches the literal
        # non-HTTP action, not a normal relative path. Live-verified
        # against a real target: without this, `javascript:someFunc()`
        # was recorded as a "form endpoint" alongside genuine ones.
        if not action_url.startswith(("http://", "https://")):
            continue
        method = form.get("method", "GET")
        location = "body" if method == "POST" else "query"
        inputs = form.get("inputs", [])
        parameters = [i["name"] for i in inputs if i.get("name")]
        # Only entries with a genuinely non-empty `value` -- most inputs
        # (a username field, a search box) start blank and have nothing
        # worth snapshotting; a hidden anti-CSRF token field is the
        # motivating case that does (`csrf_tests.py` needs the real
        # token value to submit a working baseline request).
        parameter_values = {i["name"]: i["value"] for i in inputs if i.get("name") and i.get("value")}
        endpoints.append(
            Endpoint(
                url=action_url,
                method=method,
                endpoint_type="form",
                parameters=parameters,
                param_locations=dict.fromkeys(parameters, location),
                parameter_values=parameter_values,
            )
        )
    return endpoints
