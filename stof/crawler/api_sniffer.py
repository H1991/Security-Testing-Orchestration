"""Layer 7 — XHR/fetch endpoint capture during crawl.

Registers `page.on("request")` and captures every XHR/fetch request the
page makes while the crawler navigates, deduplicating by (method, path)
-- distinct query strings/bodies on the same path collapse into one
Endpoint, with parameter names merged.

Also captures POST/PUT/PATCH requests of any resource type (not just
xhr/fetch) that aren't a static asset -- a real full-page form
submission the site triggers on its own (e.g. a redirect chain) is just
as interesting as an XHR call, and was previously dropped entirely.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from .endpoint_store import Endpoint

if TYPE_CHECKING:
    from playwright.async_api import Page, Request

_BODY_BEARING_METHODS = ("POST", "PUT", "PATCH")
_SKIP_RESOURCE_TYPES = {"image", "stylesheet", "font", "media", "manifest", "other"}


def _body_param_names(request: "Request") -> list[str]:
    """Parameter names from the request BODY -- for a POST, that's where
    the real parameters usually live, not the URL query string (which is
    all the previous version of this module ever looked at)."""
    post_data = request.post_data
    if not post_data:
        return []

    content_type = (request.headers or {}).get("content-type", "")
    if "application/json" in content_type:
        try:
            body = json.loads(post_data)
        except (json.JSONDecodeError, TypeError):
            return []
        return list(body.keys()) if isinstance(body, dict) else []

    # Default assumption: application/x-www-form-urlencoded.
    return list(parse_qs(post_data).keys())


class ApiSniffer:
    """`origin_url`, when given, restricts captured requests to the same
    origin -- a real page routinely fires XHR/fetch calls to embedded
    third-party widgets (confirmed live: a GitHub star-button embed on
    a crawled target fired its own API calls to github.com and
    collector.github.com). Those aren't this target's endpoints, and
    recording them would mean vulnerability modules and Burp's Active
    Scan later send test/attack traffic to a real third party without
    authorization. `None` (the default) keeps the old unfiltered
    behavior for callers that already scope their own input."""

    def __init__(self, origin_url: str | None = None) -> None:
        self._seen: dict[tuple[str, str], Endpoint] = {}
        self._origin = urlparse(origin_url) if origin_url else None

    @property
    def endpoints(self) -> list[Endpoint]:
        return list(self._seen.values())

    def attach(self, page: "Page") -> None:
        page.on("request", self._on_request)

    def detach(self, page: "Page") -> None:
        page.remove_listener("request", self._on_request)

    def _is_same_origin(self, url: str) -> bool:
        if self._origin is None:
            return True
        parsed = urlparse(url)
        return (parsed.scheme, parsed.hostname, parsed.port) == (
            self._origin.scheme, self._origin.hostname, self._origin.port,
        )

    def _on_request(self, request: "Request") -> None:
        if not self._is_same_origin(request.url):
            return
        if request.resource_type in _SKIP_RESOURCE_TYPES:
            return
        method = request.method.upper()
        if request.resource_type not in ("xhr", "fetch") and method not in _BODY_BEARING_METHODS:
            return

        parsed = urlparse(request.url)
        key = (method, parsed.path)
        # `keep_blank_values=True` -- a query param with an empty value
        # right now (a typeahead search box captured before the user
        # typed anything, e.g. Juice Shop's own `?q=`) still names a
        # real parameter the endpoint accepts values through.
        # `parse_qs`'s default drops blank-valued keys entirely, which
        # silently meant this parameter was never even recorded as
        # existing, let alone tested by any injection module -- not a
        # target-specific quirk, any search-as-you-type field on any
        # site starts out this way.
        query_params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        body_params = _body_param_names(request) if method in _BODY_BEARING_METHODS else []
        parameters = list(dict.fromkeys(query_params + body_params))
        # Body params are tagged last so a name appearing in both (rare)
        # resolves to "body" -- that's where a real submission actually
        # places the value that matters.
        param_locations = {name: "query" for name in query_params}
        param_locations.update({name: "body" for name in body_params})

        existing = self._seen.get(key)
        if existing is None:
            self._seen[key] = Endpoint(
                url=request.url, method=method, endpoint_type="api",
                parameters=parameters, param_locations=param_locations,
            )
        else:
            existing.parameters = list(dict.fromkeys(existing.parameters + parameters))
            for name, location in param_locations.items():
                existing.param_locations.setdefault(name, location)
