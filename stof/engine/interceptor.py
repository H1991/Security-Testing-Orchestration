"""Layer 3B — request/response interception and payload injection.

Registers `page.route()` / `page.on("response")` handlers. Vulnerability
modules never manipulate the page directly for this — they call
`RequestInterceptor.inject_payload(pattern, payload)` (request side) or
`RequestInterceptor.inject_response(pattern, rewrite)` (response side)
and this module handles applying it to matching in-flight requests.

Response rewriting exists for one specific, otherwise-untestable class
of finding: an SPA that trusts a denial response it can be shown a
manipulated version of (a 401/403 flipped to 200, or an
`{"authorized": false}` field flipped to `true`) instead of the server
independently re-checking the follow-up action -- see
`bfla_tests.py`'s TC-055.6. Route interception normally only sees the
REQUEST; to rewrite the RESPONSE, the real request has to actually be
made first (`route.fetch()`) so the rewrite has real bytes to start
from, then handed back modified (`route.fulfill()`) instead of the
request being allowed to pass straight through (`route.continue_()`).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from playwright.async_api import Page, Request, Response, Route

_log = get_logger("engine.interceptor")

Injection = tuple[re.Pattern[str], dict[str, Any]]
ResponseInjection = tuple[re.Pattern[str], dict[str, Any]]


@dataclass
class InterceptedExchange:
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str | None
    response_status: int | None = None
    response_headers: dict[str, str] | None = None


def compute_overrides(url: str, injections: list[Injection]) -> dict[str, Any]:
    """Merge every injection whose pattern matches `url` into a single
    set of overrides (`headers`, `post_data`, `url`). Injections
    registered later win on conflicting header keys. Pure function --
    kept separate from the async route handler so it's testable without
    a real Playwright `Route`/`Request`."""
    overrides: dict[str, Any] = {}
    for pattern, payload in injections:
        if not pattern.search(url):
            continue
        if "headers" in payload:
            overrides["headers"] = {**overrides.get("headers", {}), **payload["headers"]}
        if "body" in payload:
            overrides["post_data"] = payload["body"]
        if "url" in payload:
            overrides["url"] = payload["url"]
    return overrides


def compute_response_rewrite(url: str, injections: list[ResponseInjection]) -> dict[str, Any] | None:
    """Same last-match-wins merge shape as `compute_overrides`, for the
    response side: `status`/`only_if_status`/`flip_false_fields`/
    `body_patch` keys across every injection whose pattern matches
    `url`. Returns `None` when nothing matches at all, so
    `_handle_route` can skip the extra `route.fetch()` round-trip
    entirely for the overwhelming common case of no response injection
    registered (most requests, most of the time)."""
    matched: dict[str, Any] = {}
    hit = False
    for pattern, rewrite in injections:
        if not pattern.search(url):
            continue
        hit = True
        if "status" in rewrite:
            matched["status"] = rewrite["status"]
        if "only_if_status" in rewrite:
            matched["only_if_status"] = rewrite["only_if_status"]
        if "flip_false_fields" in rewrite:
            matched["flip_false_fields"] = tuple(rewrite["flip_false_fields"])
        if "body_patch" in rewrite:
            matched["body_patch"] = {**matched.get("body_patch", {}), **rewrite["body_patch"]}
    return matched if hit else None


def _patch_json_object(body: bytes, flip_fields: tuple[str, ...], body_patch: dict[str, Any] | None) -> bytes:
    """The JSON-decode/mutate/re-encode half of `apply_response_rewrite`,
    split out purely to keep that function's own branching (the
    only-if-status gate) readable at a glance. A malformed/non-JSON/
    non-dict body is returned unchanged rather than raising -- see
    `apply_response_rewrite`'s docstring for why.

    `flip_fields` matches case-insensitively (the actual key's original
    casing is preserved on write) -- a caller has no way to know
    whether a target names its field `authorized`, `isAuthorized`, or
    `IsAuthorized`, and a naming-convention mismatch silently no-op'ing
    the whole rewrite would be far worse than the near-zero risk of a
    same-name-different-case collision."""
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return body
    if not isinstance(parsed, dict):
        return body
    lowered_keys = {key.lower(): key for key in parsed}
    changed = False
    for field in flip_fields:
        actual_key = lowered_keys.get(field.lower())
        if actual_key is not None and parsed.get(actual_key) is False:
            parsed[actual_key] = True
            changed = True
    if body_patch:
        parsed.update(body_patch)
        changed = True
    return json.dumps(parsed).encode("utf-8") if changed else body


def apply_response_rewrite(status: int, content_type: str, body: bytes, rewrite: dict[str, Any]) -> tuple[int, bytes]:
    """Pure function: apply a `compute_response_rewrite` result to a
    real captured response. `only_if_status` gates the whole rewrite on
    the ORIGINAL status (e.g. only touch responses that were actually
    401/403) so a broad, URL-agnostic pattern like `.*` stays safe --
    everything that wasn't already a denial passes through byte-for-
    byte untouched. `flip_false_fields`/`body_patch` only ever apply to
    a JSON response (see `_patch_json_object`)."""
    only_if_status = rewrite.get("only_if_status")
    if only_if_status is not None and status not in only_if_status:
        return status, body
    new_status = rewrite.get("status", status)
    flip_fields = rewrite.get("flip_false_fields") or ()
    body_patch = rewrite.get("body_patch")
    new_body = body
    if (flip_fields or body_patch) and "json" in content_type.lower():
        new_body = _patch_json_object(body, flip_fields, body_patch)
    return new_status, new_body


class RequestInterceptor:
    def __init__(self, page: "Page") -> None:
        self._page = page
        self._injections: list[Injection] = []
        self._response_injections: list[ResponseInjection] = []
        self.exchanges: list[InterceptedExchange] = []

    def inject_payload(self, pattern: str, payload: dict[str, Any]) -> None:
        """Register a payload to inject into requests whose URL matches
        `pattern` (a regex). `payload` may set `headers` (merged over
        the original request headers), `body` (raw POST data), and/or
        `url` (full URL override)."""
        self._injections.append((re.compile(pattern), payload))

    def inject_response(self, pattern: str, rewrite: dict[str, Any]) -> None:
        """Register a rewrite for RESPONSES whose URL matches `pattern`.
        `rewrite` may set `status` (override the HTTP status code --
        combine with `only_if_status` to only flip an actual denial,
        e.g. `{"only_if_status": (401, 403), "status": 200}`, so a
        broad `.*` pattern stays safe), `flip_false_fields` (a tuple of
        JSON field names to flip from `false` to `true` if present),
        and/or `body_patch` (unconditionally shallow-merged into a JSON
        body). Used to test whether an SPA trusts a denial response it
        can be shown a manipulated version of, instead of the server
        independently re-checking the real, follow-up action."""
        self._response_injections.append((re.compile(pattern), rewrite))

    async def start(self) -> None:
        await self._page.route("**/*", self._handle_route)
        self._page.on("response", self._on_response)

    async def stop(self) -> None:
        await self._page.unroute("**/*", self._handle_route)
        self._page.remove_listener("response", self._on_response)

    async def _handle_route(self, route: "Route", request: "Request") -> None:
        overrides = compute_overrides(request.url, self._injections)
        final_headers = {**request.headers, **overrides.get("headers", {})}
        final_url = overrides.get("url", request.url)
        final_body = overrides.get("post_data", request.post_data)

        self.exchanges.append(
            InterceptedExchange(
                method=request.method,
                url=final_url,
                request_headers=final_headers,
                request_body=final_body,
            )
        )

        fetch_kwargs: dict[str, Any] = {"headers": final_headers}
        if "url" in overrides:
            fetch_kwargs["url"] = overrides["url"]
        if "post_data" in overrides:
            fetch_kwargs["post_data"] = overrides["post_data"]

        rewrite = compute_response_rewrite(final_url, self._response_injections) if self._response_injections else None
        if rewrite is None:
            await route.continue_(**fetch_kwargs)
            return

        api_response = await route.fetch(**fetch_kwargs)
        body = await api_response.body()
        content_type = api_response.headers.get("content-type", "")
        new_status, new_body = apply_response_rewrite(api_response.status, content_type, body, rewrite)
        await route.fulfill(response=api_response, status=new_status, body=new_body)

    async def _on_response(self, response: "Response") -> None:
        for exchange in reversed(self.exchanges):
            if exchange.url == response.url and exchange.response_status is None:
                exchange.response_status = response.status
                exchange.response_headers = dict(response.headers)
                return
