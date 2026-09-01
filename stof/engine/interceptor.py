"""Layer 3B — request/response interception and payload injection.

Registers `page.route()` / `page.on("response")` handlers. Vulnerability
modules never manipulate the page directly for this — they call
`RequestInterceptor.inject_payload(pattern, payload)` and this module
handles applying it to matching in-flight requests.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from playwright.async_api import Page, Request, Response, Route

_log = get_logger("engine.interceptor")

Injection = tuple[re.Pattern[str], dict[str, Any]]


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


class RequestInterceptor:
    def __init__(self, page: "Page") -> None:
        self._page = page
        self._injections: list[Injection] = []
        self.exchanges: list[InterceptedExchange] = []

    def inject_payload(self, pattern: str, payload: dict[str, Any]) -> None:
        """Register a payload to inject into requests whose URL matches
        `pattern` (a regex). `payload` may set `headers` (merged over
        the original request headers), `body` (raw POST data), and/or
        `url` (full URL override)."""
        self._injections.append((re.compile(pattern), payload))

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

        kwargs: dict[str, Any] = {"headers": final_headers}
        if "url" in overrides:
            kwargs["url"] = overrides["url"]
        if "post_data" in overrides:
            kwargs["post_data"] = overrides["post_data"]
        await route.continue_(**kwargs)

    async def _on_response(self, response: "Response") -> None:
        for exchange in reversed(self.exchanges):
            if exchange.url == response.url and exchange.response_status is None:
                exchange.response_status = response.status
                exchange.response_headers = dict(response.headers)
                return
