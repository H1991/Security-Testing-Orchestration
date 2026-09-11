"""Layer 3B — transparent scope/audit/rate-limit wrapper around a
Playwright `BrowserContext`'s own `.request` API.

Every `VulnModule` and crawler function receives its `BrowserContext`
from `stof.engine.multi_session.SessionPool` -- never launches its own
(see CLAUDE.md's Layer 3B rules). That makes `SessionPool` the one
choke point where every module's real HTTP traffic already funnels
through, whether or not the module itself remembers to call
`core.rate_limiter.throttled()`. `GuardedBrowserContext` is what
`SessionPool` hands back instead of the raw context once a
`stof.core.traffic_guard.TrafficGuard` is configured for the scan: it
looks and behaves exactly like a normal `BrowserContext` for everything
a module already does with one (`__getattr__` delegates every
unrecognized attribute straight to the real object), except its
`.request.get/post/put/delete/patch/head` calls are scope-checked,
throttled, and audit-logged before the real Playwright call is ever
made.

`GuardedRequestContext` deliberately does NOT wrap `.fetch()` --
grep-verified nothing in `stof/modules/` or `stof/crawler/` calls
`APIRequestContext.fetch()` today (the codebase's only `.fetch()` use
is `Route.fetch()` in `engine/interceptor.py`, an unrelated Playwright
API already covered by that module's own request/response interception
for workflow replay). `__getattr__` still forwards it to the real
object if some future module does start calling it, so nothing breaks
-- it just isn't scope/audit-covered until a real caller shows up to
write a test against.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from stof.core.rate_limiter import throttled
from stof.core.traffic_guard import TrafficGuard

if TYPE_CHECKING:
    from playwright.async_api import APIRequestContext, APIResponse, BrowserContext

_GUARDED_METHODS = ("get", "post", "put", "delete", "patch", "head")


class GuardedRequestContext:
    def __init__(self, real: "APIRequestContext", guard: TrafficGuard, role: str | None) -> None:
        self._real = real
        self._guard = guard
        self._role = role

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    async def get(self, url: str, **kwargs: Any) -> "APIResponse":
        return await self._issue("GET", self._real.get, url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> "APIResponse":
        return await self._issue("POST", self._real.post, url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> "APIResponse":
        return await self._issue("PUT", self._real.put, url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> "APIResponse":
        return await self._issue("DELETE", self._real.delete, url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> "APIResponse":
        return await self._issue("PATCH", self._real.patch, url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> "APIResponse":
        return await self._issue("HEAD", self._real.head, url, **kwargs)

    def _request_body(self, kwargs: dict[str, Any]) -> str | None:
        for key in ("data", "form", "multipart"):
            if key in kwargs and kwargs[key] is not None:
                return str(kwargs[key])
        return None

    async def _record_response(self, method: str, url: str, kwargs: dict[str, Any], started: float, response: "APIResponse | None", error: str | None) -> None:
        latency_ms = (time.monotonic() - started) * 1000
        response_status: int | None = None
        response_headers: dict[str, str] = {}
        response_body_len: int | None = None
        if response is not None:
            response_status = response.status
            response_headers = dict(response.headers)
            try:
                response_body_len = len(await response.body())
            except Exception:
                response_body_len = None  # best-effort only -- never worth failing the scan over
        entry = self._guard.build_entry(
            method=method, url=url, role=self._role,
            request_headers=kwargs.get("headers"), request_body=self._request_body(kwargs),
            response_status=response_status, response_headers=response_headers,
            response_body_len=response_body_len, latency_ms=latency_ms, error=error,
        )
        self._guard.record(entry)

    async def _issue(self, method: str, real_method: Any, url: str, **kwargs: Any) -> "APIResponse":
        self._guard.check_scope(url)
        started = time.monotonic()
        response: "APIResponse | None" = None
        error: str | None = None
        try:
            response = await throttled(real_method(url, **kwargs))
            return response
        except Exception as exc:
            error = str(exc)
            raise
        finally:
            await self._record_response(method, url, kwargs, started, response, error)


class GuardedBrowserContext:
    def __init__(self, real: "BrowserContext", guard: TrafficGuard, role: str | None = None) -> None:
        self._real = real
        self.request = GuardedRequestContext(real.request, guard, role)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)
