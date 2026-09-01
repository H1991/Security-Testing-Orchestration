"""Layer 3C — Burp Controller: real Burp Suite Professional REST API
integration.

Built at explicit user instruction, ahead of CLAUDE.md's own documented
Phase 2 schedule for this file (same precedent as Layer 8's early
build) -- flagged here exactly as clearly.

**Live-verified** against a real Burp Suite Professional 2021.7.1
instance on `http://127.0.0.1:1337`. The original assumption (below,
kept for history) was that the `Location` header on scan creation
would be a path like `/v0.1/scan/1`. Against the real instance it is
just the bare task id (e.g. `"4"`) -- `_scan_status_url()` handles
both forms.

REST API shape (Burp Suite Professional's built-in REST API, not the
older standalone extension):
    POST {base_url}/{api_key}/v0.1/scan            -> starts a scan,
        201 response with a `Location` header holding the task id
        (e.g. "4"), not a path.
    GET  {base_url}/{api_key}/v0.1/scan/{task_id}    -> poll status;
        `{"scan_status": "running"|"succeeded"|"failed", ...,
          "issue_events": [{"issue": {...}}, ...]}` once progressing

Each issue's `evidence` entries carry base64-encoded request/response
bodies -- decoded here into `Finding.request_raw`/`response_raw` by
Layer 11's `findings/burp_normalizer.py`, which consumes this
controller's raw issue dicts (kept as plain dicts here, deliberately,
so the normalizer -- not this transport-layer module -- owns the
Burp-issue-to-Finding mapping).
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from playwright.async_api import APIRequestContext, Playwright

_log = get_logger("engine.burp_controller")


class BurpApiError(Exception):
    """Burp's REST API responded, but with an error status or a shape
    this controller couldn't make sense of."""


class BurpController:
    def __init__(
        self,
        request_context: "APIRequestContext",
        base_url: str,
        api_key: str,
        poll_interval_s: int = 5,
        timeout_s: int = 600,
    ) -> None:
        self._request_context = request_context
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._poll_interval_s = poll_interval_s
        self._timeout_s = timeout_s

    @classmethod
    async def create(
        cls,
        playwright: "Playwright",
        base_url: str,
        api_key: str,
        poll_interval_s: int = 5,
        timeout_s: int = 600,
    ) -> "BurpController":
        """Standalone `APIRequestContext` -- Burp's REST API needs no
        cookies/browser session, so this deliberately doesn't reuse
        `SessionPool`'s per-role browser contexts (Layer 3B); it's a
        separate, lightweight HTTP client the same way `SessionPool.
        launch()` is a separate browser."""
        request_context = await playwright.request.new_context()
        return cls(request_context, base_url, api_key, poll_interval_s, timeout_s)

    async def close(self) -> None:
        await self._request_context.dispose()

    def _url(self, path: str) -> str:
        return f"{self._base_url}/{self._api_key}{path}"

    def _scan_status_url(self, task_location: str) -> str:
        """`task_location` is whatever `start_scan` returned: the real
        Burp REST API puts a bare task id (e.g. "4") in the `Location`
        header, not a path -- but this also accepts a full path or URL
        in case a different Burp version emits one."""
        if task_location.startswith("http"):
            return task_location
        if "/v0.1/scan" in task_location:
            return f"{self._base_url}{task_location}"
        return self._url(f"/v0.1/scan/{task_location.lstrip('/')}")

    async def start_scan(self, urls: list[str], scope_prefixes: list[str] | None = None) -> str:
        """Starts a Burp Active Scan against `urls`. Returns the task's
        location path (relative, e.g. "/v0.1/scan/1") for polling."""
        payload: dict[str, Any] = {"urls": urls}
        if scope_prefixes:
            payload["scope"] = {"include": [{"rule": prefix} for prefix in scope_prefixes]}

        resp = await self._request_context.post(self._url("/v0.1/scan"), data=payload)
        if resp.status not in (200, 201, 202):
            body = await resp.text()
            raise BurpApiError(f"Burp scan start failed: HTTP {resp.status} -- {body[:500]}")

        location = resp.headers.get("location")
        if not location:
            raise BurpApiError("Burp did not return a Location header for the new scan task")
        _log.info(f"started Burp active scan for {len(urls)} URL(s) -> task {location}")
        return location

    async def get_scan_status(self, task_location: str) -> dict[str, Any]:
        url = self._scan_status_url(task_location)
        resp = await self._request_context.get(url)
        if resp.status != 200:
            body = await resp.text()
            raise BurpApiError(f"Burp scan status check failed: HTTP {resp.status} -- {body[:500]}")
        return await resp.json()

    async def wait_for_completion(self, task_location: str, allow_partial: bool = False) -> dict[str, Any]:
        """Polls until Burp reports "succeeded"/"failed", or `timeout_s`
        elapses.

        A full unauthenticated crawl+audit of a real site routinely
        takes far longer than a short demo timeout -- `allow_partial`
        (used by `run_active_scan`) makes a timeout non-fatal: instead
        of raising and discarding every issue Burp had already found,
        it returns the last polled status as-is (whatever `issue_events`
        it carries). Direct callers that need the strict "did this
        actually finish" guarantee keep the default `False` behavior.
        """
        elapsed = 0
        last_result: dict[str, Any] = {"scan_status": "unknown", "issue_events": []}
        while elapsed < self._timeout_s:
            last_result = await self.get_scan_status(task_location)
            last_status = last_result.get("scan_status", "unknown")
            if last_status in ("succeeded", "failed"):
                _log.info(f"Burp scan {task_location} finished with status '{last_status}'")
                return last_result
            await asyncio.sleep(self._poll_interval_s)
            elapsed += self._poll_interval_s

        last_status = last_result.get("scan_status", "unknown")
        if allow_partial:
            _log.warning(
                f"Burp scan {task_location} did not complete within {self._timeout_s}s "
                f"(last status: '{last_status}') -- returning "
                f"{len(last_result.get('issue_events', []))} issue(s) found so far"
            )
            return last_result
        raise TimeoutError(
            f"Burp scan {task_location} did not complete within {self._timeout_s}s "
            f"(last status: '{last_status}')"
        )

    async def run_active_scan(self, urls: list[str], scope_prefixes: list[str] | None = None) -> list[dict[str, Any]]:
        """Starts a scan, waits for it to finish, and returns the raw
        list of Burp issue dicts. Callers pass these straight to Layer
        11's `findings.burp_normalizer.normalize_burp_issues()`.

        Uses `allow_partial=True`: a scan still running when `timeout_s`
        elapses returns whatever issues Burp had already reported rather
        than raising and losing them."""
        task_location = await self.start_scan(urls, scope_prefixes)
        result = await self.wait_for_completion(task_location, allow_partial=True)
        issues = [event["issue"] for event in result.get("issue_events", []) if "issue" in event]
        _log.info(f"Burp active scan returned {len(issues)} issue(s)")
        return issues
