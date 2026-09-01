"""Shared HTTP request throttle for every technique that probes a real
target through Playwright's `APIRequestContext`.

Real gap this closes: nothing anywhere in this codebase previously
capped how many requests could be in flight at once (grep-verified: no
`Semaphore`, no `max_concurrent`, no politeness delay anywhere in
`stof/modules/`, `stof/crawler/`, or `stof/core/`). A wordlist sweep, a
candidate-ID probe loop, and several vulnerability modules running
concurrently can all fire real attack traffic against the same target
at once with nothing capping it -- a realistic self-inflicted-DoS or
WAF-ban risk against a client's target, which is very often a staging
environment less resilient than production, not a load-testing
scenario this tool should ever cause by accident.

Deliberately a process-wide singleton, not per-`VulnModule`-instance
state: the cap needs to hold across every module running concurrently
within one scan (they share one `SessionPool`/browser already), not
just within one module's own requests.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, TypeVar

# Conservative default -- STOF is a security testing tool sending real
# attack payloads, not a load generator. This many concurrent in-flight
# requests keeps a scan reasonably fast without behaving like a stress
# test against a target that was never asked to withstand one.
MAX_CONCURRENT_REQUESTS = 6

_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

T = TypeVar("T")


async def throttled(awaitable: Awaitable[T]) -> T:
    """Awaits `awaitable` under the shared semaphore. `awaitable` is an
    already-constructed coroutine (e.g. `context.request.get(url)`) --
    calling an async function only builds the coroutine, it doesn't
    start the network I/O until something awaits it, so callers build
    the call as normal and this just gates *when* it's allowed to run."""
    async with _semaphore:
        return await awaitable
