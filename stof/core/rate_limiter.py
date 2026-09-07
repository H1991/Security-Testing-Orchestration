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
import time
from typing import Awaitable, TypeVar

# Conservative default -- STOF is a security testing tool sending real
# attack payloads, not a load generator. This many concurrent in-flight
# requests keeps a scan reasonably fast without behaving like a stress
# test against a target that was never asked to withstand one.
#
# Reconfigurable via `configure()` -- live-verified this session against
# a real target: a candidate-ID/wordlist sweep firing dozens of requests
# in quick succession (concurrency cap alone doesn't limit REQUESTS PER
# SECOND, only how many are in flight at once) triggered two real
# account lockouts at the concurrency-only default below. `min_interval_s`
# below closes that gap for a target that needs to be treated with more
# care than the default assumes.
MAX_CONCURRENT_REQUESTS = 6
_MIN_INTERVAL_S = 0.0

_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
_pace_lock = asyncio.Lock()
_last_request_at = 0.0

T = TypeVar("T")

# The three named presets `config.json`'s `testing.scan_intensity`
# exposes -- (max_concurrent, min_interval_s). "standard" is this
# module's own original, long-standing default, kept byte-for-byte so
# an existing config with no `scan_intensity` set behaves identically
# to before this preset system existed. "cautious" trades scan
# duration for a real, live-observed safety margin (see this module's
# own docstring); "aggressive" is for a dedicated, disposable test
# environment an operator has explicitly confirmed can take faster
# traffic -- still nowhere near an actual load-testing tool's rate.
SCAN_INTENSITY_PROFILES: dict[str, tuple[int, float]] = {
    "cautious": (3, 0.5),
    "standard": (6, 0.0),
    "aggressive": (10, 0.0),
}


def configure_from_intensity(scan_intensity: str) -> None:
    """`configure()` from a named preset instead of raw numbers --
    the one call site `main.py`'s scan entrypoint needs. Falls back to
    "standard" for an unrecognized value rather than raising, matching
    this project's own "never let an operator's scan fail to start over
    a cosmetic config mismatch" convention."""
    max_concurrent, min_interval_s = SCAN_INTENSITY_PROFILES.get(scan_intensity, SCAN_INTENSITY_PROFILES["standard"])
    configure(max_concurrent, min_interval_s)


def configure(max_concurrent: int, min_interval_s: float = 0.0) -> None:
    """Reconfigures this process-wide throttle. Called once, early, by
    the scan entrypoint (`main.py`) before any module runs -- never
    mid-scan. Safe as a single reassignment: each `stof scan`/`stof
    test` run is its own fresh subprocess (see `main.py`'s own scan-
    entrypoint docstring), so there's no concurrent scan sharing this
    module's global state to race against."""
    global _semaphore, MAX_CONCURRENT_REQUESTS, _MIN_INTERVAL_S, _last_request_at
    MAX_CONCURRENT_REQUESTS = max_concurrent
    _MIN_INTERVAL_S = min_interval_s
    _semaphore = asyncio.Semaphore(max_concurrent)
    _last_request_at = 0.0


async def _pace() -> None:
    """The politeness-delay half of the throttle: ensures at least
    `_MIN_INTERVAL_S` seconds have passed since the last request STARTED
    (across every technique/module sharing this one process-wide
    throttle), before letting this one proceed. A no-op loop iteration
    when `_MIN_INTERVAL_S` is 0 (the default) -- unchanged behavior for
    every scan that doesn't opt into a slower pace."""
    if _MIN_INTERVAL_S <= 0:
        return
    global _last_request_at
    async with _pace_lock:
        elapsed = time.monotonic() - _last_request_at
        if elapsed < _MIN_INTERVAL_S:
            await asyncio.sleep(_MIN_INTERVAL_S - elapsed)
        _last_request_at = time.monotonic()


async def throttled(awaitable: Awaitable[T]) -> T:
    """Awaits `awaitable` under the shared semaphore (and, if configured,
    the shared politeness delay). `awaitable` is an already-constructed
    coroutine (e.g. `context.request.get(url)`) -- calling an async
    function only builds the coroutine, it doesn't start the network I/O
    until something awaits it, so callers build the call as normal and
    this just gates *when* it's allowed to run."""
    async with _semaphore:
        await _pace()
        return await awaitable
