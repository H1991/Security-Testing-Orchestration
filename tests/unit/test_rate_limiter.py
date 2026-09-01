"""Unit tests for stof.core.rate_limiter -- the shared request throttle
closing the "no concurrency cap anywhere" gap (see rate_limiter.py's
own module docstring for the real risk this addresses)."""
import asyncio

import pytest

from stof.core import rate_limiter


@pytest.mark.asyncio
async def test_throttled_awaits_and_returns_the_coroutines_result():
    async def work():
        return "done"

    result = await rate_limiter.throttled(work())
    assert result == "done"


@pytest.mark.asyncio
async def test_throttled_caps_concurrency_at_the_shared_limit():
    """The real behavior this module exists for: never more than
    MAX_CONCURRENT_REQUESTS calls actually running at once, regardless
    of how many are requested simultaneously."""
    limit = rate_limiter.MAX_CONCURRENT_REQUESTS
    in_flight = 0
    max_observed = 0
    lock = asyncio.Lock()

    async def work():
        nonlocal in_flight, max_observed
        async with lock:
            in_flight += 1
            max_observed = max(max_observed, in_flight)
        await asyncio.sleep(0.01)
        async with lock:
            in_flight -= 1

    await asyncio.gather(*(rate_limiter.throttled(work()) for _ in range(limit * 3)))

    assert max_observed <= limit
