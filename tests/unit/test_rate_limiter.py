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


# ---------------------------------------------------------------------------
# configure() -- reconfigurable concurrency cap + politeness delay
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_default_throttle():
    """Every test in this module runs under the SAME process-wide
    global state `configure()` mutates -- reset it to this module's own
    original defaults after each test so a test that opts into a slower
    pace can't silently leave later tests (in this file or another)
    running against a throttle they never asked for."""
    yield
    rate_limiter.configure(6, 0.0)


@pytest.mark.asyncio
async def test_configure_changes_the_concurrency_cap():
    rate_limiter.configure(2, 0.0)

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

    await asyncio.gather(*(rate_limiter.throttled(work()) for _ in range(6)))

    assert max_observed <= 2


@pytest.mark.asyncio
async def test_configure_zero_interval_adds_no_delay():
    rate_limiter.configure(6, 0.0)

    start = asyncio.get_event_loop().time()
    await rate_limiter.throttled(asyncio.sleep(0))
    await rate_limiter.throttled(asyncio.sleep(0))
    elapsed = asyncio.get_event_loop().time() - start

    assert elapsed < 0.05  # no artificial pacing when min_interval_s is 0


@pytest.mark.asyncio
async def test_configure_positive_interval_paces_sequential_requests():
    rate_limiter.configure(6, 0.1)

    start = asyncio.get_event_loop().time()
    await rate_limiter.throttled(asyncio.sleep(0))
    await rate_limiter.throttled(asyncio.sleep(0))
    elapsed = asyncio.get_event_loop().time() - start

    assert elapsed >= 0.1  # the second call had to wait out the pace interval


# ---------------------------------------------------------------------------
# configure_from_intensity() -- the named-preset resolver config.json's
# testing.scan_intensity actually drives
# ---------------------------------------------------------------------------


def test_configure_from_intensity_standard_matches_the_original_default():
    rate_limiter.configure_from_intensity("standard")
    assert rate_limiter.MAX_CONCURRENT_REQUESTS == 6
    assert rate_limiter._MIN_INTERVAL_S == 0.0


def test_configure_from_intensity_cautious_lowers_concurrency_and_adds_pacing():
    rate_limiter.configure_from_intensity("cautious")
    assert rate_limiter.MAX_CONCURRENT_REQUESTS < 6
    assert rate_limiter._MIN_INTERVAL_S > 0.0


def test_configure_from_intensity_aggressive_raises_concurrency():
    rate_limiter.configure_from_intensity("aggressive")
    assert rate_limiter.MAX_CONCURRENT_REQUESTS > 6


def test_configure_from_intensity_unknown_value_falls_back_to_standard():
    rate_limiter.configure_from_intensity("not-a-real-preset")
    assert rate_limiter.MAX_CONCURRENT_REQUESTS == 6
    assert rate_limiter._MIN_INTERVAL_S == 0.0
