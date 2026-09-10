"""Unit tests for Layer 9 -- stof.modules.mfa_tests (TC-140)."""
from unittest.mock import AsyncMock, MagicMock

import pyotp
import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.mfa_tests import MfaTestConfig, MfaTestsModule
from stof.modules.results import FAIL, PASS, SKIPPED

LOGIN_URL = "https://x.example/login"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def _config(**overrides) -> MfaTestConfig:
    base = dict(
        login_url=LOGIN_URL, test_role="normal", test_username="user@x.example",
        test_password="pw", totp_secret=TOTP_SECRET,
    )
    base.update(overrides)
    return MfaTestConfig(**base)


def _mock_page(found_selectors: set[str], click_navigates_to: dict[str, str] | None = None) -> AsyncMock:
    """A fake Playwright `Page`. `found_selectors` controls which
    generic candidate selectors `page.locator(sel).count()` reports as
    present -- the same shape `test_form_login.py`'s own
    `_page_with_selective_locator` uses, since this module's
    `_find_selector` is the same "poll each candidate" logic.
    `click_navigates_to` maps a selector to the URL `page.url` should
    report AFTER that selector is clicked (simulating a real page
    navigating on submit) -- absent means clicking that selector
    doesn't change `page.url`."""
    page = AsyncMock()
    page.url = LOGIN_URL
    page.goto = AsyncMock()

    def _locator(selector):
        loc = AsyncMock()
        loc.count = AsyncMock(return_value=1 if selector in found_selectors else 0)
        return loc

    page.locator = MagicMock(side_effect=_locator)

    async def _click(selector, *args, **kwargs):
        if click_navigates_to and selector in click_navigates_to:
            page.url = click_navigates_to[selector]

    page.click = AsyncMock(side_effect=_click)
    page.fill = AsyncMock()
    page.wait_for_timeout = AsyncMock()
    page.close = AsyncMock()
    page.on = MagicMock()
    page.remove_listener = MagicMock()
    page.route = AsyncMock()
    page.unroute = AsyncMock()
    return page


def _pool_returning(pages: list[AsyncMock], context_extra: AsyncMock | None = None) -> SessionPool:
    """A `SessionPool` whose `new_anonymous_context()` returns one
    fresh mock `BrowserContext` per call, and whose `context.new_page()`
    yields pages from `pages` in order -- each technique opens 1+ fresh
    pages, so tests hand this exactly as many as the technique under
    test will request."""
    pages_iter = iter(pages)

    async def _new_context(**kwargs):
        context = context_extra or AsyncMock()
        context.new_page = AsyncMock(side_effect=lambda: next(pages_iter))
        context.close = AsyncMock()
        return context

    browser = AsyncMock()
    browser.new_context = AsyncMock(side_effect=_new_context)
    return SessionPool(browser)


# ---------------------------------------------------------------------------
# Shared precondition (_ready / SKIPPED for every technique)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_technique_skips_when_no_totp_secret_configured():
    module = MfaTestsModule(config=_config(totp_secret=None))
    results = await module.run_techniques([], session_manager=None, session_pool=None)
    assert len(results) == 5
    assert all(r.status == SKIPPED for r in results)
    assert all("TOTP secret" in r.detail for r in results)


@pytest.mark.asyncio
async def test_every_technique_skips_when_login_url_missing():
    module = MfaTestsModule(config=_config(login_url=None))
    results = await module.run_techniques([], session_manager=None, session_pool=None)
    assert all(r.status == SKIPPED for r in results)


# ---------------------------------------------------------------------------
# TC-140.1 -- pre-MFA session/endpoint access
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pre_mfa_access_skips_with_no_auth_required_endpoint():
    module = MfaTestsModule(config=_config())
    pool = _pool_returning([])
    result = await module._technique_pre_mfa_access([], pool)
    assert result.status == SKIPPED


@pytest.mark.asyncio
async def test_pre_mfa_access_fails_when_protected_endpoint_reachable_before_otp():
    endpoints = [Endpoint(url="https://x.example/api/orders", method="GET", endpoint_type="api", auth_required=True)]
    page = _mock_page(found_selectors={"input[type='email']", "input[type='password']", "button[type='submit']"})
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=AsyncMock(status=200, text=AsyncMock(return_value="x" * 200)))
    pool = _pool_returning([page], context_extra=context)

    result = await MfaTestsModule(config=_config())._technique_pre_mfa_access(endpoints, pool)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "Critical"


@pytest.mark.asyncio
async def test_pre_mfa_access_passes_when_protected_endpoint_rejects_pre_mfa_session():
    endpoints = [Endpoint(url="https://x.example/api/orders", method="GET", endpoint_type="api", auth_required=True)]
    page = _mock_page(found_selectors={"input[type='email']", "input[type='password']", "button[type='submit']"})
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=AsyncMock(status=401, text=AsyncMock(return_value="unauthorized")))
    pool = _pool_returning([page], context_extra=context)

    result = await MfaTestsModule(config=_config())._technique_pre_mfa_access(endpoints, pool)

    assert result.status == PASS


# ---------------------------------------------------------------------------
# TC-140.2 -- OTP verification response manipulation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_response_manipulation_skips_when_no_otp_field_appears():
    page = _mock_page(found_selectors={"input[type='email']", "input[type='password']", "button[type='submit']"})
    pool = _pool_returning([page])

    result = await MfaTestsModule(config=_config())._technique_response_manipulation(pool, evidence=None)

    assert result.status == SKIPPED


@pytest.mark.asyncio
async def test_response_manipulation_fails_when_client_proceeds_past_mfa_after_tampering():
    """Registering the route interceptor and the client landing on a
    non-login/non-2FA URL afterward is the observable signal this
    technique reports on -- the actual `route.fetch()`/`fulfill()`
    plumbing only matters against a real browser/server, so this test
    (like every other technique's test in this file) asserts on the
    outcome contract, not on internal `page.route` mechanics."""
    found = {"input[type='email']", "input[type='password']", "button[type='submit']", "input[name='code']"}
    submit_sel = "button[type='submit']"
    page = _mock_page(found, click_navigates_to={submit_sel: "https://x.example/dashboard"})
    pool = _pool_returning([page])

    result = await MfaTestsModule(config=_config())._technique_response_manipulation(pool, evidence=None)

    assert result.status == FAIL
    assert result.finding.vuln_type == "MFA Bypass (Client-Trusted Response)"
    page.route.assert_awaited_once()
    page.unroute.assert_awaited_once()


@pytest.mark.asyncio
async def test_response_manipulation_passes_when_client_stays_on_mfa_step():
    found = {"input[type='email']", "input[type='password']", "button[type='submit']", "input[name='code']"}
    page = _mock_page(found)  # click never navigates -- app correctly ignored the tampered response
    pool = _pool_returning([page])

    result = await MfaTestsModule(config=_config())._technique_response_manipulation(pool, evidence=None)

    assert result.status == PASS


# ---------------------------------------------------------------------------
# TC-140.3 -- OTP brute-force / missing rate limiting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_brute_force_fails_when_no_throttling_signal_appears():
    found = {"input[type='email']", "input[type='password']", "button[type='submit']", "input[name='code']"}
    pages = [_mock_page(found) for _ in range(1 + 8)]  # 1 for the initial OTP-field probe, 8 for the attempts

    for page in pages[1:]:
        original_click = page.click

        async def _click_and_fire_response(selector, *a, _page=page, _orig=original_click, **kw):
            await _orig(selector, *a, **kw)
            for call in _page.on.call_args_list:
                if call.args[0] == "response":
                    handler = call.args[1]
                    fake_response = AsyncMock()
                    fake_response.request.method = "POST"
                    fake_response.status = 401
                    fake_response.text = AsyncMock(return_value='{"error":"invalid code"}')
                    await handler(fake_response)

        page.click = AsyncMock(side_effect=_click_and_fire_response)

    pool = _pool_returning(pages)
    result = await MfaTestsModule(config=_config())._technique_brute_force(pool)

    assert result.status == FAIL
    assert result.finding.vuln_type == "Missing MFA Rate Limiting"


@pytest.mark.asyncio
async def test_brute_force_passes_when_rate_limit_status_appears():
    found = {"input[type='email']", "input[type='password']", "button[type='submit']", "input[name='code']"}
    pages = [_mock_page(found) for _ in range(1 + 8)]

    for i, page in enumerate(pages[1:]):
        original_click = page.click
        status_to_fire = 429 if i == 2 else 401

        async def _click_and_fire_response(selector, *a, _page=page, _orig=original_click, _status=status_to_fire, **kw):
            await _orig(selector, *a, **kw)
            for call in _page.on.call_args_list:
                if call.args[0] == "response":
                    handler = call.args[1]
                    fake_response = AsyncMock()
                    fake_response.request.method = "POST"
                    fake_response.status = _status
                    fake_response.text = AsyncMock(return_value="too many attempts")
                    await handler(fake_response)

        page.click = AsyncMock(side_effect=_click_and_fire_response)

    pool = _pool_returning(pages)
    result = await MfaTestsModule(config=_config())._technique_brute_force(pool)

    assert result.status == PASS


# ---------------------------------------------------------------------------
# TC-140.4 -- OTP replay
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_otp_replay_fails_when_same_valid_code_accepted_twice():
    found = {"input[type='email']", "input[type='password']", "button[type='submit']", "input[name='code']"}
    submit_sel = "button[type='submit']"
    success_url = "https://x.example/dashboard"
    pages = [
        _mock_page(found, click_navigates_to={submit_sel: success_url}),
        _mock_page(found, click_navigates_to={submit_sel: success_url}),
    ]
    pool = _pool_returning(pages)

    result = await MfaTestsModule(config=_config())._technique_otp_replay(pool)

    assert result.status == FAIL
    assert result.finding.vuln_type == "MFA OTP Replay"


@pytest.mark.asyncio
async def test_otp_replay_passes_when_second_use_is_rejected():
    found = {"input[type='email']", "input[type='password']", "button[type='submit']", "input[name='code']"}
    submit_sel = "button[type='submit']"
    success_url = "https://x.example/dashboard"
    first_page = _mock_page(found, click_navigates_to={submit_sel: success_url})
    second_page = _mock_page(found)  # click never navigates -- stays on the login/OTP page
    pool = _pool_returning([first_page, second_page])

    result = await MfaTestsModule(config=_config())._technique_otp_replay(pool)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_otp_replay_skips_when_the_generated_code_is_never_even_accepted_once():
    found = {"input[type='email']", "input[type='password']", "button[type='submit']", "input[name='code']"}
    page = _mock_page(found)  # click never navigates anywhere
    pool = _pool_returning([page])

    result = await MfaTestsModule(config=_config())._technique_otp_replay(pool)

    assert result.status == SKIPPED


# ---------------------------------------------------------------------------
# TC-140.5 -- static/weak code acceptance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_static_code_fails_when_a_weak_code_is_accepted():
    found = {"input[type='email']", "input[type='password']", "button[type='submit']", "input[name='code']"}
    submit_sel = "button[type='submit']"
    page = _mock_page(found, click_navigates_to={submit_sel: "https://x.example/dashboard"})
    pool = _pool_returning([page])

    result = await MfaTestsModule(config=_config())._technique_static_code(pool)

    assert result.status == FAIL
    assert result.finding.severity == "Critical"


@pytest.mark.asyncio
async def test_static_code_passes_when_no_weak_code_is_ever_accepted():
    found = {"input[type='email']", "input[type='password']", "button[type='submit']", "input[name='code']"}
    page = _mock_page(found)  # never navigates -- every weak code correctly rejected
    pool = _pool_returning([page])

    result = await MfaTestsModule(config=_config())._technique_static_code(pool)

    assert result.status == PASS


# ---------------------------------------------------------------------------
# Real RFC 6238 math sanity check -- proves the module computes a real,
# currently-valid code rather than a placeholder, same convention
# test_form_login.py's own TOTP test uses.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_otp_replay_uses_a_real_currently_valid_totp_code():
    found = {"input[type='email']", "input[type='password']", "button[type='submit']", "input[name='code']"}
    page = _mock_page(found)
    pool = _pool_returning([page])

    await MfaTestsModule(config=_config())._technique_otp_replay(pool)

    expected_code = pyotp.TOTP(TOTP_SECRET).now()
    filled_values = {call.args[1] for call in page.fill.await_args_list}
    assert expected_code in filled_values
