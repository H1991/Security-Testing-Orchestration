"""Unit tests for Layer 4 — stof.auth.form_login."""
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from stof.auth.base import AuthExpiredError, AuthFailedError
from stof.auth.form_login import DEFAULT_SESSION_LIFETIME, FormLoginProvider, _dismiss_overlays
from stof.config.schema import UserConfig

LOGIN_URL = "https://demo.testfire.net/login.jsp"


def _user(auth_type: str = "form_login") -> UserConfig:
    return UserConfig(
        id="admin-01",
        role="admin",
        username="admin",
        password="s3cr3t",
        auth_type=auth_type,
    )


def _page(url: str, cookies: list[dict] | None = None, storage_token: str | None = None) -> AsyncMock:
    page = AsyncMock()
    page.url = url
    page.context.cookies = AsyncMock(return_value=cookies or [])
    # `_first_matching()` probes `page.locator(selector).count()` --
    # these tests only ever configure exactly-matching selectors, so a
    # fixed "found" count is all the mock needs to provide.
    locator = AsyncMock()
    locator.count = AsyncMock(return_value=1)
    page.locator = MagicMock(return_value=locator)
    # `_form_scope_selector()` calls this to find the password field's
    # <form> ancestor -- these generic tests don't model real DOM
    # structure, so it degrades to "no form found," matching this
    # module's pre-scoping behavior exactly (page-wide candidates only).
    page.eval_on_selector = AsyncMock(return_value=None)
    # `extract_storage_token()` calls `page.evaluate(...)` -- default to
    # "nothing in storage" (a bare AsyncMock would otherwise return a
    # truthy Mock object here, silently faking a bearer token on every
    # existing cookie-based test in this file).
    page.evaluate = AsyncMock(return_value=storage_token)
    return page


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_with_success_selector_captures_cookies():
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="#uid",
        password_selector="#passw",
        submit_selector="#login-btn",
        success_selector="text=Welcome",
    )
    page = _page("https://demo.testfire.net/bank/main.jsp", cookies=[{"name": "JSESSIONID", "value": "abc"}])

    session = await provider.authenticate(_user(), page)

    assert session.user_id == "admin-01"
    assert session.role == "admin"
    assert session.auth_type == "form_login"
    assert session.cookies == {"JSESSIONID": "abc"}
    page.goto.assert_awaited_once_with(LOGIN_URL)
    page.fill.assert_any_await("#uid", "admin")
    page.fill.assert_any_await("#passw", "s3cr3t")
    page.wait_for_selector.assert_any_await("#passw", timeout=20000, state="attached")
    page.wait_for_selector.assert_any_await("text=Welcome", timeout=20000)


@pytest.mark.asyncio
async def test_authenticate_sets_a_real_expiry_not_none():
    """Regression: a form_login session used to get `expires_at=None`,
    which Layer 5's `needs_refresh()` treats as "never expires" --
    confirmed live, this let `stof test` silently keep reusing an
    hours-old, server-side-expired session forever, returning 0
    findings with no error at all. See module docstring."""
    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#login-btn",
    )
    page = _page("https://demo.testfire.net/bank/main.jsp")

    before = datetime.now(timezone.utc)
    session = await provider.authenticate(_user(), page)
    after = datetime.now(timezone.utc)

    assert session.expires_at is not None
    assert before + DEFAULT_SESSION_LIFETIME <= session.expires_at <= after + DEFAULT_SESSION_LIFETIME


@pytest.mark.asyncio
async def test_authenticate_respects_custom_session_lifetime():
    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#login-btn",
        session_lifetime=timedelta(minutes=1),
    )
    page = _page("https://demo.testfire.net/bank/main.jsp")

    session = await provider.authenticate(_user(), page)

    assert session.expires_at <= datetime.now(timezone.utc) + timedelta(minutes=1, seconds=5)


@pytest.mark.asyncio
async def test_authenticate_without_success_selector_uses_url_change_fallback():
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="#uid",
        password_selector="#passw",
        submit_selector="#login-btn",
    )
    page = _page("https://demo.testfire.net/bank/main.jsp")

    session = await provider.authenticate(_user(), page)

    assert session.auth_type == "form_login"
    page.wait_for_url.assert_awaited_once()


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_waits_for_password_field_before_probing():
    """Regression: a client-rendered SPA can still be mounting its login
    form after `page.goto()`'s 'load' event fires -- probing for the
    password field immediately used to race the page and fail with
    a spurious AuthFailedError even though the field appears moments
    later. `authenticate()` must wait for it first."""
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="#uid",
        password_selector="#passw",
        submit_selector="#login-btn",
    )
    page = _page(LOGIN_URL.rstrip(".jsp") + "/dashboard")
    # wait_for_selector succeeding here is what stands in for "the SPA
    # finished rendering the form" -- the subsequent _first_matching()
    # calls still rely on page.locator(...).count(), already stubbed
    # to "found" by _page().
    page.wait_for_selector = AsyncMock(return_value=None)

    await provider.authenticate(_user(), page)

    page.wait_for_selector.assert_any_await("#passw", timeout=20000, state="attached")


@pytest.mark.asyncio
async def test_authenticate_raises_when_success_selector_never_appears():
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="#uid",
        password_selector="#passw",
        submit_selector="#login-btn",
        success_selector="text=Welcome",
    )
    page = _page(LOGIN_URL)
    page.wait_for_selector = AsyncMock(side_effect=TimeoutError("timed out"))

    with pytest.raises(AuthFailedError, match="login could not be confirmed"):
        await provider.authenticate(_user(), page)


@pytest.mark.asyncio
async def test_authenticate_raises_when_still_on_login_page_with_no_selector_configured():
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="#uid",
        password_selector="#passw",
        submit_selector="#login-btn",
    )
    page = _page(LOGIN_URL)  # bounced back to the same login page
    page.wait_for_url = AsyncMock(side_effect=TimeoutError("timed out"))

    with pytest.raises(AuthFailedError, match="still on the login page"):
        await provider.authenticate(_user(), page)


@pytest.mark.asyncio
async def test_authenticate_retries_once_and_succeeds_after_a_transient_rejection():
    """Regression: a real SPA sometimes rejects fully correct
    credentials on the first submit (an async init race, most likely a
    CSRF/nonce fetch not yet resolved) and accepts them cleanly on a
    second, freshly-reloaded attempt. authenticate() must not give up
    after just one try."""
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="#uid",
        password_selector="#passw",
        submit_selector="#login-btn",
    )
    page = _page("https://demo.testfire.net/bank/main.jsp")
    page.wait_for_url = AsyncMock(side_effect=[TimeoutError("timed out"), None])

    session = await provider.authenticate(_user(), page)

    assert session.auth_type == "form_login"
    assert page.wait_for_url.await_count == 2
    assert page.goto.await_count == 2  # initial navigate + one retry reload


@pytest.mark.asyncio
async def test_authenticate_retries_click_with_force_when_intercepted():
    """A persistent decorative overlay (e.g. a corner ribbon link,
    confirmed live) can occupy the submit button's bounding box
    without visually covering it -- Playwright's normal click
    correctly refuses to click through it. The provider must retry
    with force=True rather than giving up."""
    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#email", password_selector="#password", submit_selector="#loginButton",
    )
    page = _page("https://x/after-login")
    page.click = AsyncMock(side_effect=[TimeoutError("intercepted by overlay"), None])

    await provider.authenticate(_user(), page)

    assert page.click.await_count == 2
    page.click.assert_awaited_with("#loginButton", force=True)


@pytest.mark.asyncio
async def test_authenticate_tries_candidate_selectors_in_order():
    """A target with no explicit TargetConfig selectors gets a
    candidate list -- the provider must pick whichever one the live
    page actually has, not assume the first is always right."""
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector=["#username", "#email"],
        password_selector="#password",
        submit_selector="#loginButton",
    )
    page = _page("https://x/after-login")

    def _locator(selector: str):
        locator = AsyncMock()
        locator.count = AsyncMock(return_value=0 if selector == "#username" else 1)
        return locator

    page.locator = MagicMock(side_effect=_locator)

    await provider.authenticate(_user(), page)

    page.fill.assert_any_await("#email", "admin")


@pytest.mark.asyncio
async def test_authenticate_raises_when_no_candidate_selector_matches():
    """The password field is located FIRST (it anchors form-scoping --
    see `_form_scope_selector()`), so when nothing on the page matches
    anything at all, that's the field the failure is reported against."""
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector=["#username", "#email"],
        password_selector="#password",
        submit_selector="#loginButton",
    )
    page = _page(LOGIN_URL)
    no_match = AsyncMock()
    no_match.count = AsyncMock(return_value=0)
    page.locator = MagicMock(return_value=no_match)

    with pytest.raises(AuthFailedError, match="password"):
        await provider.authenticate(_user(), page)


# ---------------------------------------------------------------------------
# Form-scoped candidate matching (multi-form false-match fix)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_prefers_form_scoped_candidate_over_page_wide_match():
    """A page with a header search box (also `input[type='text']`)
    AND a real login form: the password field anchors a form-scope
    selector, and the scoped username candidate must win over the
    generic page-wide one that would otherwise match the search box."""
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="input[type='text']",
        password_selector="#password",
        submit_selector="#loginButton",
    )
    page = _page("https://x/after-login")
    page.eval_on_selector = AsyncMock(return_value='[data-stof-scope="stof-scope-abc123"]')

    def _locator(selector: str):
        locator = AsyncMock()
        # The unscoped password lookup (run first, before scoping is
        # even computed) and the form-scoped username candidate match;
        # the bare page-wide username candidate (what pre-scoping code
        # would have used, and would wrongly hit the search box) does not.
        matches = selector == "#password" or selector.startswith("[data-stof-scope")
        locator.count = AsyncMock(return_value=1 if matches else 0)
        return locator

    page.locator = MagicMock(side_effect=_locator)

    await provider.authenticate(_user(), page)

    page.fill.assert_any_await('[data-stof-scope="stof-scope-abc123"] input[type=\'text\']', "admin")


@pytest.mark.asyncio
async def test_authenticate_falls_back_to_page_wide_when_scoped_candidate_absent():
    """A form ancestor exists, but the username field happens to sit
    OUTSIDE it (an unusual but real SPA pattern) -- the scoped
    candidate finds nothing, so the page-wide candidate must still be
    tried rather than failing outright."""
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="#username",
        password_selector="#password",
        submit_selector="#loginButton",
    )
    page = _page("https://x/after-login")
    page.eval_on_selector = AsyncMock(return_value='[data-stof-scope="stof-scope-xyz789"]')

    def _locator(selector: str):
        locator = AsyncMock()
        locator.count = AsyncMock(return_value=0 if selector.startswith("[data-stof-scope") else 1)
        return locator

    page.locator = MagicMock(side_effect=_locator)

    await provider.authenticate(_user(), page)

    page.fill.assert_any_await("#username", "admin")


@pytest.mark.asyncio
async def test_authenticate_unscoped_when_password_field_has_no_form_ancestor():
    """`eval_on_selector` returning None (no <form> ancestor at all)
    must behave exactly like this module did before scoping existed --
    page-wide candidates, no scoping prefix."""
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="#username",
        password_selector="#password",
        submit_selector="#loginButton",
    )
    page = _page("https://x/after-login")  # eval_on_selector -> None via the shared fixture

    await provider.authenticate(_user(), page)

    page.fill.assert_any_await("#username", "admin")


@pytest.mark.asyncio
async def test_dismiss_overlays_clicks_a_matching_selector():
    """A cookie-consent/welcome overlay confirmed live to intercept
    every click on the real login button underneath it -- dismissing
    known overlay patterns first must click through to the actual
    element, not just probe it."""
    page = AsyncMock()
    clicked: list[str] = []

    def _locator(selector: str):
        locator = AsyncMock()
        matches = selector == "#cookieconsent-container button"
        locator.count = AsyncMock(return_value=1 if matches else 0)
        locator.first = AsyncMock()
        locator.first.click = AsyncMock(side_effect=lambda **kw: clicked.append(selector))
        return locator

    page.locator = MagicMock(side_effect=_locator)

    await _dismiss_overlays(page)

    assert clicked == ["#cookieconsent-container button"]


@pytest.mark.asyncio
async def test_dismiss_overlays_does_nothing_when_none_present():
    page = AsyncMock()
    no_match = AsyncMock()
    no_match.count = AsyncMock(return_value=0)
    page.locator = MagicMock(return_value=no_match)

    await _dismiss_overlays(page)  # must not raise


@pytest.mark.asyncio
async def test_dismiss_overlays_survives_a_click_failure():
    """Best-effort only -- an overlay that matched but couldn't actually
    be clicked (e.g. already gone by the time we act) must never block
    login from proceeding."""
    page = AsyncMock()
    locator = AsyncMock()
    locator.count = AsyncMock(return_value=1)
    locator.first = AsyncMock()
    locator.first.click = AsyncMock(side_effect=RuntimeError("element not attached"))
    page.locator = MagicMock(return_value=locator)

    await _dismiss_overlays(page)  # must not raise


@pytest.mark.asyncio
async def test_refresh_always_raises_auth_expired_error():
    provider = FormLoginProvider(
        login_url=LOGIN_URL,
        username_selector="#uid",
        password_selector="#passw",
        submit_selector="#login-btn",
    )
    from stof.session.models import Session

    session = Session(user_id="admin-01", role="admin", auth_type="form_login")

    with pytest.raises(AuthExpiredError, match="cannot be refreshed"):
        await provider.refresh(session, _page(LOGIN_URL))


# ---------------------------------------------------------------------------
# Input validation — is_authenticated()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_authenticated_true_when_cookies_still_match():
    from stof.session.models import Session

    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#btn"
    )
    session = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"})
    page = _page("https://demo.testfire.net/bank/main.jsp", cookies=[{"name": "JSESSIONID", "value": "abc"}])

    assert await provider.is_authenticated(session, page) is True


@pytest.mark.asyncio
async def test_is_authenticated_false_when_cookie_value_changed():
    from stof.session.models import Session

    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#btn"
    )
    session = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"})
    page = _page("https://demo.testfire.net/login.jsp", cookies=[{"name": "JSESSIONID", "value": "different"}])

    assert await provider.is_authenticated(session, page) is False


@pytest.mark.asyncio
async def test_is_authenticated_false_when_session_already_marked_invalid():
    from stof.session.models import Session

    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#btn"
    )
    session = Session(user_id="admin-01", role="admin", auth_type="form_login", is_valid=False)
    page = _page("https://demo.testfire.net/bank/main.jsp")

    assert await provider.is_authenticated(session, page) is False
    page.context.cookies.assert_not_awaited()


# ---------------------------------------------------------------------------
# Modern SPA (localStorage/sessionStorage bearer token) support
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_captures_storage_token_as_authorization_header():
    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#btn"
    )
    # A pure-token SPA sets no cookie at all -- the whole point of this
    # feature is that cookies=={} here must not mean "session unusable".
    page = _page("https://app.example.com/dashboard", cookies=[], storage_token="eyJhbGciOi.fake.jwt")

    session = await provider.authenticate(_user(), page)

    assert session.cookies == {}
    assert session.headers == {"Authorization": "Bearer eyJhbGciOi.fake.jwt"}


@pytest.mark.asyncio
async def test_authenticate_leaves_headers_empty_when_no_storage_token_present():
    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#btn"
    )
    page = _page("https://demo.testfire.net/bank/main.jsp", cookies=[{"name": "JSESSIONID", "value": "abc"}])

    session = await provider.authenticate(_user(), page)

    assert session.headers == {}


@pytest.mark.asyncio
async def test_extract_storage_token_returns_none_when_evaluate_raises():
    from stof.auth.form_login import extract_storage_token

    page = AsyncMock()
    page.evaluate = AsyncMock(side_effect=RuntimeError("storage access blocked"))

    assert await extract_storage_token(page) is None


@pytest.mark.asyncio
async def test_extract_storage_token_passes_the_fixed_candidate_keys_and_returns_result():
    from stof.auth.form_login import GENERIC_TOKEN_STORAGE_KEYS, extract_storage_token

    page = AsyncMock()
    page.evaluate = AsyncMock(return_value="the-token-value")

    result = await extract_storage_token(page)

    assert result == "the-token-value"
    script_arg, keys_arg = page.evaluate.await_args.args
    assert keys_arg == GENERIC_TOKEN_STORAGE_KEYS
    # Regression guard: the JWT-value-shape fallback scan (added after a
    # real target stored its auth token under an app-specific, oddly-
    # capitalized key like "kautorAuthTOken" that no fixed candidate
    # list could match) must still be present in the evaluated script --
    # this is the actual behavior change under test, since
    # `page.evaluate` itself is mocked and can't run the real JS.
    assert "jwtShape" in script_arg
    assert "eyJ" in script_arg


@pytest.mark.asyncio
async def test_is_authenticated_checks_authorization_header_when_no_cookies():
    from stof.session.models import Session

    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#btn"
    )
    session = Session(
        user_id="admin-01", role="admin", auth_type="form_login", cookies={},
        headers={"Authorization": "Bearer eyJhbGciOi.fake.jwt"},
    )
    page = _page("https://app.example.com/dashboard")

    assert await provider.is_authenticated(session, page) is True
    page.context.cookies.assert_not_awaited()


@pytest.mark.asyncio
async def test_is_authenticated_false_for_token_only_session_with_no_stored_header():
    from stof.session.models import Session

    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#btn"
    )
    session = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={}, headers={})
    page = _page("https://app.example.com/dashboard")

    assert await provider.is_authenticated(session, page) is False


# ---------------------------------------------------------------------------
# TOTP / MFA second step
# ---------------------------------------------------------------------------


TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # a standard base32 test secret (RFC 4648 alphabet)


def _user_with_totp() -> UserConfig:
    return UserConfig(
        id="admin-01", role="admin", username="admin", password="s3cr3t",
        auth_type="form_login", totp_secret=TOTP_SECRET,
    )


def _page_with_selective_locator(url: str, found_selectors: set[str], cookies: list[dict] | None = None) -> AsyncMock:
    """Like `_page()`, but `page.locator(selector).count()` only reports
    "found" for selectors in `found_selectors` -- needed to distinguish
    "the TOTP field showed up" from "every other field showed up too"
    (the generic `_page()` fixture makes every selector match, which
    can't tell those two cases apart)."""
    page = AsyncMock()
    page.url = url
    page.context.cookies = AsyncMock(return_value=cookies or [])

    def _locator(selector):
        loc = AsyncMock()
        loc.count = AsyncMock(return_value=1 if selector in found_selectors else 0)
        return loc

    page.locator = MagicMock(side_effect=_locator)
    page.eval_on_selector = AsyncMock(return_value=None)
    page.evaluate = AsyncMock(return_value=None)
    return page


@pytest.mark.asyncio
async def test_totp_code_is_generated_and_submitted_when_mfa_field_appears():
    import pyotp

    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#btn",
        success_selector="text=Welcome",
    )
    page = _page_with_selective_locator(
        "https://demo.testfire.net/bank/main.jsp",
        found_selectors={"#uid", "#passw", "#btn", "input[autocomplete='one-time-code']", "text=Welcome"},
    )

    session = await provider.authenticate(_user_with_totp(), page)

    assert session.user_id == "admin-01"
    # The exact code STOF computed must be a real, currently-valid TOTP
    # code for this secret -- not just "some 6-digit string" -- proving
    # this actually ran the real RFC 6238 algorithm, not a stub.
    expected_code = pyotp.TOTP(TOTP_SECRET).now()
    page.fill.assert_any_await("input[autocomplete='one-time-code']", expected_code)
    # The MFA step's own submit click happened -- same selector as the
    # primary submit here since the fake page reports both as present;
    # what matters is fill() was called with the code before this.
    assert page.click.await_count >= 2


@pytest.mark.asyncio
async def test_no_totp_step_attempted_when_user_has_no_secret():
    """The overwhelming common case: a user with no `totp_secret`
    configured must behave byte-for-byte like before this feature
    existed -- no polling, no fill() call with any code."""
    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#btn",
        success_selector="text=Welcome",
    )
    page = _page_with_selective_locator(
        "https://demo.testfire.net/bank/main.jsp",
        found_selectors={"#uid", "#passw", "#btn", "text=Welcome"},
    )

    await provider.authenticate(_user(), page)  # no totp_secret

    filled_selectors = {call.args[0] for call in page.fill.await_args_list}
    assert "input[autocomplete='one-time-code']" not in filled_selectors


@pytest.mark.asyncio
async def test_totp_secret_configured_but_no_mfa_field_appears_is_a_noop():
    """A user configured with a totp_secret against a target that
    (this run, or always) doesn't actually show an MFA step -- must
    complete the login normally, not hang or raise. `timeout_ms` kept
    small here so the bounded poll (min(5000, timeout_ms)) doesn't slow
    the test down."""
    provider = FormLoginProvider(
        login_url=LOGIN_URL, username_selector="#uid", password_selector="#passw", submit_selector="#btn",
        success_selector="text=Welcome", timeout_ms=100,
    )
    page = _page_with_selective_locator(
        "https://demo.testfire.net/bank/main.jsp",
        found_selectors={"#uid", "#passw", "#btn", "text=Welcome"},  # no TOTP field ever appears
    )

    session = await provider.authenticate(_user_with_totp(), page)

    assert session.user_id == "admin-01"
    filled_selectors = {call.args[0] for call in page.fill.await_args_list}
    assert "input[autocomplete='one-time-code']" not in filled_selectors


@pytest.mark.asyncio
async def test_wait_for_totp_field_returns_none_when_nothing_matches_within_timeout():
    from stof.auth.form_login import FormLoginProvider as _FLP

    provider = _FLP(login_url=LOGIN_URL)
    page = _page_with_selective_locator(LOGIN_URL, found_selectors=set())

    result = await provider._wait_for_totp_field(page, timeout_ms=50)

    assert result is None
