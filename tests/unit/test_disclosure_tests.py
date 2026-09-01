"""Unit tests for Layer 9 — stof.modules.disclosure_tests (TC-105)."""
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.disclosure_tests import (
    DisclosureTestConfig,
    DisclosureTestsModule,
    _looks_like_env_file,
    _looks_like_git_config,
    _looks_like_source_map,
    find_hidden_disclosures,
    find_pii,
)
from stof.modules.results import FAIL, PASS, SKIPPED
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore

# ---------------------------------------------------------------------------
# find_pii — pure function
# ---------------------------------------------------------------------------


def test_find_pii_matches_email():
    matches = find_pii("contact jane.doe@example.com for help")
    assert any(m.label == "Email address" for m in matches)


def test_find_pii_ignores_generic_organizational_email_addresses():
    """Regression: live-verified against this project's own demo
    target -- /rest/admin/application-configuration echoes back the
    app's own contact address ("donotreply@owasp-juice.shop"), which
    isn't a real person's PII the way a user record's email would be."""
    for local_part in ("noreply", "donotreply", "support", "admin", "info", "contact"):
        matches = find_pii(f"privacyContactEmail: {local_part}@owasp-juice.shop")
        assert matches == [], f"{local_part}@... should have been filtered as organizational"


def test_find_pii_matches_ssn_shaped_value():
    matches = find_pii("ssn: 123-45-6789")
    assert any(m.label == "US Social Security Number" for m in matches)


def test_find_pii_matches_luhn_valid_card_number():
    matches = find_pii("card: 4111111111111111")
    assert any(m.label == "Credit Card Number" for m in matches)


def test_find_pii_ignores_luhn_invalid_long_digit_runs():
    """Regression: a 13-digit JS timestamp or a large sequential id
    must not be flagged as a credit card just because it's the right
    length -- only a Luhn-valid run counts."""
    matches = find_pii("created_at: 1700000000000, id: 8827364591234")
    assert not any(m.label == "Credit Card Number" for m in matches)


def test_find_pii_ignores_luhn_valid_but_non_card_prefixed_digit_run():
    """Regression: live-verified against this project's own demo
    target -- an image filename embedding a JS millisecond timestamp
    ("magn(et)ificent!-1571814229653.jpg") happened to be Luhn-valid
    purely by chance (~10% of random same-length digit runs are).
    Luhn alone isn't enough; a real issuer prefix is also required."""
    matches = find_pii("magn(et)ificent!-1571814229653.jpg")
    assert not any(m.label == "Credit Card Number" for m in matches)


def test_find_pii_empty_for_clean_text():
    assert find_pii("no personal data here, just a product name and a price of 19.99") == []


# ---------------------------------------------------------------------------
# run_techniques() — async
# ---------------------------------------------------------------------------


def _user(role: str) -> UserConfig:
    return UserConfig(id=f"{role}-01", role=role, username=role, password="pw", auth_type="form_login")


class _RoutingProvider(AuthProvider):
    def __init__(self, sessions: dict[str, Session]) -> None:
        self._sessions = sessions

    async def authenticate(self, user, page) -> Session:
        return self._sessions[user.role]

    async def refresh(self, session, page) -> Session:
        raise NotImplementedError

    async def is_authenticated(self, session, page) -> bool:
        return True


def _session_manager(tmp_path, sessions: dict[str, Session]) -> SessionManager:
    store = SessionStore(db_path=tmp_path / "stof.db")
    users = {role: _user(role) for role in sessions}
    return SessionManager(users=users, providers={"form_login": _RoutingProvider(sessions)}, store=store)


def _response(status: int, body: str):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    return resp


def _fake_context(get_side_effect):
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    context.request.get = AsyncMock(side_effect=get_side_effect)
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


@pytest.mark.asyncio
async def test_pii_in_api_response_flags_a_matching_endpoint(tmp_path):
    endpoint = Endpoint(url="https://x/rest/users/me", method="GET", endpoint_type="api", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(200, '{"email": "victim@example.com", "ssn": "123-45-6789"}')

    pool = _pool_with_context(_fake_context(fake_get))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.1"].status == FAIL
    assert by_id["TC-105.1"].finding is not None


@pytest.mark.asyncio
async def test_pii_in_api_response_passes_when_clean(tmp_path):
    endpoint = Endpoint(url="https://x/rest/products", method="GET", endpoint_type="api", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(200, '{"name": "Widget", "price": 9.99}')

    pool = _pool_with_context(_fake_context(fake_get))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.1"].status == PASS


@pytest.mark.asyncio
async def test_pii_in_api_response_skipped_when_no_get_api_endpoints(tmp_path):
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.1"].status == SKIPPED


@pytest.mark.asyncio
async def test_pii_in_errors_fails_when_error_response_leaks_pii(tmp_path):
    endpoint = Endpoint(url="https://x/rest/users/lookup", method="GET", endpoint_type="api", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(500, 'Error: user jane.doe@example.com not found in table')

    pool = _pool_with_context(_fake_context(fake_get))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.2"].status == FAIL
    assert by_id["TC-105.2"].finding is not None


@pytest.mark.asyncio
async def test_pii_in_errors_passes_when_no_pii_in_error(tmp_path):
    endpoint = Endpoint(url="https://x/rest/users/lookup", method="GET", endpoint_type="api", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(500, "Internal Server Error")

    pool = _pool_with_context(_fake_context(fake_get))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.2"].status == PASS


def test_pii_in_urls_flags_pii_named_parameter():
    endpoints = [Endpoint(url="https://x/api/lookup?email=someone@example.com", method="GET", endpoint_type="api", parameters=["email"])]
    module = DisclosureTestsModule()

    result = module._technique_pii_in_urls(endpoints)

    assert result.status == FAIL


def test_pii_in_urls_passes_when_no_endpoints_carry_pii():
    endpoints = [Endpoint(url="https://x/api/products?category=widgets", method="GET", endpoint_type="api", parameters=["category"])]
    module = DisclosureTestsModule()

    result = module._technique_pii_in_urls(endpoints)

    assert result.status == PASS


def test_config_defaults():
    config = DisclosureTestConfig()
    assert config.high_priv_role == "admin"
    assert config.max_endpoints_scanned == 15


# ---------------------------------------------------------------------------
# _looks_like_* / find_hidden_disclosures — pure functions (TC-105.5/.6)
# ---------------------------------------------------------------------------


def test_looks_like_source_map_true_for_real_source_map():
    body = '{"version": 3, "sources": ["webpack:///src/app.js"], "mappings": "AAAA"}'
    assert _looks_like_source_map(body) is True


def test_looks_like_source_map_false_for_bare_json():
    assert _looks_like_source_map('{"foo": "bar"}') is False


def test_looks_like_source_map_false_for_non_json():
    assert _looks_like_source_map("not json at all") is False


def test_looks_like_git_config_true():
    body = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
    assert _looks_like_git_config(body) is True


def test_looks_like_git_config_false_for_unrelated_body():
    assert _looks_like_git_config("<html>not a git config</html>") is False


def test_looks_like_env_file_true():
    assert _looks_like_env_file("DATABASE_URL=postgres://user:pw@host/db\nDEBUG=true") is True


def test_looks_like_env_file_false_for_unrelated_body():
    assert _looks_like_env_file("name=widget\nprice=9.99") is False


def test_find_hidden_disclosures_matches_pii_in_html_comment():
    html = "<html><body><!-- ssn: 123-45-6789 --><p>hello</p></body></html>"
    matches = find_hidden_disclosures(html)
    assert any(m.label == "US Social Security Number" for m in matches)


def test_find_hidden_disclosures_matches_secret_in_inline_script():
    html = '<script>var apiKey = "AKIAABCDEFGHIJKLMNOP";</script>'
    matches = find_hidden_disclosures(html)
    assert any(m.label == "AWS Access Key ID" for m in matches)


def test_find_hidden_disclosures_ignores_pii_only_in_visible_page_text():
    """Regression: must NOT false-positive on PII that's already
    visible in the rendered page -- only comment/inline-script spans
    count as a NEW source-inspection disclosure."""
    html = "<html><body><p>contact jane.doe@example.com for support</p></body></html>"
    matches = find_hidden_disclosures(html)
    assert matches == []


def test_find_hidden_disclosures_ignores_external_script_src():
    html = '<script src="https://cdn.example.com/app.js"></script>'
    matches = find_hidden_disclosures(html)
    assert matches == []


# ---------------------------------------------------------------------------
# TC-105.5 — source map / VCS / backup exposure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_source_map_and_backup_exposure_fails_on_exposed_git_config(tmp_path):
    endpoint = Endpoint(url="https://x/app.js", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        if url == "https://x/.git/config":
            return _response(200, "[core]\n\trepositoryformatversion = 0\n")
        return _response(404, "not found")

    pool = _pool_with_context(_fake_context(fake_get))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.5"].status == FAIL
    assert by_id["TC-105.5"].finding is not None


@pytest.mark.asyncio
async def test_source_map_and_backup_exposure_fails_on_exposed_env_file(tmp_path):
    endpoint = Endpoint(url="https://x/app.js", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        if url == "https://x/.env":
            return _response(200, "DATABASE_URL=postgres://user:pw@host/db\n")
        return _response(404, "not found")

    pool = _pool_with_context(_fake_context(fake_get))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.5"].status == FAIL


@pytest.mark.asyncio
async def test_source_map_and_backup_exposure_fails_on_exposed_source_map(tmp_path):
    endpoint = Endpoint(url="https://x/static/app.js", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        if url == "https://x/static/app.js":
            return _response(200, "console.log(1);\n//# sourceMappingURL=app.js.map")
        if url == "https://x/static/app.js.map":
            return _response(200, '{"version":3,"sources":["webpack:///src/index.js"],"mappings":""}')
        return _response(404, "not found")

    pool = _pool_with_context(_fake_context(fake_get))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.5"].status == FAIL


@pytest.mark.asyncio
async def test_source_map_and_backup_exposure_passes_when_none_found(tmp_path):
    endpoint = Endpoint(url="https://x/static/app.js", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(404, "not found")

    pool = _pool_with_context(_fake_context(fake_get))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.5"].status == PASS


@pytest.mark.asyncio
async def test_source_map_and_backup_exposure_skipped_with_no_origin_or_js_assets(tmp_path):
    module = DisclosureTestsModule()
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(AsyncMock()))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.5"].status == SKIPPED


# ---------------------------------------------------------------------------
# TC-105.6 — PII/secrets hidden in HTML comments or inline scripts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pii_in_html_source_fails_on_comment_hidden_pii(tmp_path):
    endpoint = Endpoint(url="https://x/debug", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(200, "<html><!-- ssn: 123-45-6789 --><body>hi</body></html>")

    pool = _pool_with_context(_fake_context(fake_get))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.6"].status == FAIL
    assert by_id["TC-105.6"].finding is not None


@pytest.mark.asyncio
async def test_pii_in_html_source_fails_on_inline_script_hidden_secret(tmp_path):
    endpoint = Endpoint(url="https://x/debug", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(200, '<html><body><script>var apiKey = "AKIAABCDEFGHIJKLMNOP";</script></body></html>')

    pool = _pool_with_context(_fake_context(fake_get))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.6"].status == FAIL


@pytest.mark.asyncio
async def test_pii_in_html_source_passes_when_pii_only_visible_in_page_text(tmp_path):
    endpoint = Endpoint(url="https://x/contact", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(200, "<html><body><p>contact jane.doe@example.com</p></body></html>")

    pool = _pool_with_context(_fake_context(fake_get))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.6"].status == PASS


@pytest.mark.asyncio
async def test_pii_in_html_source_skipped_when_no_page_endpoints(tmp_path):
    endpoint = Endpoint(url="https://x/api/products", method="GET", endpoint_type="api", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.6"].status == SKIPPED


# ---------------------------------------------------------------------------
# TC-105.7 — PII/secrets left in localStorage or sessionStorage
# ---------------------------------------------------------------------------


def _fake_page(evaluate_result=None, evaluate_side_effect=None):
    page = AsyncMock()
    page.goto = AsyncMock(return_value=None)
    if evaluate_side_effect is not None:
        page.evaluate = AsyncMock(side_effect=evaluate_side_effect)
    else:
        page.evaluate = AsyncMock(return_value=evaluate_result)
    page.close = AsyncMock(return_value=None)
    return page


def _fake_context_with_page(get_side_effect, page):
    """Same shape as `_fake_context`, but `new_page()` returns a
    caller-supplied fake `Page` instead of a bare `AsyncMock()` -- this
    module's other techniques never touch `new_page()`'s return value,
    only TC-105.7 (`_technique_pii_in_client_storage`) does, so this
    is additive rather than a change to the shared helper."""
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=page)
    context.request.get = AsyncMock(side_effect=get_side_effect)
    return context


@pytest.mark.asyncio
async def test_pii_in_client_storage_fails_on_pii_in_local_storage(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(404, "not found")

    page = _fake_page(evaluate_result={
        "local": [["userProfile", '{"email": "jane.doe@example.com"}']],
        "session": [],
    })
    pool = _pool_with_context(_fake_context_with_page(fake_get, page))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.7"].status == FAIL
    assert by_id["TC-105.7"].finding is not None
    assert "localStorage.userProfile" in by_id["TC-105.7"].finding.response_raw


@pytest.mark.asyncio
async def test_pii_in_client_storage_fails_on_pii_in_session_storage(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(404, "not found")

    page = _fake_page(evaluate_result={
        "local": [],
        "session": [["authToken", "ssn on file: 123-45-6789"]],
    })
    pool = _pool_with_context(_fake_context_with_page(fake_get, page))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.7"].status == FAIL


@pytest.mark.asyncio
async def test_pii_in_client_storage_passes_when_clean(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(404, "not found")

    page = _fake_page(evaluate_result={
        "local": [["theme", "dark"], ["cartId", "8827364591234"]],
        "session": [["csrfNonce", "abc123"]],
    })
    pool = _pool_with_context(_fake_context_with_page(fake_get, page))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.7"].status == PASS
    page.close.assert_awaited()


@pytest.mark.asyncio
async def test_pii_in_client_storage_skipped_when_no_page_endpoints(tmp_path):
    endpoint = Endpoint(url="https://x/api/products", method="GET", endpoint_type="api", parameters=[])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = DisclosureTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.7"].status == SKIPPED


@pytest.mark.asyncio
async def test_pii_in_client_storage_survives_evaluate_failure_and_continues(tmp_path):
    """Regression: a navigation/evaluate failure on one endpoint (an
    opaque-origin page, a network blip) must be treated like
    `_probe_get`'s own failure case -- skip that endpoint and keep
    scanning the rest, not abort the whole technique into an ERROR."""
    endpoints = [
        Endpoint(url="https://x/broken", method="GET", endpoint_type="page", parameters=[]),
        Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page", parameters=[]),
    ]
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(404, "not found")

    calls = {"n": 0}

    async def evaluate_side_effect(_script):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("Execution context was destroyed")
        return {"local": [["profile", "contact jane.doe@example.com"]], "session": []}

    page = _fake_page(evaluate_side_effect=evaluate_side_effect)
    pool = _pool_with_context(_fake_context_with_page(fake_get, page))
    module = DisclosureTestsModule()

    results = await module.run_techniques(endpoints, session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-105.7"].status == FAIL
