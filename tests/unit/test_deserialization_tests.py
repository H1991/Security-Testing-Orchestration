"""Unit tests for Layer 9 — stof.modules.deserialization_tests (TC-085)."""
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.deserialization_tests import (
    DeserializationTestsModule,
    _content_type_indicates_serialization_format,
    _looks_like_serialized_blob,
    _viewstate_mac_disabled,
    extract_serialization_library_fingerprint,
    looks_like_deserialization_error,
)
from stof.modules.results import FAIL, NOT_IMPLEMENTED, PASS, SKIPPED
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore

# ---------------------------------------------------------------------------
# looks_like_deserialization_error — pure function
# ---------------------------------------------------------------------------


def test_looks_like_deserialization_error_matches_known_signature():
    assert looks_like_deserialization_error("com.fasterxml.jackson.databind.exc.InvalidDefinitionException: ...")


def test_looks_like_deserialization_error_false_for_generic_validation_error():
    assert not looks_like_deserialization_error('{"error": "email is required"}')


# ---------------------------------------------------------------------------
# _viewstate_mac_disabled — pure function
# ---------------------------------------------------------------------------


def test_viewstate_mac_disabled_true_when_viewstate_present_and_mac_absent():
    html = '<input type="hidden" name="__VIEWSTATE" value="/wEPDwUKMTE..." />'
    assert _viewstate_mac_disabled(html)


def test_viewstate_mac_disabled_false_when_both_fields_present():
    html = (
        '<input type="hidden" name="__VIEWSTATE" value="/wEPDwUKMTE..." />'
        '<input type="hidden" name="__VIEWSTATEMAC" value="abc123==" />'
    )
    assert not _viewstate_mac_disabled(html)


def test_viewstate_mac_disabled_false_when_viewstate_absent_entirely():
    html = "<html><body><h1>Java/JSP app, no ViewState here</h1></body></html>"
    assert not _viewstate_mac_disabled(html)


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


def _fake_context(post_side_effect):
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    context.request.post = AsyncMock(side_effect=post_side_effect)
    return context


def _fake_get_context(get_side_effect):
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    context.request.get = AsyncMock(side_effect=get_side_effect)
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


@pytest.mark.asyncio
async def test_always_reports_two_not_implemented_gadget_and_dos_techniques(tmp_path):
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = DeserializationTestsModule()

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.1"].status == NOT_IMPLEMENTED
    assert by_id["TC-085.3"].status == NOT_IMPLEMENTED


@pytest.mark.asyncio
async def test_polymorphic_type_confusion_fails_on_deserialization_shaped_error(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        return _response(500, "com.fasterxml.jackson.databind.exc.InvalidDefinitionException: Cannot construct instance")

    pool = _pool_with_context(_fake_context(fake_post))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.2"].status == FAIL
    assert by_id["TC-085.2"].finding is not None
    assert "did not attempt exploitation" in by_id["TC-085.2"].finding.description
    # Regression: the description says exactly that -- a
    # deserialization-shaped error signal, not a confirmed gadget-chain
    # RCE.
    assert by_id["TC-085.2"].finding.confidence == "likely"


@pytest.mark.asyncio
async def test_polymorphic_type_confusion_passes_on_ordinary_error(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        return _response(400, '{"error": "invalid request body"}')

    pool = _pool_with_context(_fake_context(fake_post))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.2"].status == PASS


@pytest.mark.asyncio
async def test_polymorphic_type_confusion_skipped_when_no_write_endpoint(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.2"].status == SKIPPED


# ---------------------------------------------------------------------------
# _technique_viewstate_mac_disabled (TC-085.4) — async
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewstate_mac_disabled_fails_when_viewstate_present_without_mac(tmp_path):
    endpoint = Endpoint(url="https://x/legacy/login.aspx", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(200, '<input type="hidden" name="__VIEWSTATE" value="/wEPDwUK..." />')

    pool = _pool_with_context(_fake_get_context(fake_get))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.4"].status == FAIL
    assert by_id["TC-085.4"].finding is not None
    assert "confirms the precondition" in by_id["TC-085.4"].finding.description
    assert by_id["TC-085.4"].finding.severity == "Medium"


@pytest.mark.asyncio
async def test_viewstate_mac_disabled_passes_when_mac_present(tmp_path):
    endpoint = Endpoint(url="https://x/legacy/login.aspx", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(
            200,
            '<input type="hidden" name="__VIEWSTATE" value="/wEPDwUK..." />'
            '<input type="hidden" name="__VIEWSTATEMAC" value="abc==" />',
        )

    pool = _pool_with_context(_fake_get_context(fake_get))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.4"].status == PASS


@pytest.mark.asyncio
async def test_viewstate_mac_disabled_passes_on_non_aspnet_page(tmp_path):
    endpoint = Endpoint(url="https://x/legacy/index.jsp", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        return _response(200, "<html><body><h1>Java/JSP app</h1></body></html>")

    pool = _pool_with_context(_fake_get_context(fake_get))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.4"].status == PASS


@pytest.mark.asyncio
async def test_viewstate_mac_disabled_skipped_when_no_page_endpoint(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_get_context(AsyncMock()))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.4"].status == SKIPPED


# ---------------------------------------------------------------------------
# _content_type_indicates_serialization_format / _looks_like_serialized_blob
# -- pure functions
# ---------------------------------------------------------------------------


def test_content_type_indicates_serialization_format_true_for_java_serialized_object():
    assert _content_type_indicates_serialization_format("application/x-java-serialized-object; charset=utf-8")


def test_content_type_indicates_serialization_format_false_for_ordinary_json():
    assert not _content_type_indicates_serialization_format("application/json; charset=utf-8")


def test_looks_like_serialized_blob_true_for_java_magic_bytes_base64():
    assert _looks_like_serialized_blob("rO0ABXNyAB1qYXZhLnV0aWwuSGFzaE1hcA==")


def test_looks_like_serialized_blob_true_for_java_magic_bytes_hex():
    assert _looks_like_serialized_blob("aced000573720013")


def test_looks_like_serialized_blob_false_for_ordinary_value():
    assert not _looks_like_serialized_blob("some-ordinary-session-token-value")


def test_looks_like_serialized_blob_false_for_empty_value():
    assert not _looks_like_serialized_blob("")


# ---------------------------------------------------------------------------
# extract_serialization_library_fingerprint -- pure function
# ---------------------------------------------------------------------------


def test_extract_serialization_library_fingerprint_matches_known_library_and_version():
    headers = {"x-powered-by": "Jackson-Databind/2.9.8"}
    assert extract_serialization_library_fingerprint(headers) == "Jackson-Databind/2.9.8"


def test_extract_serialization_library_fingerprint_none_for_unrelated_header():
    headers = {"x-powered-by": "Express", "server": "nginx/1.18.0"}
    assert extract_serialization_library_fingerprint(headers) is None


def test_extract_serialization_library_fingerprint_none_when_name_present_without_version():
    headers = {"x-powered-by": "Jackson"}
    assert extract_serialization_library_fingerprint(headers) is None


# ---------------------------------------------------------------------------
# _technique_content_type_discovery (TC-085.5) -- async
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_content_type_discovery_fails_on_passive_serialized_parameter_value(tmp_path):
    endpoint = Endpoint(
        url="https://x/api/orders", method="POST", endpoint_type="api",
        parameters=["payload"], parameter_values={"payload": "rO0ABXNyAB1qYXZhLnV0aWwuSGFzaE1hcA=="},
    )
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_get_context(AsyncMock()))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.5"].status == FAIL
    assert by_id["TC-085.5"].finding is not None
    assert by_id["TC-085.5"].finding.severity == "Info"
    assert "no new request or crafted serialized payload was sent" in by_id["TC-085.5"].finding.description


@pytest.mark.asyncio
async def test_content_type_discovery_fails_on_serialization_response_content_type(tmp_path):
    endpoint = Endpoint(url="https://x/legacy/rmi", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    def _resp(status, headers):
        resp = AsyncMock()
        resp.status = status
        resp.headers = headers
        return resp

    async def fake_get(url, max_redirects=0):
        return _resp(200, {"content-type": "application/x-java-serialized-object"})

    pool = _pool_with_context(_fake_get_context(fake_get))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.5"].status == FAIL
    assert by_id["TC-085.5"].finding.severity == "Info"


@pytest.mark.asyncio
async def test_content_type_discovery_passes_on_ordinary_json_content_type(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    def _resp(status, headers):
        resp = AsyncMock()
        resp.status = status
        resp.headers = headers
        return resp

    async def fake_get(url, max_redirects=0):
        return _resp(200, {"content-type": "application/json"})

    pool = _pool_with_context(_fake_get_context(fake_get))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.5"].status == PASS


@pytest.mark.asyncio
async def test_content_type_discovery_skipped_when_no_applicable_endpoint(tmp_path):
    endpoint = Endpoint(url="https://x/form", method="POST", endpoint_type="form")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_get_context(AsyncMock()))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.5"].status == SKIPPED


# ---------------------------------------------------------------------------
# _technique_library_fingerprinting (TC-085.6) -- async
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_library_fingerprinting_fails_when_version_banner_header_present(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    def _resp(status, headers):
        resp = AsyncMock()
        resp.status = status
        resp.headers = headers
        return resp

    async def fake_get(url, max_redirects=0):
        return _resp(200, {"X-Powered-By": "Jackson-Databind/2.9.8"})

    pool = _pool_with_context(_fake_get_context(fake_get))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.6"].status == FAIL
    assert by_id["TC-085.6"].finding is not None
    assert by_id["TC-085.6"].finding.severity == "Info"
    assert "Jackson-Databind/2.9.8" in by_id["TC-085.6"].finding.description


@pytest.mark.asyncio
async def test_library_fingerprinting_passes_when_no_version_banner(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    def _resp(status, headers):
        resp = AsyncMock()
        resp.status = status
        resp.headers = headers
        return resp

    async def fake_get(url, max_redirects=0):
        return _resp(200, {"server": "nginx"})

    pool = _pool_with_context(_fake_get_context(fake_get))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.6"].status == PASS


@pytest.mark.asyncio
async def test_library_fingerprinting_skipped_when_no_applicable_endpoint(tmp_path):
    endpoint = Endpoint(url="https://x/form", method="POST", endpoint_type="form")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_get_context(AsyncMock()))
    module = DeserializationTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-085.6"].status == SKIPPED
