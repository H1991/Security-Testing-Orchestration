"""Unit tests for Layer 9 — stof.modules.graphql_tests (TC-116)."""
import json
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.graphql_tests import GraphQLTestConfig, GraphQLTestsModule, find_graphql_endpoint
from stof.modules.results import FAIL, PASS, SKIPPED
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore

# ---------------------------------------------------------------------------
# find_graphql_endpoint — pure function
# ---------------------------------------------------------------------------


def test_find_graphql_endpoint_matches_common_path():
    endpoints = [
        Endpoint(url="https://x/rest/products", method="GET", endpoint_type="api"),
        Endpoint(url="https://x/graphql", method="POST", endpoint_type="api"),
    ]
    found = find_graphql_endpoint(endpoints)
    assert found is not None
    assert found.url == "https://x/graphql"


def test_find_graphql_endpoint_none_for_rest_only_target():
    endpoints = [Endpoint(url="https://x/rest/products", method="GET", endpoint_type="api")]
    assert find_graphql_endpoint(endpoints) is None


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


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


@pytest.mark.asyncio
async def test_run_techniques_skipped_when_no_graphql_endpoint(tmp_path):
    endpoint = Endpoint(url="https://x/rest/products", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = GraphQLTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    assert len(results) == 5
    assert all(r.status == SKIPPED for r in results)
    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.4"].status == SKIPPED
    assert by_id["TC-116.5"].status == SKIPPED
    assert by_id["TC-116.5"].severity == "Low"


@pytest.mark.asyncio
async def test_field_level_bypass_fails_when_sensitive_field_returns_data(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        payload = json.loads(data)
        if "__schema" in payload["query"]:
            body = {"data": {"__schema": {"queryType": {"fields": [{"name": "adminUsers"}]}, "mutationType": {"fields": []}}}}
        elif "adminUsers" in payload["query"]:
            body = {"data": {"adminUsers": [{"id": 1, "email": "victim@x.com"}]}}
        else:
            body = {"data": {}}
        return _response(200, json.dumps(body))

    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.1"].status == "FAIL"
    assert by_id["TC-116.1"].finding is not None


@pytest.mark.asyncio
async def test_field_level_bypass_passes_when_no_data_returned(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        payload = json.loads(data)
        schema_body = {"data": {"__schema": {"queryType": {"fields": [{"name": "adminUsers"}]}, "mutationType": {"fields": []}}}}
        denied_body = {"errors": [{"message": "Forbidden"}]}
        body = schema_body if "__schema" in payload["query"] else denied_body
        return _response(200, json.dumps(body))

    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.1"].status == PASS


@pytest.mark.asyncio
async def test_field_level_bypass_skipped_when_introspection_disabled(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        return _response(200, json.dumps({"errors": [{"message": "introspection disabled"}]}))

    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.1"].status == SKIPPED


# ---------------------------------------------------------------------------
# _find_login_mutation / _looks_like_rate_limited -- pure helpers
# ---------------------------------------------------------------------------


def test_find_login_mutation_matches_hinted_name():
    assert GraphQLTestsModule._find_login_mutation(["createOrder", "login", "deleteUser"]) == "login"
    assert GraphQLTestsModule._find_login_mutation(["signinUser", "updateProfile"]) == "signinUser"
    assert GraphQLTestsModule._find_login_mutation(["authenticateUser"]) == "authenticateUser"


def test_find_login_mutation_none_when_no_login_shaped_field():
    assert GraphQLTestsModule._find_login_mutation(["createOrder", "updateProfile", "deleteUser"]) is None


def test_looks_like_rate_limited_matches_lockout_phrases():
    assert GraphQLTestsModule._looks_like_rate_limited([{"message": "Too many attempts, try again later"}])
    assert GraphQLTestsModule._looks_like_rate_limited([{"message": "Account locked"}])
    assert GraphQLTestsModule._looks_like_rate_limited([{"message": "Rate limit exceeded"}])


def test_looks_like_rate_limited_false_for_unrelated_error():
    assert not GraphQLTestsModule._looks_like_rate_limited([{"message": "Invalid credentials"}])
    assert not GraphQLTestsModule._looks_like_rate_limited([])


# ---------------------------------------------------------------------------
# TC-116.3 -- aliased batch bypasses login attempt limiter
# ---------------------------------------------------------------------------

_LOGIN_SCHEMA_BODY = {
    "data": {"__schema": {"queryType": {"fields": []}, "mutationType": {"fields": [{"name": "login"}]}}}
}
_NO_LOGIN_SCHEMA_BODY = {
    "data": {"__schema": {"queryType": {"fields": []}, "mutationType": {"fields": [{"name": "updateProfile"}]}}}
}


def _make_batching_fake_post(schema_body: dict, lock_at: int | None, batch_locks: bool = False):
    """`lock_at`: sequential attempt number (1-based) at which a
    lockout-shaped error starts appearing; `None` means the sequential
    baseline never locks. `batch_locks`: whether the single aliased
    batch request should also come back with a lockout-shaped error."""
    state = {"sequential_attempts": 0}

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        payload = json.loads(data)
        query = payload["query"]
        if "__schema" in query:
            return _response(200, json.dumps(schema_body))
        if "a0:" in query:  # single aliased-batch request
            body = {"errors": [{"message": "too many attempts, try again later"}]} if batch_locks else {"data": {"a0": {"token": "x"}}}
            return _response(200, json.dumps(body))
        # sequential single-call attempt
        state["sequential_attempts"] += 1
        locked = lock_at is not None and state["sequential_attempts"] >= lock_at
        body = {"errors": [{"message": "too many attempts, try again later"}]} if locked else {"errors": [{"message": "invalid credentials"}]}
        return _response(200, json.dumps(body))

    return fake_post


@pytest.mark.asyncio
async def test_batching_bypass_skipped_when_gate_off(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    fake_post = _make_batching_fake_post(_LOGIN_SCHEMA_BODY, lock_at=3)
    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule(config=GraphQLTestConfig(test_username="normal", allow_state_changing_probes=False))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.3"].status == SKIPPED
    assert "allow_state_changing_probes" in by_id["TC-116.3"].detail


@pytest.mark.asyncio
async def test_batching_bypass_skipped_when_no_login_mutation(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    fake_post = _make_batching_fake_post(_NO_LOGIN_SCHEMA_BODY, lock_at=None)
    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule(config=GraphQLTestConfig(test_username="normal", allow_state_changing_probes=True, max_sequential_attempts=5))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.3"].status == SKIPPED
    assert "no login" in by_id["TC-116.3"].detail.lower()


@pytest.mark.asyncio
async def test_batching_bypass_passes_with_inconclusive_baseline_when_no_lockout(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    fake_post = _make_batching_fake_post(_LOGIN_SCHEMA_BODY, lock_at=None)
    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule(config=GraphQLTestConfig(test_username="normal", allow_state_changing_probes=True, max_sequential_attempts=5))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.3"].status == PASS
    assert "inconclusive" in by_id["TC-116.3"].detail.lower()


@pytest.mark.asyncio
async def test_batching_bypass_fails_on_genuine_differential(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    fake_post = _make_batching_fake_post(_LOGIN_SCHEMA_BODY, lock_at=3, batch_locks=False)
    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule(config=GraphQLTestConfig(test_username="normal", allow_state_changing_probes=True, max_sequential_attempts=5))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.3"].status == FAIL
    assert by_id["TC-116.3"].finding is not None
    assert "attempt 3/5" in by_id["TC-116.3"].detail


@pytest.mark.asyncio
async def test_batching_bypass_passes_when_limiter_holds_under_aliasing(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    fake_post = _make_batching_fake_post(_LOGIN_SCHEMA_BODY, lock_at=3, batch_locks=True)
    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule(config=GraphQLTestConfig(test_username="normal", allow_state_changing_probes=True, max_sequential_attempts=5))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.3"].status == PASS
    assert by_id["TC-116.3"].finding is None
    assert "holds under aliasing" in by_id["TC-116.3"].detail


# ---------------------------------------------------------------------------
# TC-116.4 -- nested-object authorization bypass via relationship traversal
# ---------------------------------------------------------------------------

_NESTED_SCHEMA_BODY = {
    "data": {"__schema": {"queryType": {"fields": [{"name": "adminUser"}]}, "mutationType": {"fields": []}}}
}


@pytest.mark.asyncio
async def test_nested_relationship_bypass_fails_when_nested_field_returns_data(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        payload = json.loads(data)
        query = payload["query"]
        if "__schema" in query:
            return _response(200, json.dumps(_NESTED_SCHEMA_BODY))
        if "adminUser" in query and "id" in query:
            # First sub-field hint tried ("id") resolves with real nested data.
            body = {"data": {"adminUser": {"id": "victim-42"}}}
            return _response(200, json.dumps(body))
        return _response(200, json.dumps({"errors": [{"message": "Cannot query field"}]}))

    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.4"].status == FAIL
    assert by_id["TC-116.4"].finding is not None
    assert "adminUser" in by_id["TC-116.4"].detail


@pytest.mark.asyncio
async def test_nested_relationship_bypass_passes_when_all_subfields_error_or_null(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        payload = json.loads(data)
        query = payload["query"]
        if "__schema" in query:
            return _response(200, json.dumps(_NESTED_SCHEMA_BODY))
        # Every nested sub-field probe errors (field doesn't exist on the real type).
        return _response(200, json.dumps({"errors": [{"message": "Cannot query field"}]}))

    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.4"].status == PASS
    assert by_id["TC-116.4"].finding is None


@pytest.mark.asyncio
async def test_nested_relationship_bypass_skipped_when_introspection_disabled(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        return _response(200, json.dumps({"errors": [{"message": "introspection disabled"}]}))

    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.4"].status == SKIPPED


# ---------------------------------------------------------------------------
# TC-116.5 -- introspection exposure scored as its own finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_introspection_exposed_fails_when_schema_non_trivial(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        body = {"data": {"__schema": {"queryType": {"fields": [{"name": "products"}]}, "mutationType": {"fields": [{"name": "login"}]}}}}
        return _response(200, json.dumps(body))

    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    result = by_id["TC-116.5"]
    assert result.status == FAIL
    assert result.severity == "Low"
    assert result.finding is not None
    assert result.finding.severity == "Low"
    assert "non-production" in result.finding.description


@pytest.mark.asyncio
async def test_introspection_exposed_passes_when_schema_empty(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        body = {"data": {"__schema": {"queryType": {"fields": []}, "mutationType": {"fields": []}}}}
        return _response(200, json.dumps(body))

    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    result = by_id["TC-116.5"]
    assert result.status == PASS
    assert result.finding is None


@pytest.mark.asyncio
async def test_introspection_exposed_passes_when_introspection_disabled(tmp_path):
    endpoint = Endpoint(url="https://x/graphql", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        return _response(200, json.dumps({"errors": [{"message": "introspection disabled"}]}))

    pool = _pool_with_context(_fake_context(fake_post))
    module = GraphQLTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-116.5"].status == PASS
