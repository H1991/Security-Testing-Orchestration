"""Unit tests for TC-131 -- stof.modules.tenant_tests (Tenant Isolation
BOLA, composed into IdorTestsModule as a mixin). Follows the same
fixture/fake shape as test_idor_tests_critical_gaps.py."""
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules._idor_shared import _looks_like_tenant_scope_param
from stof.modules.idor_tests import IdorTestConfig, IdorTestsModule
from stof.modules.results import FAIL, PASS, SKIPPED
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore


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


def _fake_context(**method_side_effects):
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    for method, side_effect in method_side_effects.items():
        setattr(context.request, method, AsyncMock(side_effect=side_effect))
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


# ---------------------------------------------------------------------------
# Pure helper
# ---------------------------------------------------------------------------


def test_looks_like_tenant_scope_param_matches_org_id():
    assert _looks_like_tenant_scope_param("org_id") is True


def test_looks_like_tenant_scope_param_matches_tenant_id_camel():
    assert _looks_like_tenant_scope_param("tenantId") is True


def test_looks_like_tenant_scope_param_matches_workspace_id():
    assert _looks_like_tenant_scope_param("workspace_id") is True


def test_looks_like_tenant_scope_param_rejects_plain_object_id():
    """A plain object id (`id`, `orderId`) is NOT a tenant-scope
    parameter -- the two attack shapes are deliberately distinct, per
    idor_knowledge_base.json's tenant_isolation family."""
    assert _looks_like_tenant_scope_param("id") is False
    assert _looks_like_tenant_scope_param("orderId") is False


def test_looks_like_tenant_scope_param_and_object_reference_are_independent_functions():
    """`_looks_like_tenant_scope_param` and `_looks_like_object_reference`
    are deliberately separate, independently-evaluated functions (per
    idor_knowledge_base.json's tenant_isolation family: "a param can be
    an object id OR a tenant scope, not conflated") -- a param may match
    both heuristics (e.g. 'tenant_id' contains the generic 'id' hint),
    but each family's own technique probes it via its own function, not
    a shared/merged classification."""
    from stof.modules._idor_shared import _looks_like_object_reference

    # A tenant-scope-shaped name is classified as a tenant scope by its
    # own function, independent of whatever _looks_like_object_reference
    # separately reports for the same name (both may be True -- that's
    # fine, since a param can legitimately be probed by both families;
    # what matters is the two functions never share implementation).
    assert _looks_like_tenant_scope_param("tenant_id") is True
    assert _looks_like_tenant_scope_param("theme") is False
    assert _looks_like_object_reference("theme") is False


# ---------------------------------------------------------------------------
# TC-131.1 -- GET-based tenant-scope substitution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tenant_scope_skipped_when_no_candidate_endpoint(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="GET", endpoint_type="api", parameters=["orderId"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = IdorTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-131.1"].status == SKIPPED


@pytest.mark.asyncio
async def test_tenant_scope_fails_when_distinct_org_content_returned(tmp_path):
    endpoint = Endpoint(url="https://x/bugs.json", method="GET", endpoint_type="api", parameters=["organization_id"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    bodies = {"1": "Org #1 private bug reports" * 20, "2": "Org #2 private bug reports" * 20}

    async def fake_get(url, **kwargs):
        from urllib.parse import parse_qs, urlsplit
        cid = parse_qs(urlsplit(url).query).get("organization_id", ["?"])[0]
        return _response(200, bodies[cid]) if cid in bodies else _response(404, "not found")

    pool = _pool_with_context(_fake_context(get=fake_get))
    config = IdorTestConfig(candidate_ids=["1", "2"])
    module = IdorTestsModule(config=config)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-131.1"].status == FAIL
    assert by_id["TC-131.1"].finding is not None
    assert "organization" in by_id["TC-131.1"].finding.description.lower()


@pytest.mark.asyncio
async def test_tenant_scope_passes_when_content_identical_across_candidates(tmp_path):
    """A GET/POST substitution technique that always returns
    identical/absent content is the correct, expected negative for a
    single-tenant target (e.g. demo.testfire.net, which has no
    multi-tenant concept) -- must PASS, not falsely FAIL."""
    endpoint = Endpoint(url="https://x/bugs.json", method="GET", endpoint_type="api", parameters=["organization_id"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_get(url, **kwargs):
        return _response(200, "identical content for every org" * 10)

    pool = _pool_with_context(_fake_context(get=fake_get))
    config = IdorTestConfig(candidate_ids=["1", "2"])
    module = IdorTestsModule(config=config)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-131.1"].status == PASS
    assert by_id["TC-131.1"].finding is None


# ---------------------------------------------------------------------------
# TC-131.1 -- POST-based tenant-scope substitution (gated)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tenant_scope_post_endpoint_skipped_without_get_candidates_and_gate_off(tmp_path):
    """A POST-only tenant-scope endpoint with the write gate off still
    results in SKIPPED (the POST candidate is dropped, and there's no
    GET candidate to fall back to) -- never an ungated write."""
    endpoint = Endpoint(url="https://x/bugs.json", method="POST", endpoint_type="api", parameters=["organization_id"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    context = _fake_context(post=AsyncMock(return_value=_response(200, "should never be called" * 20)))
    pool = _pool_with_context(context)
    module = IdorTestsModule()  # allow_state_changing_probes defaults False

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-131.1"].status == SKIPPED
    context.request.post.assert_not_called()


@pytest.mark.asyncio
async def test_tenant_scope_post_fails_when_gate_on_and_distinct_org_content_returned(tmp_path):
    endpoint = Endpoint(url="https://x/bugs.json", method="POST", endpoint_type="api", parameters=["organization_id"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    bodies = {"1": "Org #1 private bug reports" * 20, "2": "Org #2 private bug reports" * 20}

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        import json
        cid = json.loads(data)["organization_id"]
        return _response(200, bodies[cid]) if cid in bodies else _response(404, "not found")

    pool = _pool_with_context(_fake_context(post=fake_post))
    config = IdorTestConfig(candidate_ids=["1", "2"], allow_state_changing_probes=True)
    module = IdorTestsModule(config=config)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-131.1"].status == FAIL
    assert by_id["TC-131.1"].finding is not None
