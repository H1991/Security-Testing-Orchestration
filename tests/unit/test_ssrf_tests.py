"""Unit tests for Layer 9 -- stof.modules.ssrf_tests (TC-137)."""
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.results import FAIL, PASS, SKIPPED
from stof.modules.ssrf_tests import SsrfTestConfig, SsrfTestsModule
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore

# ---------------------------------------------------------------------------
# Pure candidate filtering
# ---------------------------------------------------------------------------


def test_param_candidates_only_selects_url_shaped_params():
    module = SsrfTestsModule()
    endpoints = [
        Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["callback_url", "page_size"]),
        Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["query"]),
    ]
    candidates = module._param_candidates(endpoints)
    names = [c[1] for c in candidates]
    assert names == ["callback_url"]


def test_param_candidates_respects_max_targets():
    module = SsrfTestsModule(config=SsrfTestConfig(max_targets=1))
    endpoints = [
        Endpoint(url="https://x/a", method="GET", endpoint_type="page", parameters=["url"]),
        Endpoint(url="https://x/b", method="GET", endpoint_type="page", parameters=["webhook"]),
    ]
    candidates = module._param_candidates(endpoints)
    assert len(candidates) == 1


# ---------------------------------------------------------------------------
# run_techniques() -- async
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


def _response(status: int, body: str, headers: dict | None = None):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.headers = headers or {}
    return resp


def _fake_context(get_side_effect=None):
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    if get_side_effect is not None:
        context.request.get = AsyncMock(side_effect=get_side_effect)
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


def _by_id(results):
    return {r.technique_id: r for r in results}


@pytest.mark.asyncio
async def test_run_techniques_skipped_when_no_url_shaped_param():
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["query"])
    pool = _pool_with_context(_fake_context())
    session_manager = None  # never consulted -- run_techniques() returns before authenticating when no candidate exists
    module = SsrfTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert len(by_id) == 6
    assert all(r.status == SKIPPED for r in by_id.values())


@pytest.mark.asyncio
async def test_metadata_fingerprint_fails_on_signature(tmp_path):
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])

    def fake_get(url, params=None, max_redirects=0):
        value = params.get("url", "")
        if "169.254.169.254" in value:
            return _response(200, "ami-id\ninstance-id\ninstance-type\n")
        return _response(200, "")  # baseline + loopback: empty/failed fetch

    context = _fake_context(get_side_effect=fake_get)
    module = SsrfTestsModule()

    result = await module._technique_metadata_fingerprint(
        module._param_candidates([endpoint]), context, evidence=None,
    )

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "Critical"


@pytest.mark.asyncio
async def test_metadata_fingerprint_passes_when_no_signature():
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])

    def fake_get(url, params=None, max_redirects=0):
        return _response(200, "same generic response")

    context = _fake_context(get_side_effect=fake_get)
    module = SsrfTestsModule()

    result = await module._technique_metadata_fingerprint(
        module._param_candidates([endpoint]), context, evidence=None,
    )

    assert result.status == PASS


@pytest.mark.asyncio
async def test_blind_timing_fails_on_repeatable_delay(monkeypatch):
    # Mocks send_probe directly (its own elapsed-seconds return value)
    # rather than making a fake context.request.get actually sleep --
    # this codebase's AsyncMock side_effect convention returns whatever
    # a sync side_effect function returns as-is, so an async-def
    # side_effect meant to await asyncio.sleep() doesn't get awaited
    # the way a real Playwright call would be (confirmed empirically
    # elsewhere in this test suite already).
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])
    import stof.modules.ssrf_tests as ssrf_mod

    async def fake_send_probe(context, ep, params, location):
        value = params.get("url", "")
        elapsed = 5.0 if "10.255.255.1" in value else 0.1
        return 200, "ok", elapsed, {}

    monkeypatch.setattr(ssrf_mod, "send_probe", fake_send_probe)
    module = SsrfTestsModule()

    result = await module._technique_blind_timing(
        module._param_candidates([endpoint]), context=None, evidence=None,
    )

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "High"


@pytest.mark.asyncio
async def test_blind_timing_requires_repeatable_delay_not_one_off(monkeypatch):
    """A single slow response must not be enough -- matches
    sqli_tests.py's TC-127.3 discipline (require the delta twice)."""
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])
    import stof.modules.ssrf_tests as ssrf_mod

    calls = {"n": 0}

    async def fake_send_probe(context, ep, params, location):
        value = params.get("url", "")
        if "10.255.255.1" in value:
            calls["n"] += 1
            # Only the FIRST blackhole probe is slow; the confirmation isn't.
            return 200, "ok", (5.0 if calls["n"] == 1 else 0.1), {}
        return 200, "ok", 0.1, {}

    monkeypatch.setattr(ssrf_mod, "send_probe", fake_send_probe)
    module = SsrfTestsModule()

    result = await module._technique_blind_timing(
        module._param_candidates([endpoint]), context=None, evidence=None,
    )

    assert result.status == PASS


@pytest.mark.asyncio
async def test_blind_timing_passes_when_no_delay():
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])

    def fake_get(url, params=None, max_redirects=0):
        return _response(200, "ok")

    context = _fake_context(get_side_effect=fake_get)
    module = SsrfTestsModule()

    result = await module._technique_blind_timing(
        module._param_candidates([endpoint]), context, evidence=None,
    )

    assert result.status == PASS


@pytest.mark.asyncio
async def test_file_scheme_fails_on_passwd_fingerprint():
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])

    def fake_get(url, params=None, max_redirects=0):
        value = params.get("url", "")
        if value.startswith("file://"):
            return _response(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin")
        return _response(200, "")

    context = _fake_context(get_side_effect=fake_get)
    module = SsrfTestsModule()

    result = await module._technique_file_scheme(
        module._param_candidates([endpoint]), context, evidence=None,
    )

    assert result.status == FAIL
    assert result.finding is not None


@pytest.mark.asyncio
async def test_file_scheme_passes_when_no_fingerprint():
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])

    def fake_get(url, params=None, max_redirects=0):
        return _response(200, "not a passwd file")

    context = _fake_context(get_side_effect=fake_get)
    module = SsrfTestsModule()

    result = await module._technique_file_scheme(
        module._param_candidates([endpoint]), context, evidence=None,
    )

    assert result.status == PASS


# ---------------------------------------------------------------------------
# TC-137.4 internal port sweep
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_port_sweep_fails_when_a_port_responds_differently():
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])

    def fake_get(url, params=None, max_redirects=0):
        value = params.get("url", "")
        if "127.0.0.1:6379" in value:
            return _response(200, "-ERR unknown command 'GET'\r\n-ERR wrong number of arguments\r\n")
        return _response(200, "")

    context = _fake_context(get_side_effect=fake_get)
    module = SsrfTestsModule()

    result = await module._technique_internal_port_sweep(
        module._param_candidates([endpoint]), context, evidence=None,
    )

    assert result.status == FAIL
    assert result.finding is not None
    assert "6379" in result.finding.description


@pytest.mark.asyncio
async def test_port_sweep_passes_when_all_ports_match_baseline():
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])

    def fake_get(url, params=None, max_redirects=0):
        return _response(200, "")

    context = _fake_context(get_side_effect=fake_get)
    module = SsrfTestsModule()

    result = await module._technique_internal_port_sweep(
        module._param_candidates([endpoint]), context, evidence=None,
    )

    assert result.status == PASS


# ---------------------------------------------------------------------------
# TC-137.5 IP/hostname parsing bypass
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ip_bypass_fails_when_encoded_variant_succeeds_but_plain_blocked():
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])

    def fake_get(url, params=None, max_redirects=0):
        value = params.get("url", "")
        if "2130706433" in value:  # decimal-encoded 127.0.0.1
            return _response(200, "<html>Internal admin panel</html>")
        return _response(200, "")  # baseline + plain loopback: both blocked/empty

    context = _fake_context(get_side_effect=fake_get)
    module = SsrfTestsModule()

    result = await module._technique_ip_parsing_bypass(
        module._param_candidates([endpoint]), context, evidence=None,
    )

    assert result.status == FAIL
    assert result.finding is not None


@pytest.mark.asyncio
async def test_ip_bypass_skips_when_plain_loopback_already_unrestricted():
    """If the plain form already reaches loopback, TC-137.1 owns that
    finding -- this technique must not double-report it as a 'bypass'
    when nothing was actually bypassed."""
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])

    def fake_get(url, params=None, max_redirects=0):
        value = params.get("url", "")
        if "127.0.0.1" in value or "2130706433" in value:
            return _response(200, "<html>Internal admin panel</html>")
        return _response(200, "")

    context = _fake_context(get_side_effect=fake_get)
    module = SsrfTestsModule()

    result = await module._technique_ip_parsing_bypass(
        module._param_candidates([endpoint]), context, evidence=None,
    )

    assert result.status == PASS


@pytest.mark.asyncio
async def test_ip_bypass_passes_when_no_variant_succeeds():
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])

    def fake_get(url, params=None, max_redirects=0):
        return _response(200, "")

    context = _fake_context(get_side_effect=fake_get)
    module = SsrfTestsModule()

    result = await module._technique_ip_parsing_bypass(
        module._param_candidates([endpoint]), context, evidence=None,
    )

    assert result.status == PASS


# ---------------------------------------------------------------------------
# TC-137.6 OOB callback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oob_callback_skipped_when_not_configured():
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])
    module = SsrfTestsModule(config=SsrfTestConfig(collaborator_url=""))

    result = await module._technique_oob_callback(
        module._param_candidates([endpoint]), context=None, evidence=None,
    )

    assert result.status == SKIPPED
    assert "not configured" in result.detail.lower() or "no out-of-band" in result.detail.lower()


@pytest.mark.asyncio
async def test_oob_callback_sends_marker_and_reports_skipped_with_instructions():
    endpoint = Endpoint(url="https://x/fetch", method="GET", endpoint_type="page", parameters=["url"])

    sent_urls = []

    def fake_get(url, params=None, max_redirects=0):
        sent_urls.append(params.get("url", ""))
        return _response(200, "ok")

    context = _fake_context(get_side_effect=fake_get)
    module = SsrfTestsModule(config=SsrfTestConfig(collaborator_url="oast.example.com"))

    result = await module._technique_oob_callback(
        module._param_candidates([endpoint]), context, evidence=None,
    )

    assert result.status == SKIPPED
    assert "oast.example.com" in sent_urls[0]
    assert "stof-" in sent_urls[0]
    assert "check its dashboard" in result.detail.lower() or "check the collaborator" in result.detail.lower() or "collaborator's own dashboard" in result.detail.lower()
