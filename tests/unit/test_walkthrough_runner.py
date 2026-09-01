"""Unit tests for Layer 13 — stof.reporting.walkthrough_runner."""
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.findings.models import Finding
from stof.reporting import walkthrough_players as wp
from stof.reporting.walkthrough_runner import build_walkthroughs
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


class _FakePage:
    def __init__(self) -> None:
        self.visited_urls: list[str] = []

    def on(self, event, handler) -> None:
        pass

    async def goto(self, url: str, timeout: "int | None" = None) -> None:
        self.visited_urls.append(url)

    async def evaluate(self, *args, **kwargs) -> None:
        pass

    async def screenshot(self, path: str, full_page: bool = True) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\nfake")

    async def close(self) -> None:
        pass


def _fake_context_with_page(page):
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=page)
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


def _finding(vuln_type: str, finding_id: str, role: str = "normal") -> Finding:
    endpoint = Endpoint(url="https://x/target", method="GET", endpoint_type="page")
    return Finding(
        finding_id=finding_id, module_id="m", vuln_type=vuln_type, severity="High", cvss_score=7.0,
        endpoint=endpoint, user_role=role, request_raw="GET https://x/target",
        response_raw="body", description="desc", recommendation="fix",
    )


@pytest.mark.asyncio
async def test_build_walkthroughs_produces_one_per_finding(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context_with_page(_FakePage()))
    findings = [_finding("Missing Security Header", "f1"), _finding("Reflected Cross-Site Scripting", "f2")]

    walkthroughs = await build_walkthroughs(findings, session_manager, pool, "scan1", screenshot_base_dir=tmp_path)

    assert len(walkthroughs) == 2
    assert {w.finding_id for w in walkthroughs} == {"f1", "f2"}
    assert all(w.build_error is None for w in walkthroughs)
    assert all(len(w.steps) > 0 for w in walkthroughs)


@pytest.mark.asyncio
async def test_build_walkthroughs_isolates_one_finding_failure(tmp_path, monkeypatch):
    """One player raising must not stop the others -- the failed
    finding gets a `build_error` set, the rest still get real steps."""
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context_with_page(_FakePage()))
    findings = [_finding("Missing Security Header", "f1"), _finding("Reflected Cross-Site Scripting", "f2")]

    async def _boom(*args, **kwargs):
        raise RuntimeError("simulated player failure")

    monkeypatch.setitem(wp.PLAYERS, "annotated_evidence", _boom)

    walkthroughs = await build_walkthroughs(findings, session_manager, pool, "scan1", screenshot_base_dir=tmp_path)

    by_id = {w.finding_id: w for w in walkthroughs}
    assert by_id["f1"].build_error is not None
    assert "simulated player failure" in by_id["f1"].build_error
    assert by_id["f1"].steps == []
    assert by_id["f2"].build_error is None
    assert len(by_id["f2"].steps) > 0


@pytest.mark.asyncio
async def test_build_walkthroughs_empty_input_returns_empty_list(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(_fake_context_with_page(_FakePage()))

    walkthroughs = await build_walkthroughs([], session_manager, pool, "scan1", screenshot_base_dir=tmp_path)

    assert walkthroughs == []


@pytest.mark.asyncio
async def test_build_walkthroughs_calls_progress_callback(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context_with_page(_FakePage()))
    findings = [_finding("Missing Security Header", "f1")]
    calls = []

    await build_walkthroughs(
        findings, session_manager, pool, "scan1", screenshot_base_dir=tmp_path,
        progress=lambda done, total, label: calls.append((done, total)),
    )

    assert calls[0] == (0, 1)
    assert calls[-1] == (1, 1)
