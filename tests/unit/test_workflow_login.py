"""Unit tests for Layer 4 -- stof.auth.workflow_login."""
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthExpiredError, AuthFailedError
from stof.auth.workflow_login import WorkflowLoginProvider
from stof.config.schema import UserConfig
from stof.session.models import Session
from stof.workflows.models import NeutralAction, Workflow
from stof.workflows.repository import WorkflowNotFoundError

LOGIN_URL = "https://spa.example/login"


def _user(login_workflow_id: str | None = "spa-login") -> UserConfig:
    return UserConfig(
        id="admin-01", role="admin", username="admin@example.com", password="s3cr3t",
        auth_type="recorded_workflow", login_workflow_id=login_workflow_id,
    )


def _page(url: str, cookies: list[dict] | None = None, storage_token: str | None = None) -> AsyncMock:
    page = AsyncMock()
    page.url = url
    page.context.cookies = AsyncMock(return_value=cookies or [])
    page.evaluate = AsyncMock(return_value=storage_token)
    return page


class _FakeRepository:
    """Stand-in for `WorkflowRepository` -- a plain dict lookup, same
    shape as the real one's own `.get()`, so `WorkflowLoginProvider`
    never knows the difference."""

    def __init__(self, workflows: dict[str, Workflow]):
        self._workflows = workflows

    def get(self, workflow_id: str) -> Workflow:
        if workflow_id not in self._workflows:
            raise WorkflowNotFoundError(f"no workflow indexed with workflow_id '{workflow_id}'")
        return self._workflows[workflow_id]


def _login_workflow(*, ends_with_wait: bool = False) -> Workflow:
    actions = [
        NeutralAction(type="navigate", url=LOGIN_URL),
        NeutralAction(type="fill", selector="#email", value="{{user.username}}"),
        NeutralAction(type="fill", selector="#password", value="{{user.password}}"),
        NeutralAction(type="click", selector="#submit"),
    ]
    if ends_with_wait:
        actions.append(NeutralAction(type="wait_for", selector="#dashboard", timeout_ms=5000))
    return Workflow(workflow_id="spa-login", target_url=LOGIN_URL, actions=actions)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_resolves_credential_tokens_and_replays_actions():
    workflow = _login_workflow()
    provider = WorkflowLoginProvider(_FakeRepository({"spa-login": workflow}))
    page = _page("https://spa.example/dashboard", cookies=[{"name": "session", "value": "abc123"}])

    session = await provider.authenticate(_user(), page)

    page.goto.assert_awaited_once_with(LOGIN_URL)
    page.fill.assert_any_await("#email", "admin@example.com")
    page.fill.assert_any_await("#password", "s3cr3t")
    page.click.assert_awaited_once_with("#submit")
    assert session.auth_type == "recorded_workflow"
    assert session.cookies == {"session": "abc123"}
    assert session.role == "admin"
    assert session.expires_at is not None


@pytest.mark.asyncio
async def test_authenticate_captures_a_spa_storage_token_as_bearer_header():
    """Modern SPAs often stash the real auth token in localStorage
    rather than a cookie -- the same `extract_storage_token` fallback
    `FormLoginProvider` already relies on, reused here rather than
    duplicated."""
    workflow = _login_workflow(ends_with_wait=True)
    provider = WorkflowLoginProvider(_FakeRepository({"spa-login": workflow}))
    page = _page("https://spa.example/dashboard", storage_token="eyJhbGci.eyJzdWIi.abc123signature")

    session = await provider.authenticate(_user(), page)

    assert session.headers == {"Authorization": "Bearer eyJhbGci.eyJzdWIi.abc123signature"}


@pytest.mark.asyncio
async def test_authenticate_waits_for_settle_only_when_workflow_has_no_trailing_wait_for():
    workflow_without_wait = _login_workflow(ends_with_wait=False)
    provider = WorkflowLoginProvider(_FakeRepository({"spa-login": workflow_without_wait}))
    page = _page("https://spa.example/dashboard", cookies=[{"name": "s", "value": "v"}])

    await provider.authenticate(_user(), page)

    page.wait_for_url.assert_awaited()


@pytest.mark.asyncio
async def test_authenticate_skips_the_generic_settle_when_recording_already_asserts_one():
    workflow_with_wait = _login_workflow(ends_with_wait=True)
    provider = WorkflowLoginProvider(_FakeRepository({"spa-login": workflow_with_wait}))
    page = _page("https://spa.example/dashboard", cookies=[{"name": "s", "value": "v"}])
    page.wait_for_selector = AsyncMock(return_value=None)

    await provider.authenticate(_user(), page)

    page.wait_for_selector.assert_awaited_once()  # the recorded wait_for action itself
    page.wait_for_url.assert_not_awaited()  # no second, generic settle on top of it


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_raises_when_no_workflow_id_configured():
    provider = WorkflowLoginProvider(_FakeRepository({}))
    with pytest.raises(AuthFailedError, match="no login_workflow_id configured"):
        await provider.authenticate(_user(login_workflow_id=None), _page(LOGIN_URL))


@pytest.mark.asyncio
async def test_authenticate_raises_when_the_configured_workflow_does_not_exist():
    provider = WorkflowLoginProvider(_FakeRepository({}))
    with pytest.raises(AuthFailedError, match="no workflow indexed"):
        await provider.authenticate(_user(login_workflow_id="missing"), _page(LOGIN_URL))


@pytest.mark.asyncio
async def test_authenticate_raises_when_an_action_fails_mid_replay():
    workflow = _login_workflow()
    provider = WorkflowLoginProvider(_FakeRepository({"spa-login": workflow}))
    page = _page(LOGIN_URL)
    page.fill = AsyncMock(side_effect=TimeoutError("selector not found"))

    with pytest.raises(AuthFailedError, match="failed on action 'fill'"):
        await provider.authenticate(_user(), page)


@pytest.mark.asyncio
async def test_authenticate_raises_when_nothing_usable_was_captured():
    """A recording that doesn't actually complete login (bad selector
    that silently no-ops, wrong target) must fail loudly, not hand back
    an empty, useless session that looks superficially fine."""
    workflow = _login_workflow(ends_with_wait=True)
    provider = WorkflowLoginProvider(_FakeRepository({"spa-login": workflow}))
    page = _page("https://spa.example/dashboard", cookies=[], storage_token=None)
    page.wait_for_selector = AsyncMock(return_value=None)

    with pytest.raises(AuthFailedError, match="finished with no cookies"):
        await provider.authenticate(_user(), page)


@pytest.mark.asyncio
async def test_refresh_always_raises_auth_expired():
    """A recorded workflow is cheap to re-run -- refreshing means a full
    fresh authenticate(), same convention FormLoginProvider's own
    refresh() already establishes, not a bespoke incremental path."""
    provider = WorkflowLoginProvider(_FakeRepository({}))
    session = Session(user_id="admin-01", role="admin", auth_type="recorded_workflow", cookies={"a": "b"})

    with pytest.raises(AuthExpiredError, match="needs a fresh authenticate"):
        await provider.refresh(session, _page(LOGIN_URL))


# ---------------------------------------------------------------------------
# is_authenticated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_authenticated_false_when_session_marked_invalid():
    provider = WorkflowLoginProvider(_FakeRepository({}))
    session = Session(user_id="admin-01", role="admin", auth_type="recorded_workflow", cookies={"a": "b"}, is_valid=False)

    assert await provider.is_authenticated(session, _page(LOGIN_URL)) is False


@pytest.mark.asyncio
async def test_is_authenticated_true_when_cookies_still_match():
    provider = WorkflowLoginProvider(_FakeRepository({}))
    session = Session(user_id="admin-01", role="admin", auth_type="recorded_workflow", cookies={"session": "abc123"})
    page = _page(LOGIN_URL, cookies=[{"name": "session", "value": "abc123"}])

    assert await provider.is_authenticated(session, page) is True
