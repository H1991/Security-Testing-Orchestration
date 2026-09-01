"""Unit tests for Layer 6 — stof.workflows.runner."""
from unittest.mock import AsyncMock

import pytest

from stof.config.schema import UserConfig, UsersConfig
from stof.session.models import Session
from stof.workflows.models import NeutralAction, Workflow
from stof.workflows.repository import WorkflowRepository
from stof.workflows.runner import WorkflowRunner

USERS = UsersConfig(
    users=[
        UserConfig(id="admin-01", role="admin", username="admin", password="s3cr3t", auth_type="form_login"),
    ]
)


def _repo_with(workflow: Workflow, tmp_path) -> WorkflowRepository:
    repo = WorkflowRepository(workflows_dir=tmp_path)
    repo.save(workflow)
    return repo


def _token_workflow() -> Workflow:
    return Workflow(
        workflow_id="wf-1",
        target_url="https://demo.testfire.net",
        actions=[
            NeutralAction(type="navigate", url="https://demo.testfire.net/login.jsp"),
            NeutralAction(type="fill", selector="#uid", value="{{user.username}}"),
            NeutralAction(type="fill", selector="#passw", value="{{user.password}}"),
            NeutralAction(type="click", selector="button"),
        ],
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_workflow_resolves_tokens_and_calls_engine_replay(tmp_path):
    repo = _repo_with(_token_workflow(), tmp_path)
    engine = AsyncMock()
    engine.replay = AsyncMock(return_value="fake-result")
    runner = WorkflowRunner(repository=repo, engine=engine, users=USERS)
    session = Session(user_id="admin-01", role="admin", auth_type="form_login")

    result = await runner.run_workflow("wf-1", session)

    assert result == "fake-result"
    engine.replay.assert_awaited_once()
    (called_workflow_dict, called_session) = engine.replay.await_args.args
    assert called_session is session
    assert called_workflow_dict["actions"][1]["value"] == "admin"
    assert called_workflow_dict["actions"][2]["value"] == "s3cr3t"


@pytest.mark.asyncio
async def test_run_workflow_leaves_non_token_values_unchanged(tmp_path):
    workflow = Workflow(
        workflow_id="wf-2",
        target_url="https://x",
        actions=[NeutralAction(type="fill", selector="#q", value="search term")],
    )
    repo = _repo_with(workflow, tmp_path)
    engine = AsyncMock()
    engine.replay = AsyncMock(return_value=None)
    runner = WorkflowRunner(repository=repo, engine=engine, users=USERS)
    session = Session(user_id="admin-01", role="admin", auth_type="form_login")

    await runner.run_workflow("wf-2", session)

    called_workflow_dict = engine.replay.await_args.args[0]
    assert called_workflow_dict["actions"][0]["value"] == "search term"


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_workflow_unknown_workflow_id_propagates_not_found(tmp_path):
    from stof.workflows.repository import WorkflowNotFoundError

    repo = WorkflowRepository(workflows_dir=tmp_path)
    engine = AsyncMock()
    runner = WorkflowRunner(repository=repo, engine=engine, users=USERS)
    session = Session(user_id="admin-01", role="admin", auth_type="form_login")

    with pytest.raises(WorkflowNotFoundError):
        await runner.run_workflow("wf-ghost", session)

    engine.replay.assert_not_awaited()


# ---------------------------------------------------------------------------
# Input validation — session.user_id with no matching UserConfig
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_workflow_leaves_token_unresolved_when_no_matching_user(tmp_path, monkeypatch):
    repo = _repo_with(_token_workflow(), tmp_path)
    engine = AsyncMock()
    engine.replay = AsyncMock(return_value=None)
    runner = WorkflowRunner(repository=repo, engine=engine, users=USERS)
    session = Session(user_id="ghost-99", role="admin", auth_type="form_login")

    warnings = []
    import stof.workflows.runner as runner_module

    monkeypatch.setattr(runner_module._log, "warning", lambda msg, *a, **k: warnings.append(msg))

    await runner.run_workflow("wf-1", session)

    called_workflow_dict = engine.replay.await_args.args[0]
    assert called_workflow_dict["actions"][1]["value"] == "{{user.username}}"
    assert any("cannot resolve token" in w for w in warnings)
