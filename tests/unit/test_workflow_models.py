"""Unit tests for Layer 6 — stof.workflows.models."""
from datetime import datetime, timezone

from stof.workflows.models import NeutralAction, Workflow

# ---------------------------------------------------------------------------
# Happy path — NeutralAction
# ---------------------------------------------------------------------------


def test_neutral_action_to_dict_omits_unset_fields():
    action = NeutralAction(type="navigate", url="https://demo.testfire.net/login.jsp")

    assert action.to_dict() == {"type": "navigate", "url": "https://demo.testfire.net/login.jsp"}


def test_neutral_action_round_trips_through_dict():
    action = NeutralAction(type="wait_for", selector="text=Welcome", timeout_ms=5000)

    restored = NeutralAction.from_dict(action.to_dict())

    assert restored == action


# ---------------------------------------------------------------------------
# Happy path — Workflow, matching Layer 3A's actual exported shape
# ---------------------------------------------------------------------------

_RECORDED_WORKFLOW_JSON = {
    "workflow_id": "wf-20260722-b8d4d7",
    "target_url": "https://demo.testfire.net/bank/main.jsp",
    "recorded_at": "2026-07-22T06:49:58.570820+00:00",
    "actions": [
        {"type": "navigate", "url": "https://demo.testfire.net/login.jsp"},
        {"type": "fill", "selector": "#uid", "value": "{{user.username}}"},
        {"type": "fill", "selector": "#passw", "value": "{{user.password}}"},
        {"type": "click", "selector": "button[type=submit]"},
        {"type": "wait_for", "selector": "text=Welcome", "timeout_ms": 5000},
    ],
}


def test_workflow_from_dict_parses_a_real_recorded_workflow():
    workflow = Workflow.from_dict(_RECORDED_WORKFLOW_JSON, name="test_login")

    assert workflow.workflow_id == "wf-20260722-b8d4d7"
    assert workflow.name == "test_login"
    assert len(workflow.actions) == 5
    assert workflow.actions[1].value == "{{user.username}}"
    assert workflow.recorded_at == datetime(2026, 7, 22, 6, 49, 58, 570820, tzinfo=timezone.utc)


def test_workflow_to_dict_round_trips_to_the_exact_recorded_shape():
    workflow = Workflow.from_dict(_RECORDED_WORKFLOW_JSON, name="test_login")

    assert workflow.to_dict() == _RECORDED_WORKFLOW_JSON


def test_workflow_to_dict_never_includes_name():
    workflow = Workflow.from_dict(_RECORDED_WORKFLOW_JSON, name="test_login")

    assert "name" not in workflow.to_dict()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_workflow_from_dict_without_recorded_at_defaults_to_none():
    data = {"workflow_id": "wf-x", "target_url": "https://x", "actions": []}

    workflow = Workflow.from_dict(data)

    assert workflow.recorded_at is None
    assert workflow.name is None
