"""Unit tests for Layer 6 — stof.workflows.repository."""
import json

import pytest

from stof.workflows.models import NeutralAction, Workflow
from stof.workflows.repository import WorkflowNotFoundError, WorkflowRepository


def _write(tmp_path, filename: str, data: dict) -> None:
    (tmp_path / filename).write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_reload_indexes_json_files_with_name_from_filename(tmp_path):
    _write(
        tmp_path,
        "test_login.json",
        {"workflow_id": "wf-1", "target_url": "https://x", "actions": []},
    )

    repo = WorkflowRepository(workflows_dir=tmp_path)

    workflow = repo.get("wf-1")
    assert workflow.name == "test_login"
    assert workflow.target_url == "https://x"


def test_list_returns_every_indexed_workflow(tmp_path):
    _write(tmp_path, "a.json", {"workflow_id": "wf-a", "target_url": "https://x", "actions": []})
    _write(tmp_path, "b.json", {"workflow_id": "wf-b", "target_url": "https://x", "actions": []})

    repo = WorkflowRepository(workflows_dir=tmp_path)

    assert {w.workflow_id for w in repo.list()} == {"wf-a", "wf-b"}


def test_save_writes_file_and_indexes_immediately(tmp_path):
    repo = WorkflowRepository(workflows_dir=tmp_path)
    workflow = Workflow(
        workflow_id="wf-new", target_url="https://x", actions=[NeutralAction(type="navigate", url="https://x")]
    )

    path = repo.save(workflow)

    assert path == tmp_path / "wf-new.json"
    assert path.is_file()
    assert repo.get("wf-new") is workflow


def test_save_with_explicit_filename(tmp_path):
    repo = WorkflowRepository(workflows_dir=tmp_path)
    workflow = Workflow(workflow_id="wf-custom", target_url="https://x")

    path = repo.save(workflow, filename="my_flow.json")

    assert path == tmp_path / "my_flow.json"


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------


def test_get_unknown_workflow_id_raises(tmp_path):
    repo = WorkflowRepository(workflows_dir=tmp_path)

    with pytest.raises(WorkflowNotFoundError, match="wf-ghost"):
        repo.get("wf-ghost")


def test_reload_skips_malformed_json_without_crashing(tmp_path):
    (tmp_path / "broken.json").write_text("{not valid json", encoding="utf-8")
    _write(tmp_path, "good.json", {"workflow_id": "wf-good", "target_url": "https://x", "actions": []})

    repo = WorkflowRepository(workflows_dir=tmp_path)

    assert [w.workflow_id for w in repo.list()] == ["wf-good"]


def test_reload_skips_json_missing_workflow_id(tmp_path):
    _write(tmp_path, "no_id.json", {"target_url": "https://x", "actions": []})

    repo = WorkflowRepository(workflows_dir=tmp_path)

    assert repo.list() == []


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_repository_on_missing_directory_starts_empty(tmp_path):
    repo = WorkflowRepository(workflows_dir=tmp_path / "does_not_exist")

    assert repo.list() == []


def test_reload_rebuilds_index_reflecting_files_added_since_construction(tmp_path):
    repo = WorkflowRepository(workflows_dir=tmp_path)
    assert repo.list() == []

    _write(tmp_path, "late.json", {"workflow_id": "wf-late", "target_url": "https://x", "actions": []})
    repo.reload()

    assert repo.get("wf-late").workflow_id == "wf-late"
