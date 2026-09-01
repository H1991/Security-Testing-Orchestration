"""Layer 6 — load / store / list workflows.

Scans `data/workflows/` and indexes every `.json` file, keyed by the
`workflow_id` in its contents. The human-readable `name` CLAUDE.md
mentions comes from the filename (stem), since the neutral JSON schema
itself has no name field.
"""
from __future__ import annotations

import json
from pathlib import Path

from stof.core.logger import get_logger

from .models import Workflow

_log = get_logger("workflows.repository")

DEFAULT_WORKFLOWS_DIR = Path("data/workflows")


class WorkflowNotFoundError(Exception):
    """Raised when a requested workflow_id isn't in the repository."""


class WorkflowRepository:
    def __init__(self, workflows_dir: str | Path = DEFAULT_WORKFLOWS_DIR) -> None:
        self._dir = Path(workflows_dir)
        self._by_id: dict[str, Workflow] = {}
        self.reload()

    def reload(self) -> None:
        """Re-scan `workflows_dir` and rebuild the index."""
        self._by_id.clear()
        if not self._dir.is_dir():
            return

        for path in sorted(self._dir.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                _log.warning(f"skipping unparsable workflow file '{path}': {exc}")
                continue

            if "workflow_id" not in raw:
                _log.warning(f"skipping '{path}': no workflow_id field")
                continue

            workflow = Workflow.from_dict(raw, name=path.stem)
            self._by_id[workflow.workflow_id] = workflow

        _log.info(f"indexed {len(self._by_id)} workflow(s) from '{self._dir}'")

    def get(self, workflow_id: str) -> Workflow:
        workflow = self._by_id.get(workflow_id)
        if workflow is None:
            raise WorkflowNotFoundError(f"no workflow indexed with workflow_id '{workflow_id}'")
        return workflow

    def list(self) -> list[Workflow]:
        return list(self._by_id.values())

    def save(self, workflow: Workflow, filename: str | None = None) -> Path:
        """Write `workflow` to `workflows_dir` (default filename
        `<workflow_id>.json`) and index it immediately."""
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / (filename or f"{workflow.workflow_id}.json")
        path.write_text(json.dumps(workflow.to_dict(), indent=2) + "\n", encoding="utf-8")
        self._by_id[workflow.workflow_id] = workflow
        return path
