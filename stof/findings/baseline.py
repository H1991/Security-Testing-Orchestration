"""Baseline/diff mode -- "what changed since the last scan of this
target", the CI-usability feature every one of the four external
reviews independently named as the highest-leverage next step, and
which explicitly depends on `Finding.fingerprint` (a stable cross-scan
identity) existing first.

Two halves:
  1. `find_baseline_scan_id()` -- which PRIOR scan (of the same target)
     to diff against. Reads the already-written report JSON files under
     `data/reports/` (each one already carries `"target"` and
     `"generated_at"`, per `json_report.build_report()`) rather than
     inventing a new scan-id-to-target index: `FindingDB` itself has no
     target column (a scan with zero findings would be invisible to it
     entirely), but every completed scan -- findings or not -- writes a
     report.
  2. `compute_diff()` -- pure, fingerprint-set comparison between two
     `list[Finding]`. No I/O, independently testable.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from .models import Finding

_log = get_logger("findings.baseline")

DEFAULT_REPORTS_DIR = Path("data/reports")


def find_baseline_scan_id(
    target: str, current_scan_id: str, reports_dir: "str | Path" = DEFAULT_REPORTS_DIR,
) -> "str | None":
    """The most recent PRIOR scan's id for the same `target`, or `None`
    if this is the first scan of this target (or the reports directory
    doesn't exist yet). "Same target" is an exact string match on
    `scan_metadata["target"]` (`config.target.base_url`) -- deliberately
    not a normalized/fuzzy match, since two genuinely different targets
    that happen to share a host but differ by path prefix must never be
    silently diffed against each other."""
    reports_dir = Path(reports_dir)
    if not reports_dir.is_dir():
        return None

    candidates: list[tuple[str, str]] = []  # (generated_at, scan_id)
    for path in reports_dir.glob("scan_*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _log.warning(f"could not read report '{path}' while looking for a baseline scan: {exc}")
            continue
        scan_id = data.get("scan_id")
        generated_at = data.get("generated_at")
        if scan_id is None or scan_id == current_scan_id or generated_at is None:
            continue
        if data.get("target") != target:
            continue
        candidates.append((generated_at, scan_id))

    if not candidates:
        return None
    candidates.sort()  # ISO 8601 timestamps sort chronologically as plain strings
    return candidates[-1][1]


@dataclass
class BaselineDiff:
    baseline_scan_id: "str | None"
    new: "list[Finding]" = field(default_factory=list)
    resolved: "list[Finding]" = field(default_factory=list)
    unchanged_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_scan_id": self.baseline_scan_id,
            "new_count": len(self.new),
            "resolved_count": len(self.resolved),
            "unchanged_count": self.unchanged_count,
            "new": [f.to_dict() for f in self.new],
            "resolved": [f.to_dict() for f in self.resolved],
        }


def compute_diff(previous: "list[Finding]", current: "list[Finding]", baseline_scan_id: "str | None") -> BaselineDiff:
    """Pure fingerprint-set comparison, no I/O. `new` -- in `current`,
    not in `previous` (a genuinely new finding, or the first time this
    target has ever been scanned when `previous` is empty). `resolved`
    -- in `previous`, not in `current` (either actually fixed, or a
    false negative this run -- this function has no way to tell those
    apart, and says so nowhere it can't back up; the report layer's own
    wording should stay equally honest). `unchanged_count` -- present in
    both, the same open issue persisting; only a count, not the list
    itself, since the finding objects already show up in the "all
    findings" section of the same report and don't need to be shown
    twice.

    A `Finding` with no `fingerprint` set (constructed directly, outside
    `extract_findings()`) is treated as always-new and never-resolvable
    -- it can't be matched against anything, which is the honest
    behavior, not an error."""
    previous_by_fp = {f.fingerprint: f for f in previous if f.fingerprint}
    current_by_fp = {f.fingerprint: f for f in current if f.fingerprint}

    # A fingerprint-less finding (constructed directly, outside
    # extract_findings()) can't be matched against anything -- it's
    # always reported as new, and never eligible to be reported as
    # resolved (which would require having matched it against a prior
    # scan's finding in the first place).
    new = [f for f in current if not f.fingerprint or f.fingerprint not in previous_by_fp]
    resolved = [f for f in previous if f.fingerprint and f.fingerprint not in current_by_fp]
    unchanged_count = len(set(previous_by_fp) & set(current_by_fp))

    return BaselineDiff(baseline_scan_id=baseline_scan_id, new=new, resolved=resolved, unchanged_count=unchanged_count)
