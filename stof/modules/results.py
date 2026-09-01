"""Layer 9 — `TestCaseResult`: the per-technique execution record.

`Finding` (Layer 10) only exists for a confirmed vulnerability -- there
was never a record of a technique that ran and found nothing, or one
that had no applicable surface on this target. `TestCaseResult` is the
superset: one record per exploit technique attempted, whatever the
outcome, so a scan can report "58 techniques run, 6 FAIL, 44 PASS, 8
NOT_IMPLEMENTED" instead of only ever showing the FAILs.

Deliberately a sibling of `Finding`, not a replacement for it: reports,
the findings store, and every FAIL-only consumer built before this
existed keep working unchanged by calling `extract_findings()` to get
the exact `list[Finding]` they always expected.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint
    from stof.findings.models import Finding

# A technique's outcome, in the vocabulary a pentest report reads
# naturally: FAIL means the target failed to resist the attack (i.e.
# it's exploitable -- the "bad" outcome, backed by a Finding); PASS
# means the technique was attempted and the target resisted it;
# SKIPPED means the technique never got to run because this target/run
# has no applicable surface for it (e.g. no JWT-authenticated role
# configured); NOT_IMPLEMENTED means the technique is designed
# (tracked in EXPLOIT_COVERAGE.md) but no code exists for it yet;
# ERROR means the probe itself broke (network/parsing failure), not a
# security judgement either way.
PASS = "PASS"
FAIL = "FAIL"
SKIPPED = "SKIPPED"
NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
ERROR = "ERROR"

STATUSES = (PASS, FAIL, SKIPPED, NOT_IMPLEMENTED, ERROR)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class TestCaseResult:
    # Tells pytest not to try collecting this as a test class purely
    # because its name starts with "Test" -- it's a data record, not a
    # test case itself.
    __test__ = False

    test_id: str  # catalog id from EXPLOIT_COVERAGE.md, e.g. "TC-053"
    technique_id: str  # per-technique id, e.g. "TC-053.2"
    technique: str  # short technique description, e.g. "Query-parameter ID substitution"
    vuln_type: str
    module_id: str
    severity: str
    status: str  # one of STATUSES
    detail: str  # human-readable outcome, shown in CLI / report
    user_role: str | None = None
    endpoint: "Endpoint | None" = None
    finding: "Finding | None" = None  # populated only when status == FAIL
    executed_at: datetime = field(default_factory=_utcnow)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unknown TestCaseResult status: {self.status!r}")
        if self.status == FAIL and self.finding is None:
            raise ValueError(f"{self.technique_id}: status FAIL requires a Finding")

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "technique_id": self.technique_id,
            "technique": self.technique,
            "vuln_type": self.vuln_type,
            "module_id": self.module_id,
            "severity": self.severity,
            "status": self.status,
            "detail": self.detail,
            "user_role": self.user_role,
            "endpoint": self.endpoint.to_dict() if self.endpoint is not None else None,
            "finding_id": self.finding.finding_id if self.finding is not None else None,
            "executed_at": self.executed_at.isoformat(),
        }


def extract_findings(results: list[TestCaseResult]) -> list["Finding"]:
    """The exact `list[Finding]` every FAIL-only consumer (findings
    store, HTML/JSON/Excel reports) already expects.

    Deduplicated by `finding_id`: some techniques (e.g. TC-050.1/.2)
    deliberately reuse another technique's already-confirmed `Finding`
    object as evidence for an umbrella category rather than probing
    again -- without this, the same underlying vulnerability inflates
    the Critical count once per technique that reused it instead of
    once per actual root cause (a real reviewer flagged this exact
    "11 Critical findings" over-count against this project's own
    scan output)."""
    findings: list[Finding] = []
    seen_ids: set[str] = set()
    for r in results:
        if r.status != FAIL or r.finding is None:
            continue
        if r.finding.finding_id in seen_ids:
            continue
        seen_ids.add(r.finding.finding_id)
        findings.append(r.finding)
    return findings


def summarize(results: list[TestCaseResult]) -> dict[str, int]:
    counts = {status: 0 for status in STATUSES}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts
