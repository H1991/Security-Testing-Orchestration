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


def _root_cause_key(finding: "Finding") -> tuple[str, str, str, str]:
    """Groups findings that are, in practice, the SAME underlying gap
    independently confirmed by different sub-techniques of the same
    umbrella family -- e.g. TC-055.1 (URL-naming heuristic) and TC-055.5
    (role-differential matrix) both flagging BFLA on the identical
    endpoint. `module_id` is part of the key specifically so this never
    merges genuinely distinct vulnerability classes that happen to
    share an endpoint (a real SQLi finding from `sqli_tests` and a real
    XSS finding from `xss_tests` on the same URL stay two findings, not
    one) -- only sibling `.N` techniques under the same top-level `TC-`
    id, on the same endpoint, from the same module, count as the same
    root cause."""
    from stof.payloads.registry import UnknownTestCaseError, top_level_id

    try:
        family = top_level_id(finding.technique_id) if finding.technique_id else finding.vuln_type
    except UnknownTestCaseError:
        family = finding.technique_id
    return (finding.module_id, family, finding.endpoint.method, finding.endpoint.url)


def _merge_root_cause_duplicates(findings: list["Finding"]) -> list["Finding"]:
    """Second dedup pass, on top of `extract_findings()`'s own literal-
    `finding_id` dedup: when 2+ DIFFERENT `Finding` objects (different
    techniques, independently confirmed, never reusing each other's
    object) land on the same `_root_cause_key`, keep only the highest-
    severity one and note in its own description how many sibling
    techniques independently confirmed the same gap -- strengthening
    confidence in the kept finding rather than silently discarding the
    corroborating signal. Ties broken by encounter order (stable,
    deterministic -- matches the order techniques actually ran in)."""
    groups: dict[tuple[str, str, str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault(_root_cause_key(f), []).append(f)

    merged: list[Finding] = []
    for group in groups.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        canonical = max(group, key=lambda f: f.cvss_score)
        others = [f for f in group if f is not canonical]
        technique_ids = ", ".join(sorted({f.technique_id for f in others if f.technique_id}))
        canonical.description += (
            f" Independently confirmed by {len(others)} other technique(s) against the same "
            f"endpoint ({technique_ids}), consolidated here as one finding rather than counted separately."
        )
        merged.append(canonical)
    return merged


def extract_findings(results: list[TestCaseResult]) -> list["Finding"]:
    """The exact `list[Finding]` every FAIL-only consumer (findings
    store, HTML/JSON/Excel reports) already expects.

    Two dedup passes. First, by `finding_id`: some techniques (e.g.
    TC-050.1/.2) deliberately reuse another technique's already-
    confirmed `Finding` OBJECT as evidence for an umbrella category
    rather than probing again. Second, by `_root_cause_key()`: DIFFERENT
    `Finding` objects from sibling sub-techniques of the same umbrella
    family, independently confirming the same gap on the same endpoint,
    get consolidated into one. Without either, the same underlying
    vulnerability inflates the Critical count once per technique that
    touched it instead of once per actual root cause (a real reviewer
    flagged exactly this "11 Critical findings" over-count against this
    project's own scan output -- the first pass fixed the literal-reuse
    half of it; the second closes the independently-confirmed half)."""
    from stof.findings.classification import classify_finding_taxonomy
    from stof.findings.cvss import cvss_vector_for_finding
    from stof.findings.fingerprint import compute_fingerprint

    findings: list[Finding] = []
    seen_ids: set[str] = set()
    for r in results:
        if r.status != FAIL or r.finding is None:
            continue
        if r.finding.finding_id in seen_ids:
            continue
        seen_ids.add(r.finding.finding_id)
        # Stamped here, not at each of the ~130 `Finding(...)` call
        # sites across the vuln modules -- this is the one place every
        # module's results already funnel through, and the one place
        # that has both the `Finding` and the `TestCaseResult` (whose
        # `technique_id` a bare `Finding` never carried) in hand
        # together. See `Finding.technique_id`'s own docstring.
        r.finding.technique_id = r.technique_id
        r.finding.cwe, r.finding.owasp_category = classify_finding_taxonomy(r.finding)
        r.finding.cvss_vector = cvss_vector_for_finding(r.finding)
        # Stamped AFTER technique_id above -- compute_fingerprint()
        # reads it (falling back to vuln_type only when unset). See
        # `Finding.fingerprint`'s own docstring for why this is the
        # cross-scan identity a baseline/diff report needs.
        r.finding.fingerprint = compute_fingerprint(r.finding)
        findings.append(r.finding)
    return _merge_root_cause_duplicates(findings)


def summarize(results: list[TestCaseResult]) -> dict[str, int]:
    counts = {status: 0 for status in STATUSES}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def skipped_techniques(results: list[TestCaseResult]) -> list[dict[str, str]]:
    """Every technique that never ran, with why -- for report visibility,
    not a security judgment. `summarize()`'s counts are already CLI-only
    (`main.py`'s console output); this is the list form the HTML/JSON
    reports thread through so a reader isn't left to infer "0 findings"
    means "every technique ran". A technique gated behind
    `allow_state_changing_probes` (the plant-then-verify family: stored
    XSS, second-order SQLi, CSV injection, ...) is the single most common
    reason a clean-looking report is missing real coverage -- an external
    review specifically flagged that this was previously invisible
    outside the scan's own transient stdout."""
    return [
        {"technique_id": r.technique_id, "technique": r.technique, "module_id": r.module_id, "reason": r.detail}
        for r in results if r.status == SKIPPED
    ]
