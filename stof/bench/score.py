"""Precision/recall benchmarking against known-vulnerable/known-clean
targets -- turns "154 techniques" from a vanity number into a measured
claim, per every one of four independent external reviews of this
project naming it as the highest-leverage validation work.

Two halves, deliberately scored separately rather than forced into one
number, because they need two DIFFERENT kinds of target:

  - **Recall** (`score_recall`) needs a KNOWN-VULNERABLE target with a
    curated ground-truth manifest of what SHOULD be found (a
    `benchmarks/*.json` file -- see `benchmarks/README.md`). Answers:
    "of the vulnerabilities we know are really there, how many did STOF
    actually catch?"
  - **False-positive rate** (`score_false_positives`) needs the
    OPPOSITE: a target explicitly known to have NONE of the
    vulnerability classes being tested (a clean reference app, or a
    hardened/patched build of a benchmark app). Any FAIL finding
    against it is, by definition, a false positive -- answers: "of the
    things STOF claimed to find, how many weren't real?"

A recall number alone is a poster ("84% recall on WebGoat!"); a
recall number WITHOUT a false-positive number from a clean target is
not a real precision/recall benchmark, it's half of one -- this is the
exact critique an external review made of using only Juice Shop
(intentionally vulnerability-dense, not built for automated scoring)
as the sole benchmark target.

Both functions are pure -- they operate on already-loaded dicts (a
scan's own JSON report shape, from `stof.reporting.json_report`, and a
benchmark manifest dict), with no I/O and no dependency on a live scan
having just run. Loading files and running the actual scan is the
caller's job (a `stof bench` CLI command, or a CI step) -- kept
separate so the scoring logic itself is trivially unit-testable against
fixture dicts, not real scan output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _finding_matches_expectation(finding: dict[str, Any], expectation: dict[str, Any]) -> bool:
    """A report finding satisfies one manifest expectation when its
    `technique_id` matches (either the exact sub-technique, e.g.
    "TC-022.1", or the manifest naming only the top-level family, e.g.
    "TC-022", which matches any of its sub-techniques) AND the
    finding's endpoint URL contains the expectation's
    `endpoint_pattern` as a substring. Deliberately substring, not
    regex or exact match -- a benchmark app's own URL can carry a
    session-scoped id/query string the manifest author can't predict
    in advance; the PATH the manifest names is the part that's stable."""
    technique_id = finding.get("technique_id") or ""
    expected_technique = expectation["technique_id"]
    technique_matches = technique_id == expected_technique or technique_id.startswith(f"{expected_technique}.")
    if not technique_matches:
        return False
    endpoint_url = (finding.get("endpoint") or {}).get("url", "")
    return expectation["endpoint_pattern"] in endpoint_url


@dataclass
class BenchmarkScore:
    manifest_name: str
    target: str
    expected_total: int
    detected: "list[dict[str, str]]" = field(default_factory=list)  # [{technique_id, endpoint_pattern, description}]
    missed: "list[dict[str, str]]" = field(default_factory=list)

    @property
    def recall(self) -> float:
        return len(self.detected) / self.expected_total if self.expected_total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_name": self.manifest_name,
            "target": self.target,
            "expected_total": self.expected_total,
            "detected_count": len(self.detected),
            "missed_count": len(self.missed),
            "recall": round(self.recall, 4),
            "detected": self.detected,
            "missed": self.missed,
        }


def score_recall(report: dict[str, Any], manifest: dict[str, Any]) -> BenchmarkScore:
    """Matches every `manifest["expected_findings"]` entry against
    `report["findings"]` (a scan's own JSON report, already
    `json.load()`ed). See `_finding_matches_expectation`'s own
    docstring for the match rule. An expectation with a malformed
    finding list, or a manifest with zero expected findings, still
    returns a valid (if degenerate, `recall=0.0`) score rather than
    raising -- a benchmark run should never crash a CI job over a bad
    fixture; the score itself (0.0 expected_total) is the signal
    something's wrong."""
    findings = report.get("findings", [])
    expected = manifest.get("expected_findings", [])

    detected: list[dict[str, str]] = []
    missed: list[dict[str, str]] = []
    for expectation in expected:
        if any(_finding_matches_expectation(f, expectation) for f in findings):
            detected.append(expectation)
        else:
            missed.append(expectation)

    return BenchmarkScore(
        manifest_name=manifest.get("name", "unnamed benchmark"),
        target=manifest.get("target", report.get("target", "")),
        expected_total=len(expected),
        detected=detected,
        missed=missed,
    )


@dataclass
class FalsePositiveScore:
    target: str
    false_positive_count: int
    false_positives: "list[dict[str, Any]]" = field(default_factory=list)  # [{technique_id, vuln_type, endpoint_url}]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "false_positive_count": self.false_positive_count,
            "false_positives": self.false_positives,
        }


def score_false_positives(clean_report: dict[str, Any]) -> FalsePositiveScore:
    """Every finding in a report from a target EXPLICITLY DECLARED to
    have none of the vulnerability classes under test is, by
    definition, a false positive -- there's no ground-truth manifest to
    match against here (unlike `score_recall`), because the ground
    truth for a clean target is simply "nothing should fire". Choosing
    the right clean target is the caller's responsibility (a hardened/
    patched benchmark build, or a small reference app built specifically
    to have none of these bugs) -- this function trusts the report it's
    given came from one."""
    findings = clean_report.get("findings", [])
    false_positives = [
        {
            "technique_id": f.get("technique_id"),
            "vuln_type": f.get("vuln_type"),
            "endpoint_url": (f.get("endpoint") or {}).get("url", ""),
        }
        for f in findings
    ]
    return FalsePositiveScore(
        target=clean_report.get("target", ""), false_positive_count=len(false_positives), false_positives=false_positives,
    )
