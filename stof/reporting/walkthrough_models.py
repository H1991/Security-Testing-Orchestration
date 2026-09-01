"""Layer 13 — data contracts for the Walkthrough Report.

Deliberately separate from `stof.findings.models.Finding` (per this
project's own module-boundary rule: "Zero changes to `Finding`'s own
dataclass fields, walkthrough data lives in the new, separate
`FindingWalkthrough` structure, not bolted onto `Finding`"). A
`FindingWalkthrough` is built FROM a `Finding` by `walkthrough_runner.
build_walkthroughs()` -- it never replaces or extends it.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class WalkthroughStep:
    order: int
    caption: str  # plain English, e.g. "Log in as demo user 'jsmith'"
    screenshot_path: str | None = None  # absolute path to a captured PNG, or None if this step has no visual (e.g. a wait)
    detail: str | None = None  # optional secondary line, e.g. the exact payload typed


@dataclass
class FindingWalkthrough:
    finding_id: str
    tc_id: str  # e.g. "TC-127.4"
    title: str  # short vuln title for the page, e.g. "SQL Injection — Login Bypass"
    severity: str
    endpoint_url: str
    steps: list[WalkthroughStep] = field(default_factory=list)
    impact_summary: str = ""  # reused finding.description verbatim
    remediation: str = ""  # reused finding.recommendation verbatim
    build_error: str | None = None  # set (steps may be empty/partial) if this finding's replay hit a real problem -- never silently drop a finding
