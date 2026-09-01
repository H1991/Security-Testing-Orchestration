"""The frozen testcase catalog and the payload registry validated
against it.

Per this project's own standing rule: the payload layer never defines
a new vulnerability, it only supplies inputs for an existing `TC-*`.
`PayloadRegistry.register()` enforces that mechanically -- a payload
naming a testcase outside `KNOWN_TESTCASES` is rejected at
registration time, not silently accepted and discovered later in a
report.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .models import Payload, ProbeContext

_TOP_LEVEL_ID_RE = re.compile(r"^(TC-\d+)")

# Mirrors `config/testcases.json`'s `tests[].id` set exactly (the
# sprint-plan-derived catalog EXPLOIT_COVERAGE.md itself is built
# from). Kept as an explicit literal rather than read from disk at
# import time: expanding the catalog is meant to be a deliberate code
# change here, not something that silently grows if the JSON file
# changes. Keep the two in sync by hand.
KNOWN_TESTCASES: frozenset[str] = frozenset({
    "TC-008", "TC-009", "TC-015", "TC-016", "TC-017", "TC-018", "TC-019", "TC-020",
    "TC-022", "TC-023", "TC-024", "TC-025", "TC-026", "TC-027", "TC-029", "TC-030",
    "TC-031", "TC-032", "TC-034", "TC-036", "TC-037", "TC-038", "TC-044", "TC-045",
    "TC-046", "TC-048", "TC-049", "TC-050", "TC-051", "TC-052", "TC-053", "TC-054",
    "TC-055", "TC-056", "TC-057", "TC-058", "TC-062", "TC-067", "TC-070", "TC-073",
    "TC-076", "TC-078", "TC-080", "TC-082", "TC-084", "TC-085", "TC-087", "TC-088",
    "TC-089", "TC-093", "TC-094", "TC-095", "TC-096", "TC-097", "TC-098", "TC-099",
    "TC-100", "TC-101", "TC-104", "TC-105", "TC-107", "TC-108", "TC-113", "TC-114",
    "TC-115", "TC-116", "TC-119", "TC-121", "TC-126",
    # Wave 2 additions -- the sprint-plan-derived catalog above never had
    # a generic top-level "SQL Injection" or "Reflected XSS" entry (only
    # narrower ones: TC-067 SQLi via JWT KID specifically, TC-076
    # DOM-based XSS specifically). TC-126 was the highest id in use, so
    # TC-127/TC-128 continue the sequence rather than colliding with it.
    "TC-127",  # sqli_tests.py -- SQL Injection
    "TC-128",  # xss_tests.py -- Reflected Cross-Site Scripting
    # Wave 3 additions -- TC-128 was the highest id in use.
    "TC-129",  # session_weakness_tests.py -- Session / Rate-Limit Weaknesses
    "TC-130",  # csrf_tests.py -- Cross-Site Request Forgery (CSRF)
    # Wave 4 addition -- TC-130 was the highest id in use.
    "TC-131",  # tenant_tests.py -- Tenant Isolation BOLA (org/tenant-scope parameter substitution)
})


class UnknownTestCaseError(ValueError):
    """A Payload named a TC-* id outside the frozen catalog, or
    something that isn't a TC-* id at all."""


def top_level_id(testcase_id: str) -> str:
    """'TC-053.2' -> 'TC-053' -- the frozen catalog only has top-level
    ids; `.N` sub-technique numbering is this project's own further
    breakdown beyond the sprint-plan xlsx."""
    match = _TOP_LEVEL_ID_RE.match(testcase_id)
    if not match:
        raise UnknownTestCaseError(f"not a TC-* id: {testcase_id!r}")
    return match.group(1)


class PayloadRegistry:
    """One registry per scan (or per module, per caller's choice) --
    deliberately not a process-wide singleton, so tests don't leak
    registered payloads across each other."""

    def __init__(self) -> None:
        self._by_testcase: dict[str, list[Payload]] = defaultdict(list)

    def register(self, payload: Payload) -> None:
        top_level = top_level_id(payload.testcase_id)
        if top_level not in KNOWN_TESTCASES:
            raise UnknownTestCaseError(
                f"{payload.payload_id!r}: {payload.testcase_id!r} ({top_level}) is not in the "
                "frozen testcase catalog (config/testcases.json) -- the payload layer only "
                "supplies inputs for an existing testcase, it never defines a new one"
            )
        self._by_testcase[payload.testcase_id].append(payload)

    def register_all(self, payloads: list[Payload]) -> None:
        for payload in payloads:
            self.register(payload)

    def for_testcase(self, testcase_id: str) -> list[Payload]:
        return list(self._by_testcase.get(testcase_id, []))

    def for_context(self, context: ProbeContext) -> list[Payload]:
        return [p for p in self._by_testcase.get(context.testcase_id, []) if p.applies_to(context)]
