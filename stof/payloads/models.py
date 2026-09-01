"""Layer 9 payload data model.

A `Payload` never decides whether something is vulnerable -- that stays
the job of the existing oracle in each module (`AuthorizationDecision`
for the authorization-boundary techniques, the content-fingerprint
comparisons everywhere else). A `Payload` only describes one candidate
test input and where it's allowed to be injected. Frozen: a payload is
a fact about a testcase's input space, not mutable state a probe
accumulates onto.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# Where a payload's value may be injected into a request. Matches the
# vocabulary the review used and the shapes this project's modules
# already probe (query/path substitution in idor_tests.py, JSON body
# in the gated body-field techniques, cookie/header in the role-
# tampering techniques) -- not a new set of injection points, a name
# for the ones already in use.
PayloadContext = Literal["query", "path", "json", "form", "header", "cookie"]

# How much latitude a payload needs before it's safe to send. Mirrors
# `IdorTestConfig.allow_state_changing_probes` / `AuthTestConfig`'s
# same flag conceptually, at the level of one payload rather than one
# whole technique -- "approval_required" has no consumer yet (no
# human-approval workflow exists), the value exists so a payload can
# say what it needs without STOF pretending to enforce more than it does.
PayloadRisk = Literal["passive", "read_only", "active", "approval_required"]


@dataclass(frozen=True)
class ProbeContext:
    """What a module is asking the payload layer for: "give me
    payloads for this testcase, at this injection point, for this
    endpoint/role." A generic replacement for a module reaching into
    its own hard-coded value list.

    `method`/`content_type`/`authenticated`/`state_changing` carry
    request shape a future `applies_to()` or generator may need (a
    TC-053 GET/query probe and a TC-053 POST/json probe are different
    situations despite sharing a testcase id) even though nothing
    reads them yet -- added ahead of the Step 2 migration precisely so
    that migration doesn't have to widen this dataclass mid-refactor."""

    testcase_id: str
    location: PayloadContext
    role: str | None = None
    endpoint_url: str | None = None
    method: str | None = None
    parameter: str | None = None
    content_type: str | None = None
    authenticated: bool | None = None
    state_changing: bool | None = None


@dataclass(frozen=True)
class Payload:
    payload_id: str
    testcase_id: str  # e.g. "TC-053.2" -- validated against the frozen catalog by top-level id ("TC-053")
    family: str  # e.g. "object_id", "role_mutation" -- groups related payloads, not an individual value
    value: str | int | dict
    contexts: tuple[PayloadContext, ...]
    risk: PayloadRisk = "read_only"
    state_changing: bool = False
    description: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def applies_to(self, context: ProbeContext) -> bool:
        return self.testcase_id == context.testcase_id and context.location in self.contexts
