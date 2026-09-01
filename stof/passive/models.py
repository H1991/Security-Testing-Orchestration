"""Passive-scanning data model.

An `Observation` is deliberately NOT a `Finding` (Layer 10) -- per this
project's own standing rule ("no new vulnerabilities, only analyze
existing traffic"), a passive analyzer only ever says "here's something
an existing testcase family might want to look at," never "this is a
vulnerability." `testcase_ids` is validated against the same frozen
catalog `stof.payloads.registry` already enforces, so an analyzer can't
silently invent a new vulnerability category any more than a Payload can.

Observations are produced from traffic STOF already saw during a
normal crawl -- no additional request is ever sent to produce one.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from stof.payloads.registry import KNOWN_TESTCASES, UnknownTestCaseError, top_level_id

# What kind of thing was observed. Not a `Literal` -- new analyzers may
# add kinds without touching this file, they just need to route to a
# testcase family that's already in the frozen catalog.
ObservationKind = str


@dataclass(frozen=True)
class Observation:
    kind: ObservationKind
    testcase_ids: tuple[str, ...]
    endpoint_url: str
    method: str
    detail: str
    value: str | None = None
    role: str | None = None

    def __post_init__(self) -> None:
        for tid in self.testcase_ids:
            top = top_level_id(tid)  # raises UnknownTestCaseError if tid isn't even TC-shaped
            if top not in KNOWN_TESTCASES:
                raise UnknownTestCaseError(
                    f"{tid!r} ({top}) is not in the frozen testcase catalog (config/testcases.json) -- "
                    "a passive analyzer only supplies candidates for an existing testcase, it never defines a new one"
                )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ResponseExchange:
    """What a passive analyzer reads for a page/document response --
    headers and status only. Deliberately excludes the response body:
    reading it from inside a live Playwright `page.on("response")`
    handler requires an async round-trip that risks missing data if
    the page navigates away first, the same reason this project's
    existing `ApiSniffer` and the ad-hoc listener in
    `_submit_form_with_test_data` both stick to synchronously-available
    fields."""

    url: str
    status: int
    headers: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RequestExchange:
    """What a passive analyzer reads for an observed request --
    headers only, same sync-only reasoning as `ResponseExchange`."""

    url: str
    method: str
    headers: dict = field(default_factory=dict)


__all__ = ["Observation", "ObservationKind", "RequestExchange", "ResponseExchange", "UnknownTestCaseError"]
