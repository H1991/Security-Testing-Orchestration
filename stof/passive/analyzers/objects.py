"""ObjectReferenceAnalyzer -- feeds TC-053 (IDOR) / TC-054 (BOLA).

Flags an id-shaped path segment or query parameter on an already-
discovered endpoint as a candidate object reference. Deliberately does
NOT probe it -- `idor_tests.py`'s existing cross-session-confirmed
techniques own deciding whether it's actually an authorization gap.
This analyzer only shortens their search: instead of trying every
GET endpoint's every parameter, the active techniques can prioritize
ones already flagged here.

Self-contained rather than importing `stof.modules._idor_shared`'s
equivalent helpers -- `stof/passive/` is a lower-layer package modules
import FROM (same relationship as `stof/authorization/` and
`stof/payloads/`), not the reverse.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from stof.crawler.endpoint_store import Endpoint

from ..models import Observation
from .base import PassiveAnalyzer

_ID_PATH_SEGMENT_RE = re.compile(
    r"^\d+$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_OBJECT_REFERENCE_HINTS = (
    "id", "uuid", "guid", "account", "user", "order", "invoice",
    "record", "ref", "num", "code", "index", "item",
)


def _looks_like_object_reference(param_name: str) -> bool:
    return any(hint in param_name.lower() for hint in _OBJECT_REFERENCE_HINTS)


class ObjectReferenceAnalyzer(PassiveAnalyzer):
    def analyze_endpoint(self, endpoint: Endpoint) -> list[Observation]:
        observations: list[Observation] = []
        parts = urlsplit(endpoint.url)

        for segment in parts.path.split("/"):
            if segment and _ID_PATH_SEGMENT_RE.match(segment):
                observations.append(Observation(
                    kind="object_reference",
                    testcase_ids=("TC-053", "TC-054"),
                    endpoint_url=endpoint.url,
                    method=endpoint.method,
                    detail=f"id-shaped path segment: '{segment}'",
                    value=segment,
                ))

        for name, value in parse_qsl(parts.query, keep_blank_values=True):
            if _looks_like_object_reference(name):
                observations.append(Observation(
                    kind="object_reference",
                    testcase_ids=("TC-053", "TC-054"),
                    endpoint_url=endpoint.url,
                    method=endpoint.method,
                    detail=f"object-reference-shaped query param: '{name}'",
                    value=value,
                ))

        for name in endpoint.parameters:
            if _looks_like_object_reference(name):
                observations.append(Observation(
                    kind="object_reference",
                    testcase_ids=("TC-053", "TC-054"),
                    endpoint_url=endpoint.url,
                    method=endpoint.method,
                    detail=f"object-reference-shaped parameter: '{name}'",
                ))

        return observations
