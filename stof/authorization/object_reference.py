"""A discovered object identifier, worth cross-user replay.

`idor_tests.py`'s techniques currently pass id/param/url around as
loose function arguments. `ObjectReference` is the shared shape that
lets an "object discovery" step (crawler traffic, leaked ids in
responses, or the existing candidate-id fallback) hand results to any
cross-user replay technique uniformly.
"""
from __future__ import annotations

from dataclasses import dataclass

from stof.crawler.endpoint_store import Endpoint


@dataclass
class ObjectReference:
    endpoint: Endpoint
    parameter: str
    value: str
    owner_role: str | None = None
    evidence: str | None = None
