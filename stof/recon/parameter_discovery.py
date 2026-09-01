"""Recon Engine — parameter discovery (Arjun-equivalent).

Deliberately passive: real Arjun works by actively fuzzing candidate
parameter names against an endpoint and diffing responses. This module
instead consolidates parameter names Layer 7 already observed (form
inputs via `form_detector.py`, query/body params via `api_sniffer.py`)
into one per-endpoint view with a type guess -- no new requests, no
guessing at names the app never showed us. Active parameter fuzzing, if
wanted later, belongs alongside `crawler.py`'s existing
`submit_forms_with_test_data` opt-in, not silently bundled in here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint

_ID_HINTS = ("id", "uuid", "guid")
_BOOL_HINTS = ("is", "has", "enabled", "active", "admin", "flag")
_DATE_HINTS = ("date", "time", "dob", "created", "updated", "expiry", "expires")
_NUMBER_HINTS = ("amount", "price", "qty", "quantity", "count", "total", "balance")
_EMAIL_HINTS = ("email", "mail")


def guess_param_type(name: str) -> str:
    """Pure heuristic, name-based only (no value seen) -- intentionally
    simple, matching the "type guess" idea from the recon proposal's own
    `{"id":"number","isAdmin":"boolean"}` example."""
    lowered = name.lower()
    if any(hint in lowered for hint in _EMAIL_HINTS):
        return "email"
    if any(lowered == hint or lowered.endswith(hint.capitalize()) or lowered.startswith(hint) for hint in _BOOL_HINTS):
        return "boolean"
    if any(hint in lowered for hint in _DATE_HINTS):
        return "date"
    if any(hint in lowered for hint in _NUMBER_HINTS):
        return "number"
    if any(lowered == hint or lowered.endswith(hint) for hint in _ID_HINTS):
        return "id"
    return "string"


@dataclass
class ParameterInfo:
    name: str
    guessed_type: str


def discover_parameters(endpoints: list["Endpoint"]) -> dict[str, list[ParameterInfo]]:
    """One entry per (method, url) endpoint that has parameters, each
    holding every parameter name Layer 7 saw for it plus a type guess."""
    result: dict[str, list[ParameterInfo]] = {}
    for endpoint in endpoints:
        if not endpoint.parameters:
            continue
        key = f"{endpoint.method} {endpoint.url}"
        result[key] = [ParameterInfo(name=name, guessed_type=guess_param_type(name)) for name in endpoint.parameters]
    return result
