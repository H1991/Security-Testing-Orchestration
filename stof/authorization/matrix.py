"""A shared authorization state table: (endpoint, role) -> decision.

Modules record what they observe as they probe roles; later steps can
then query it instead of re-deriving "is there even a boundary here"
from a URL-name heuristic. `endpoints_with_boundary()` is the
generic replacement for `_looks_privileged(url, privileged_path_hints)`:
an endpoint only has something worth testing for a bypass once at
least one role has actually been observed ALLOWED and another DENIED.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from stof.authorization.decision import AuthorizationDecision
from stof.crawler.endpoint_store import Endpoint

_EndpointKey = tuple[str, str]  # (method, url)


def _endpoint_key(endpoint: Endpoint) -> _EndpointKey:
    return (endpoint.method.upper(), endpoint.url)


@dataclass
class AuthorizationMatrix:
    """One matrix per scan. Not thread-safe -- callers record
    sequentially, matching how each technique already probes one role
    at a time."""

    _cells: dict[tuple[_EndpointKey, str], AuthorizationDecision] = field(default_factory=dict)
    _endpoints: dict[_EndpointKey, Endpoint] = field(default_factory=dict)

    def record(self, endpoint: Endpoint, role: str, decision: AuthorizationDecision) -> None:
        key = _endpoint_key(endpoint)
        self._endpoints[key] = endpoint
        self._cells[(key, role)] = decision

    def decision_for(self, endpoint: Endpoint, role: str) -> AuthorizationDecision | None:
        return self._cells.get((_endpoint_key(endpoint), role))

    def roles_with_decision(self, endpoint: Endpoint, decision: AuthorizationDecision) -> list[str]:
        key = _endpoint_key(endpoint)
        return [role for (k, role), d in self._cells.items() if k == key and d == decision]

    def has_boundary(self, endpoint: Endpoint) -> bool:
        """True once at least one role was recorded ALLOWED and at
        least one other role was recorded DENIED for this endpoint --
        i.e. there is an authorization boundary here worth testing for
        a bypass. An endpoint every recorded role can reach, or every
        recorded role is denied, has no boundary to breach."""
        key = _endpoint_key(endpoint)
        decisions = [d for (k, _role), d in self._cells.items() if k == key]
        return AuthorizationDecision.ALLOWED in decisions and AuthorizationDecision.DENIED in decisions

    def endpoints_with_boundary(self) -> list[Endpoint]:
        return [endpoint for endpoint in self._endpoints.values() if self.has_boundary(endpoint)]
