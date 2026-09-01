"""Base class every passive analyzer implements.

Each hook returns `[]` by default so an analyzer only needs to
override the exchange shapes it actually cares about (most implement
exactly one of these three)."""
from __future__ import annotations

from stof.crawler.endpoint_store import Endpoint

from ..models import Observation, RequestExchange, ResponseExchange


class PassiveAnalyzer:
    def analyze_response(self, exchange: ResponseExchange) -> list[Observation]:
        return []

    def analyze_request(self, exchange: RequestExchange) -> list[Observation]:
        return []

    def analyze_endpoint(self, endpoint: Endpoint) -> list[Observation]:
        """Called with an already-discovered `Endpoint` (a page, form,
        or XHR/fetch call the crawler's existing `detect_forms()`/
        `ApiSniffer` already extracted) -- no new page I/O, just a
        second look at data STOF already has."""
        return []
