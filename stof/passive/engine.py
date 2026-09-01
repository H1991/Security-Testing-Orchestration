"""PassiveEngine -- the shared entry point every passive analyzer runs
through.

One engine per scan, owned by the caller (`main.py`'s crawl phase, in
this project's first wiring). `crawler.py` accepts an optional
`PassiveEngine` and feeds it response/request/endpoint data it already
has as a normal side effect of crawling -- opt-in and additive: a
`CrawlerConfig` with no engine configured behaves byte-for-byte like it
did before this package existed.
"""
from __future__ import annotations

from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint

from .analyzers.base import PassiveAnalyzer
from .analyzers.headers import HeadersAnalyzer
from .analyzers.jwt import JWTAnalyzer
from .analyzers.objects import ObjectReferenceAnalyzer
from .analyzers.workflows import WorkflowRoleAnalyzer
from .models import Observation, RequestExchange, ResponseExchange

_log = get_logger("passive.engine")


def default_analyzers() -> list[PassiveAnalyzer]:
    return [HeadersAnalyzer(), ObjectReferenceAnalyzer(), JWTAnalyzer(), WorkflowRoleAnalyzer()]


class PassiveEngine:
    def __init__(self, analyzers: list[PassiveAnalyzer] | None = None) -> None:
        self.analyzers = analyzers if analyzers is not None else default_analyzers()
        self.observations: list[Observation] = []
        self._seen_keys: set[tuple[str, str, str, str | None]] = set()

    def _record(self, new: list[Observation]) -> None:
        for obs in new:
            key = (obs.kind, obs.endpoint_url, obs.method, obs.value)
            if key in self._seen_keys:
                continue
            self._seen_keys.add(key)
            self.observations.append(obs)

    def observe_response(self, exchange: ResponseExchange) -> None:
        for analyzer in self.analyzers:
            try:
                self._record(analyzer.analyze_response(exchange))
            except Exception as exc:
                _log.warning(f"{type(analyzer).__name__} failed on response {exchange.url}: {exc}")

    def observe_request(self, exchange: RequestExchange) -> None:
        for analyzer in self.analyzers:
            try:
                self._record(analyzer.analyze_request(exchange))
            except Exception as exc:
                _log.warning(f"{type(analyzer).__name__} failed on request {exchange.url}: {exc}")

    def observe_endpoint(self, endpoint: Endpoint) -> None:
        for analyzer in self.analyzers:
            try:
                self._record(analyzer.analyze_endpoint(endpoint))
            except Exception as exc:
                _log.warning(f"{type(analyzer).__name__} failed on endpoint {endpoint.url}: {exc}")

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for obs in self.observations:
            counts[obs.kind] = counts.get(obs.kind, 0) + 1
        return counts

    def for_testcase(self, testcase_id: str) -> list[Observation]:
        return [obs for obs in self.observations if testcase_id in obs.testcase_ids]
