"""Turns a payload family into concrete `Payload` instances at
runtime.

Kept separate from `PayloadRegistry`: a generator's *output* is what
gets validated and registered, not the generator itself -- so adding a
new generator can never bypass the frozen-catalog check in
`PayloadRegistry.register()`.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator

from .models import Payload, PayloadContext, PayloadRisk


class PayloadGenerator:
    """Base class. A generator's only contract is "produce zero or
    more Payload instances for one testcase family" -- everything else
    (ProbeContext, PayloadRegistry, Payload itself) stays generic, so
    adding a new family means adding a new generator, not touching the
    rest of the pipeline."""

    testcase_id: str
    family: str

    def generate(self) -> Iterator[Payload]:
        raise NotImplementedError


class StaticValueGenerator(PayloadGenerator):
    """Wraps a fixed, caller-supplied list of values as `Payload`
    objects without changing what those values are -- e.g. this
    project's own `IdorTestConfig.candidate_ids`. The migration path
    for existing hard-coded test inputs: same values, now addressable
    through the registry instead of read directly off a config
    dataclass."""

    def __init__(
        self,
        testcase_id: str,
        family: str,
        values: Iterable[str | int],
        contexts: Iterable[PayloadContext],
        *,
        risk: PayloadRisk = "read_only",
        state_changing: bool = False,
    ) -> None:
        self.testcase_id = testcase_id
        self.family = family
        self._values = list(values)
        self._contexts = tuple(contexts)
        self._risk = risk
        self._state_changing = state_changing

    def generate(self) -> Iterator[Payload]:
        for i, value in enumerate(self._values):
            yield Payload(
                payload_id=f"{self.testcase_id}:{self.family}:{i}",
                testcase_id=self.testcase_id,
                family=self.family,
                value=value,
                contexts=self._contexts,
                risk=self._risk,
                state_changing=self._state_changing,
            )
