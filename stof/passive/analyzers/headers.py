"""HeadersAnalyzer -- TC-017 (Default Configuration Check).

Checks the security headers and `Server`/`X-Powered-By` banners on a
response STOF already received during crawl. No additional request.
"""
from __future__ import annotations

import re

from ..models import Observation, ResponseExchange
from .base import PassiveAnalyzer

# Missing any of these is a candidate for TC-017's own "missing
# security header" technique -- this analyzer only flags absence, the
# existing active technique still owns deciding severity/applicability.
_EXPECTED_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
)

# A version-looking banner, not just the product name -- "Apache" alone
# is not interesting, "Apache-Coyote/1.1" or "nginx/1.18.0" is.
_VERSION_BANNER_RE = re.compile(r"[A-Za-z][A-Za-z0-9._-]*/[0-9][0-9A-Za-z.+_-]*")


class HeadersAnalyzer(PassiveAnalyzer):
    def analyze_response(self, exchange: ResponseExchange) -> list[Observation]:
        if not (200 <= exchange.status < 400):
            return []
        observations: list[Observation] = []
        lower_headers = {k.lower(): v for k, v in exchange.headers.items()}

        missing = [h for h in _EXPECTED_SECURITY_HEADERS if h not in lower_headers]
        if missing:
            observations.append(Observation(
                kind="missing_security_headers",
                testcase_ids=("TC-017",),
                endpoint_url=exchange.url,
                method="GET",
                detail=f"missing: {', '.join(missing)}",
            ))

        for header_name in ("server", "x-powered-by"):
            value = lower_headers.get(header_name)
            if value and _VERSION_BANNER_RE.search(value):
                observations.append(Observation(
                    kind="server_version_disclosure",
                    testcase_ids=("TC-017",),
                    endpoint_url=exchange.url,
                    method="GET",
                    detail=f"{header_name}: {value}",
                    value=value,
                ))

        return observations
