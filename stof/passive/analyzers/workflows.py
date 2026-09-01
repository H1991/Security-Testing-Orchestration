"""WorkflowRoleAnalyzer -- feeds TC-027 (password reset/change workflow
discovery) and TC-056 (role manipulation candidate parameters).

Classifies an already-discovered `Endpoint` by URL/parameter shape --
no new page I/O. A form the crawler's existing `detect_forms()`
already extracted (or an API endpoint `ApiSniffer` already captured)
is enough; this analyzer never fetches or parses HTML itself.
"""
from __future__ import annotations

from stof.crawler.endpoint_store import Endpoint

from ..models import Observation
from .base import PassiveAnalyzer

_WORKFLOW_URL_HINTS: tuple[tuple[str, str], ...] = (
    ("forgotpassword", "PASSWORD_RESET"),
    ("forgot-password", "PASSWORD_RESET"),
    ("reset-password", "PASSWORD_RESET"),
    ("resetpassword", "PASSWORD_RESET"),
    ("changepassword", "PASSWORD_CHANGE"),
    ("change-password", "PASSWORD_CHANGE"),
    ("register", "REGISTRATION"),
    ("signup", "REGISTRATION"),
    ("invite", "INVITE_USER"),
    ("verify", "EMAIL_VERIFICATION"),
    ("verify-email", "EMAIL_VERIFICATION"),
)

_ROLE_PARAM_HINTS = (
    "role", "group", "isadmin", "is_admin", "admin", "level",
    "perm", "privilege", "access_level",
)


class WorkflowRoleAnalyzer(PassiveAnalyzer):
    def analyze_endpoint(self, endpoint: Endpoint) -> list[Observation]:
        observations: list[Observation] = []
        url_lower = endpoint.url.lower()

        for hint, workflow in _WORKFLOW_URL_HINTS:
            if hint in url_lower:
                observations.append(Observation(
                    kind="workflow_candidate",
                    testcase_ids=("TC-027",),
                    endpoint_url=endpoint.url,
                    method=endpoint.method,
                    detail=f"URL shape matches a {workflow} workflow",
                    value=workflow,
                ))
                break  # one workflow classification per endpoint is enough

        for param in endpoint.parameters:
            if any(hint in param.lower() for hint in _ROLE_PARAM_HINTS):
                observations.append(Observation(
                    kind="role_parameter",
                    testcase_ids=("TC-056",),
                    endpoint_url=endpoint.url,
                    method=endpoint.method,
                    detail=f"role-shaped parameter observed: '{param}'",
                    value=param,
                ))

        return observations
