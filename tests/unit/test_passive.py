"""Unit tests for stof.passive -- the passive-scanning observation
layer. Every analyzer here reads traffic STOF already has; none of
them send a request. `Observation.testcase_ids` is validated against
the same frozen catalog `stof.payloads.registry` enforces, so this
layer can't invent a new vulnerability category any more than a
Payload can.
"""
import base64
import json

import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.passive.analyzers.headers import HeadersAnalyzer
from stof.passive.analyzers.jwt import JWTAnalyzer
from stof.passive.analyzers.objects import ObjectReferenceAnalyzer
from stof.passive.analyzers.workflows import WorkflowRoleAnalyzer
from stof.passive.engine import PassiveEngine, default_analyzers
from stof.passive.models import Observation, RequestExchange, ResponseExchange
from stof.payloads.registry import UnknownTestCaseError


def _jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}.fakesig"


# ---------------------------------------------------------------------------
# Observation -- frozen-catalog enforcement
# ---------------------------------------------------------------------------


def test_observation_accepts_known_testcase_ids():
    obs = Observation(kind="x", testcase_ids=("TC-053",), endpoint_url="https://x/y", method="GET", detail="d")
    assert obs.testcase_ids == ("TC-053",)


def test_observation_rejects_unknown_testcase_id():
    with pytest.raises(UnknownTestCaseError):
        Observation(kind="x", testcase_ids=("TC-999",), endpoint_url="https://x/y", method="GET", detail="d")


# ---------------------------------------------------------------------------
# HeadersAnalyzer -- TC-017
# ---------------------------------------------------------------------------


def test_headers_analyzer_flags_missing_security_headers():
    analyzer = HeadersAnalyzer()
    exchange = ResponseExchange(url="https://x/page", status=200, headers={"content-type": "text/html"})

    observations = analyzer.analyze_response(exchange)

    kinds = [o.kind for o in observations]
    assert "missing_security_headers" in kinds


def test_headers_analyzer_no_finding_when_all_security_headers_present():
    analyzer = HeadersAnalyzer()
    exchange = ResponseExchange(url="https://x/page", status=200, headers={
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    })

    observations = analyzer.analyze_response(exchange)

    assert not any(o.kind == "missing_security_headers" for o in observations)


def test_headers_analyzer_flags_version_looking_server_banner():
    analyzer = HeadersAnalyzer()
    exchange = ResponseExchange(url="https://x/page", status=200, headers={"server": "Apache-Coyote/1.1"})

    observations = analyzer.analyze_response(exchange)

    disclosure = [o for o in observations if o.kind == "server_version_disclosure"]
    assert len(disclosure) == 1
    assert disclosure[0].value == "Apache-Coyote/1.1"
    assert disclosure[0].testcase_ids == ("TC-017",)


def test_headers_analyzer_ignores_generic_product_name_without_version():
    analyzer = HeadersAnalyzer()
    exchange = ResponseExchange(url="https://x/page", status=200, headers={"server": "nginx"})

    observations = analyzer.analyze_response(exchange)

    assert not any(o.kind == "server_version_disclosure" for o in observations)


def test_headers_analyzer_ignores_error_and_redirect_statuses():
    analyzer = HeadersAnalyzer()
    exchange = ResponseExchange(url="https://x/page", status=404, headers={})

    assert analyzer.analyze_response(exchange) == []


# ---------------------------------------------------------------------------
# ObjectReferenceAnalyzer -- TC-053/TC-054
# ---------------------------------------------------------------------------


def test_object_reference_analyzer_flags_numeric_path_segment():
    analyzer = ObjectReferenceAnalyzer()
    endpoint = Endpoint(url="https://x/api/orders/1842", method="GET", endpoint_type="api")

    observations = analyzer.analyze_endpoint(endpoint)

    assert len(observations) == 1
    assert observations[0].value == "1842"
    assert observations[0].testcase_ids == ("TC-053", "TC-054")


def test_object_reference_analyzer_flags_object_shaped_query_param():
    analyzer = ObjectReferenceAnalyzer()
    endpoint = Endpoint(url="https://x/bank/showAccount?listAccounts=800001", method="GET", endpoint_type="page")

    observations = analyzer.analyze_endpoint(endpoint)

    assert any(o.value == "800001" for o in observations)


def test_object_reference_analyzer_ignores_endpoint_with_no_id_shape():
    analyzer = ObjectReferenceAnalyzer()
    endpoint = Endpoint(url="https://x/about-us", method="GET", endpoint_type="page")

    assert analyzer.analyze_endpoint(endpoint) == []


# ---------------------------------------------------------------------------
# JWTAnalyzer -- TC-057
# ---------------------------------------------------------------------------


def test_jwt_analyzer_flags_role_claim_in_bearer_token():
    analyzer = JWTAnalyzer()
    token = _jwt({"sub": "u1", "role": "admin"})
    exchange = RequestExchange(url="https://x/api/orders", method="GET", headers={"Authorization": f"Bearer {token}"})

    observations = analyzer.analyze_request(exchange)

    assert len(observations) == 1
    assert observations[0].testcase_ids == ("TC-057",)
    assert "role" in observations[0].detail


def test_jwt_analyzer_ignores_non_bearer_authorization_header():
    analyzer = JWTAnalyzer()
    exchange = RequestExchange(url="https://x/api/orders", method="GET", headers={"Authorization": "Basic dXNlcjpwYXNz"})

    assert analyzer.analyze_request(exchange) == []


def test_jwt_analyzer_ignores_malformed_token_gracefully():
    analyzer = JWTAnalyzer()
    exchange = RequestExchange(url="https://x/api/orders", method="GET", headers={"Authorization": "Bearer not-a-jwt"})

    assert analyzer.analyze_request(exchange) == []


def test_jwt_analyzer_ignores_token_with_no_role_claim():
    analyzer = JWTAnalyzer()
    token = _jwt({"sub": "u1", "exp": 123})
    exchange = RequestExchange(url="https://x/api/orders", method="GET", headers={"Authorization": f"Bearer {token}"})

    assert analyzer.analyze_request(exchange) == []


def test_jwt_analyzer_ignores_request_with_no_authorization_header():
    analyzer = JWTAnalyzer()
    exchange = RequestExchange(url="https://x/api/orders", method="GET", headers={})

    assert analyzer.analyze_request(exchange) == []


# ---------------------------------------------------------------------------
# WorkflowRoleAnalyzer -- TC-027 / TC-056
# ---------------------------------------------------------------------------


def test_workflow_analyzer_classifies_password_reset_url():
    analyzer = WorkflowRoleAnalyzer()
    endpoint = Endpoint(url="https://x/forgotPassword", method="POST", endpoint_type="form")

    observations = analyzer.analyze_endpoint(endpoint)

    assert any(o.kind == "workflow_candidate" and o.value == "PASSWORD_RESET" for o in observations)
    assert observations[0].testcase_ids == ("TC-027",)


def test_workflow_analyzer_flags_role_shaped_parameter():
    analyzer = WorkflowRoleAnalyzer()
    endpoint = Endpoint(url="https://x/api/users/5", method="PUT", endpoint_type="api", parameters=["role", "name"])

    observations = analyzer.analyze_endpoint(endpoint)

    role_obs = [o for o in observations if o.kind == "role_parameter"]
    assert len(role_obs) == 1
    assert role_obs[0].value == "role"
    assert role_obs[0].testcase_ids == ("TC-056",)


def test_workflow_analyzer_ignores_unrelated_endpoint():
    analyzer = WorkflowRoleAnalyzer()
    endpoint = Endpoint(url="https://x/about-us", method="GET", endpoint_type="page")

    assert analyzer.analyze_endpoint(endpoint) == []


# ---------------------------------------------------------------------------
# PassiveEngine
# ---------------------------------------------------------------------------


def test_default_analyzers_includes_all_four():
    names = {type(a).__name__ for a in default_analyzers()}
    assert names == {"HeadersAnalyzer", "ObjectReferenceAnalyzer", "JWTAnalyzer", "WorkflowRoleAnalyzer"}


def test_engine_observe_response_records_observations():
    engine = PassiveEngine()
    engine.observe_response(ResponseExchange(url="https://x/page", status=200, headers={"server": "nginx/1.18.0"}))

    assert len(engine.observations) >= 1
    assert any(o.kind == "server_version_disclosure" for o in engine.observations)


def test_engine_deduplicates_identical_observations():
    engine = PassiveEngine()
    exchange = ResponseExchange(url="https://x/page", status=200, headers={"server": "nginx/1.18.0"})
    engine.observe_response(exchange)
    engine.observe_response(exchange)  # same page visited twice

    server_obs = [o for o in engine.observations if o.kind == "server_version_disclosure"]
    assert len(server_obs) == 1


def test_engine_isolates_a_broken_analyzer():
    class _BrokenAnalyzer:
        def analyze_response(self, exchange):
            raise RuntimeError("boom")

    engine = PassiveEngine(analyzers=[_BrokenAnalyzer(), HeadersAnalyzer()])
    engine.observe_response(ResponseExchange(url="https://x/page", status=200, headers={"server": "nginx/1.18.0"}))

    # the broken analyzer didn't stop HeadersAnalyzer from still running
    assert any(o.kind == "server_version_disclosure" for o in engine.observations)


def test_engine_summary_counts_by_kind():
    engine = PassiveEngine()
    engine.observe_endpoint(Endpoint(url="https://x/orders/1", method="GET", endpoint_type="api"))
    engine.observe_endpoint(Endpoint(url="https://x/orders/2", method="GET", endpoint_type="api"))

    summary = engine.summary()

    assert summary.get("object_reference") == 2


def test_engine_for_testcase_filters_by_id():
    engine = PassiveEngine()
    engine.observe_endpoint(Endpoint(url="https://x/forgotPassword", method="POST", endpoint_type="form"))
    engine.observe_endpoint(Endpoint(url="https://x/orders/9", method="GET", endpoint_type="api"))

    tc027 = engine.for_testcase("TC-027")

    assert len(tc027) == 1
    assert tc027[0].kind == "workflow_candidate"
