"""Unit tests for the shared stof.authorization primitives
(AuthorizationDecision classifier, ObjectReference, AuthorizationMatrix)
-- the foundation existing modules (idor_tests.py, jwt_tests.py) can
build authorization-state-driven testing on top of, per the external
review's recommendation to centralise the "is this a hit" decision and
the boundary state instead of each technique re-deriving it."""
from stof.authorization.decision import AuthorizationDecision, classify_response
from stof.authorization.matrix import AuthorizationMatrix
from stof.authorization.object_reference import ObjectReference
from stof.crawler.endpoint_store import Endpoint

# ---------------------------------------------------------------------------
# classify_response
# ---------------------------------------------------------------------------


def test_classify_response_401_is_denied():
    assert classify_response(401, "") == AuthorizationDecision.DENIED


def test_classify_response_403_is_denied():
    assert classify_response(403, "Forbidden") == AuthorizationDecision.DENIED


def test_classify_response_429_is_challenged():
    assert classify_response(429, "Too Many Requests") == AuthorizationDecision.CHALLENGED


def test_classify_response_redirect_to_login_is_denied():
    assert classify_response(302, "", redirect_location="/login.jsp") == AuthorizationDecision.DENIED


def test_classify_response_redirect_elsewhere_is_redirected():
    assert classify_response(302, "", redirect_location="/dashboard") == AuthorizationDecision.REDIRECTED


def test_classify_response_200_with_substantial_body_is_allowed():
    assert classify_response(200, "real content " * 20) == AuthorizationDecision.ALLOWED


def test_classify_response_200_with_denial_phrase_is_denied():
    """The "soft 403" pattern: an app returns HTTP 200 but renders an
    access-denied page instead of a real 401/403 -- a raw status check
    alone would misreport this as ALLOWED."""
    body = "Access Denied. You do not have permission to view this page." * 5
    assert classify_response(200, body) == AuthorizationDecision.DENIED


def test_classify_response_200_with_short_body_is_unknown():
    assert classify_response(200, "ok") == AuthorizationDecision.UNKNOWN


def test_classify_response_500_is_unknown():
    assert classify_response(500, "internal error" * 20) == AuthorizationDecision.UNKNOWN


# ---------------------------------------------------------------------------
# ObjectReference
# ---------------------------------------------------------------------------


def test_object_reference_is_a_plain_dataclass():
    endpoint = Endpoint(url="https://x/orders/1842", method="GET", endpoint_type="api")
    ref = ObjectReference(endpoint=endpoint, parameter="orderId", value="1842", owner_role="admin")

    assert ref.endpoint is endpoint
    assert ref.value == "1842"
    assert ref.owner_role == "admin"
    assert ref.evidence is None


# ---------------------------------------------------------------------------
# AuthorizationMatrix
# ---------------------------------------------------------------------------


def _endpoint(url: str = "https://x/admin/users", method: str = "GET") -> Endpoint:
    return Endpoint(url=url, method=method, endpoint_type="page")


def test_matrix_records_and_returns_decision_per_role():
    matrix = AuthorizationMatrix()
    endpoint = _endpoint()

    matrix.record(endpoint, "admin", AuthorizationDecision.ALLOWED)
    matrix.record(endpoint, "normal", AuthorizationDecision.DENIED)

    assert matrix.decision_for(endpoint, "admin") == AuthorizationDecision.ALLOWED
    assert matrix.decision_for(endpoint, "normal") == AuthorizationDecision.DENIED


def test_matrix_decision_for_unrecorded_role_is_none():
    matrix = AuthorizationMatrix()
    endpoint = _endpoint()
    matrix.record(endpoint, "admin", AuthorizationDecision.ALLOWED)

    assert matrix.decision_for(endpoint, "guest") is None


def test_matrix_has_boundary_true_when_one_role_allowed_and_another_denied():
    matrix = AuthorizationMatrix()
    endpoint = _endpoint()
    matrix.record(endpoint, "admin", AuthorizationDecision.ALLOWED)
    matrix.record(endpoint, "normal", AuthorizationDecision.DENIED)

    assert matrix.has_boundary(endpoint) is True


def test_matrix_has_boundary_false_when_every_role_allowed():
    """A public endpoint every role can reach has no authorization
    boundary to test for a bypass -- this is the generic replacement
    for the old '/admin' URL-name heuristic."""
    matrix = AuthorizationMatrix()
    endpoint = _endpoint(url="https://x/profile")
    matrix.record(endpoint, "admin", AuthorizationDecision.ALLOWED)
    matrix.record(endpoint, "normal", AuthorizationDecision.ALLOWED)

    assert matrix.has_boundary(endpoint) is False


def test_matrix_has_boundary_false_when_every_role_denied():
    matrix = AuthorizationMatrix()
    endpoint = _endpoint()
    matrix.record(endpoint, "admin", AuthorizationDecision.DENIED)
    matrix.record(endpoint, "normal", AuthorizationDecision.DENIED)

    assert matrix.has_boundary(endpoint) is False


def test_matrix_has_boundary_false_for_unrecorded_endpoint():
    matrix = AuthorizationMatrix()
    assert matrix.has_boundary(_endpoint()) is False


def test_matrix_endpoints_with_boundary_lists_only_boundary_endpoints():
    matrix = AuthorizationMatrix()
    admin_only = _endpoint(url="https://x/admin/users")
    public = _endpoint(url="https://x/profile")
    matrix.record(admin_only, "admin", AuthorizationDecision.ALLOWED)
    matrix.record(admin_only, "normal", AuthorizationDecision.DENIED)
    matrix.record(public, "admin", AuthorizationDecision.ALLOWED)
    matrix.record(public, "normal", AuthorizationDecision.ALLOWED)

    boundary_urls = {e.url for e in matrix.endpoints_with_boundary()}

    assert boundary_urls == {"https://x/admin/users"}


def test_matrix_roles_with_decision_filters_by_endpoint_and_decision():
    matrix = AuthorizationMatrix()
    endpoint = _endpoint()
    matrix.record(endpoint, "admin", AuthorizationDecision.ALLOWED)
    matrix.record(endpoint, "normal", AuthorizationDecision.DENIED)
    matrix.record(endpoint, "guest", AuthorizationDecision.DENIED)

    assert matrix.roles_with_decision(endpoint, AuthorizationDecision.DENIED) == ["normal", "guest"]


def test_matrix_keys_by_method_and_url_not_url_alone():
    """A GET and a POST to the same URL are different endpoints (e.g.
    a page load vs. a form submission) -- recording one must not leak
    into the other's decision."""
    matrix = AuthorizationMatrix()
    get_ep = _endpoint(method="GET")
    post_ep = _endpoint(method="POST")
    matrix.record(get_ep, "normal", AuthorizationDecision.ALLOWED)

    assert matrix.decision_for(post_ep, "normal") is None
