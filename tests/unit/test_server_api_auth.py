"""Unit tests for the opt-in `STOF_CONSOLE_API_KEY` console auth
middleware (`stof.ui.server._require_api_key`).

Uses a bare, non-existent `/api/...` path rather than a real route:
the middleware wraps the whole ASGI app and runs before routing, so a
401 (or pass-through) fires the same way regardless of whether a real
route exists underneath -- this keeps the test independent of any
route's own setup/fixture requirements."""
from fastapi.testclient import TestClient

from stof.ui import server


def _client() -> TestClient:
    return TestClient(server.app)


def test_api_requests_pass_through_unchanged_when_no_key_configured(monkeypatch):
    """Default, unset state -- byte-identical behavior to every prior
    release. A 404 (no such route) proves the request reached routing
    at all, i.e. the middleware did not block it."""
    monkeypatch.setattr(server, "_CONSOLE_API_KEY", "")
    response = _client().get("/api/definitely-not-a-real-route")
    assert response.status_code == 404


def test_health_endpoint_never_requires_a_key(monkeypatch):
    monkeypatch.setattr(server, "_CONSOLE_API_KEY", "s3cret")
    response = _client().get("/api/health")
    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_api_request_rejected_without_matching_key_when_configured(monkeypatch):
    monkeypatch.setattr(server, "_CONSOLE_API_KEY", "s3cret")
    response = _client().get("/api/definitely-not-a-real-route")
    assert response.status_code == 401
    assert "X-STOF-API-Key" in response.json()["detail"]


def test_api_request_rejected_with_wrong_key(monkeypatch):
    monkeypatch.setattr(server, "_CONSOLE_API_KEY", "s3cret")
    response = _client().get("/api/definitely-not-a-real-route", headers={"X-STOF-API-Key": "wrong"})
    assert response.status_code == 401


def test_api_request_accepted_with_matching_key_reaches_routing(monkeypatch):
    """A matching key clears the middleware -- the 404 (not 401) proves
    the request reached routing, i.e. the key was accepted."""
    monkeypatch.setattr(server, "_CONSOLE_API_KEY", "s3cret")
    response = _client().get("/api/definitely-not-a-real-route", headers={"X-STOF-API-Key": "s3cret"})
    assert response.status_code == 404
