"""Unit tests for the opt-in `STOF_CONSOLE_PIN` browser login gate
(`stof.ui.server._require_pin_session` and the `/api/auth/*` routes).

Sibling to `test_server_api_auth.py`'s own `STOF_CONSOLE_API_KEY` tests
-- same shape, different gate: a signed session cookie obtained via a
real login endpoint, for a real browser (that header-based mechanism
has no login screen and nothing to attach a cookie to)."""
from fastapi.testclient import TestClient

from stof.ui import server


def _client() -> TestClient:
    return TestClient(server.app)


def _reset_pin_state(monkeypatch, pin: str, tmp_path) -> None:
    """Every test gets a clean slate -- these are module-level globals
    (mirroring `_CONSOLE_API_KEY`'s own pattern), so a prior test's
    failed-attempt counter or session token must never leak into the
    next one. `CONSOLE_AUTH_PATH` is always redirected into a tmp dir
    so no test ever reads or writes the real project's
    config/console_auth.json (a change-PIN test really would persist
    to disk otherwise)."""
    monkeypatch.setattr(server, "_CONSOLE_PIN", pin)
    monkeypatch.setattr(server, "_pin_sessions", {})
    monkeypatch.setattr(server, "_pin_last_activity", {})
    monkeypatch.setattr(server, "_pin_failed_attempts", 0)
    monkeypatch.setattr(server, "_pin_locked_until", 0.0)
    monkeypatch.setattr(server, "CONSOLE_AUTH_PATH", tmp_path / "console_auth.json")


def test_api_requests_pass_through_unchanged_when_no_pin_configured(monkeypatch, tmp_path):
    """Default, unset state -- byte-identical to every prior release,
    same as `_CONSOLE_API_KEY`'s own equivalent test."""
    _reset_pin_state(monkeypatch, "", tmp_path)
    response = _client().get("/api/definitely-not-a-real-route")
    assert response.status_code == 404


def test_session_status_reports_not_required_when_pin_unset(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "", tmp_path)
    response = _client().get("/api/auth/session")
    assert response.json() == {"required": False, "authenticated": True}


def test_session_status_reports_unauthenticated_before_login(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    response = _client().get("/api/auth/session")
    assert response.json() == {"required": True, "authenticated": False, "idle_timeout_minutes": 0}


def test_gated_api_request_rejected_without_a_session(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    response = _client().get("/api/definitely-not-a-real-route")
    assert response.status_code == 401
    assert "PIN login required" in response.json()["detail"]


def test_health_and_login_and_session_routes_stay_reachable_unauthenticated(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/auth/session").status_code == 200
    # A wrong PIN still reaches the route (401 from the login logic
    # itself, not the gate) -- proves /api/auth/login is exempt.
    assert client.post("/api/auth/login", json={"pin": "000000"}).status_code == 401


def test_correct_pin_sets_a_session_cookie_that_unlocks_the_api(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    login = client.post("/api/auth/login", json={"pin": "123456"})
    assert login.status_code == 200
    assert "stof_session" in login.cookies
    assert client.get("/api/auth/session").json()["authenticated"] is True
    assert client.get("/api/definitely-not-a-real-route").status_code == 404  # reached routing, not blocked


def test_logout_clears_the_session(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    assert client.get("/api/auth/session").json()["authenticated"] is True
    logout = client.post("/api/auth/logout")
    assert logout.status_code == 200
    assert client.get("/api/auth/session").json()["authenticated"] is False


def test_repeated_wrong_pins_trigger_a_temporary_lockout(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    for _ in range(server._PIN_MAX_ATTEMPTS - 1):
        response = client.post("/api/auth/login", json={"pin": "000000"})
        assert response.status_code == 401
    locked = client.post("/api/auth/login", json={"pin": "000000"})
    assert locked.status_code == 429
    # Even the CORRECT pin is rejected while locked out -- the whole
    # point of a lockout is that it doesn't matter if the next guess
    # would have been right.
    still_locked = client.post("/api/auth/login", json={"pin": "123456"})
    assert still_locked.status_code == 429


def test_login_rejected_when_no_pin_is_configured_at_all(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "", tmp_path)
    response = _client().post("/api/auth/login", json={"pin": "123456"})
    assert response.status_code == 400


# ---------------------------------------------------------------------
# Change PIN
# ---------------------------------------------------------------------


def test_change_pin_requires_an_authenticated_session(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    response = _client().post("/api/auth/change-pin", json={"current_pin": "123456", "new_pin": "654321"})
    assert response.status_code == 401  # blocked by _require_pin_session before the handler ever runs


def test_change_pin_rejects_wrong_current_pin(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    response = client.post("/api/auth/change-pin", json={"current_pin": "000000", "new_pin": "654321"})
    assert response.status_code == 401
    assert "current PIN is incorrect" in response.json()["detail"]


def test_change_pin_rejects_a_non_six_digit_new_pin(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    response = client.post("/api/auth/change-pin", json={"current_pin": "123456", "new_pin": "12345"})
    assert response.status_code == 400


def test_change_pin_persists_and_takes_effect_immediately(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    changed = client.post("/api/auth/change-pin", json={"current_pin": "123456", "new_pin": "654321"})
    assert changed.status_code == 200
    assert (tmp_path / "console_auth.json").is_file()

    # The OLD pin no longer works; the NEW one does -- proves
    # _current_pin() actually reads the persisted override, not just
    # the original STOF_CONSOLE_PIN env value.
    fresh_client = _client()
    old_pin_attempt = fresh_client.post("/api/auth/login", json={"pin": "123456"})
    assert old_pin_attempt.status_code == 401
    new_pin_attempt = fresh_client.post("/api/auth/login", json={"pin": "654321"})
    assert new_pin_attempt.status_code == 200


def test_change_pin_survives_a_process_restart_simulation(monkeypatch, tmp_path):
    """`_current_pin()` reads the file fresh each call rather than
    caching -- the whole point of persisting to disk instead of just an
    in-memory global is that a new process (a real container restart)
    picks it up too. Simulated here by resetting `_CONSOLE_PIN` back to
    the OLD value (as a fresh env-var read would give) while leaving
    the persisted file from the previous "process" in place."""
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    client.post("/api/auth/change-pin", json={"current_pin": "123456", "new_pin": "654321"})

    monkeypatch.setattr(server, "_CONSOLE_PIN", "123456")  # "restart" -- env var reverts to its original value
    monkeypatch.setattr(server, "_pin_sessions", {})  # a real restart also loses in-memory sessions

    restarted_client = _client()
    assert restarted_client.post("/api/auth/login", json={"pin": "654321"}).status_code == 200


# ---------------------------------------------------------------------------
# Idle (inactivity) auto-logout
# ---------------------------------------------------------------------------


def test_idle_timeout_defaults_to_disabled(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    response = client.get("/api/auth/idle-timeout")
    assert response.json() == {"idle_timeout_minutes": 0}


def test_set_idle_timeout_persists(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    saved = client.put("/api/auth/idle-timeout", json={"idle_timeout_minutes": 5})
    assert saved.status_code == 200
    assert saved.json() == {"idle_timeout_minutes": 5}
    assert client.get("/api/auth/idle-timeout").json() == {"idle_timeout_minutes": 5}


def test_set_idle_timeout_caps_an_absurd_value(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    saved = client.put("/api/auth/idle-timeout", json={"idle_timeout_minutes": 999999})
    assert saved.json()["idle_timeout_minutes"] == 24 * 60


def test_session_status_reports_idle_timeout_minutes(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    client.put("/api/auth/idle-timeout", json={"idle_timeout_minutes": 5})
    status = client.get("/api/auth/session").json()
    assert status == {"required": True, "authenticated": True, "idle_timeout_minutes": 5}


def test_changing_the_pin_does_not_wipe_the_idle_timeout_setting(monkeypatch, tmp_path):
    """Regression test for a real bug: change-pin used to overwrite
    console_auth.json wholesale (`{"pin": new_pin}`), which would have
    silently dropped idle_timeout_minutes the moment this feature's own
    settings file gained a second key."""
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    client.put("/api/auth/idle-timeout", json={"idle_timeout_minutes": 5})
    client.post("/api/auth/change-pin", json={"current_pin": "123456", "new_pin": "654321"})
    assert client.get("/api/auth/idle-timeout").json() == {"idle_timeout_minutes": 5}


def test_idle_session_is_rejected_after_the_configured_minutes(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    client.put("/api/auth/idle-timeout", json={"idle_timeout_minutes": 5})
    assert client.get("/api/auth/session").json()["authenticated"] is True

    # Simulate 6 minutes of no real API activity by rewinding this
    # token's last-seen timestamp directly, rather than sleeping the
    # test for 6 real minutes.
    token = client.cookies.get("stof_session")
    monkeypatch.setitem(server._pin_last_activity, token, server.time.time() - 6 * 60)
    assert client.get("/api/auth/session").json()["authenticated"] is False
    # The expired session is also fully dropped, not just reported invalid.
    assert token not in server._pin_sessions


def test_activity_within_the_window_keeps_the_session_alive(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    client.put("/api/auth/idle-timeout", json={"idle_timeout_minutes": 5})

    token = client.cookies.get("stof_session")
    monkeypatch.setitem(server._pin_last_activity, token, server.time.time() - 4 * 60)
    # A real gated API call inside the window both succeeds AND bumps
    # last-activity forward -- proving the session doesn't expire on
    # the next check just because 4 of its original 5 minutes had
    # already elapsed before this request.
    assert client.get("/api/auth/idle-timeout").status_code == 200
    assert server._pin_last_activity[token] > server.time.time() - 5


def test_reading_session_status_alone_does_not_count_as_activity(monkeypatch, tmp_path):
    """GET /api/auth/session is exempt from the gate (see
    _PIN_EXEMPT_PATHS) specifically so the frontend can poll "am I
    still logged in?" without that poll itself being what keeps an
    otherwise-idle session alive forever. Uses a STILL-VALID stale
    timestamp (4 of 5 minutes elapsed) -- a timestamp already past the
    idle window would get the session dropped entirely by the validity
    check this same endpoint runs internally, which is correct behavior
    but would defeat this test's actual point (proving the poll itself
    doesn't refresh an otherwise-untouched timestamp)."""
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    client.put("/api/auth/idle-timeout", json={"idle_timeout_minutes": 5})

    token = client.cookies.get("stof_session")
    still_valid_but_stale = server.time.time() - 4 * 60
    monkeypatch.setitem(server._pin_last_activity, token, still_valid_but_stale)
    client.get("/api/auth/session")  # exempt path -- must not refresh activity
    assert server._pin_last_activity[token] == still_valid_but_stale


def test_logout_clears_idle_activity_tracking_too(monkeypatch, tmp_path):
    _reset_pin_state(monkeypatch, "123456", tmp_path)
    client = _client()
    client.post("/api/auth/login", json={"pin": "123456"})
    token = client.cookies.get("stof_session")
    assert token in server._pin_last_activity
    client.post("/api/auth/logout")
    assert token not in server._pin_last_activity
