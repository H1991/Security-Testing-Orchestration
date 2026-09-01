"""Unit tests for the Layer 5 Session Manager's data contract —
stof.session.models.Session.
"""
from datetime import datetime, timezone

from stof.session.models import Session

# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_session_construction_with_required_fields_only():
    session = Session(user_id="admin-01", role="admin", auth_type="form_login")

    assert session.user_id == "admin-01"
    assert session.role == "admin"
    assert session.auth_type == "form_login"
    assert session.is_valid is True
    assert session.cookies == {}
    assert session.headers == {}
    assert session.expires_at is None
    assert isinstance(session.created_at, datetime)
    assert session.created_at.tzinfo is not None


def test_session_auto_generates_a_unique_session_id():
    session_a = Session(user_id="admin-01", role="admin", auth_type="form_login")
    session_b = Session(user_id="admin-01", role="admin", auth_type="form_login")

    assert session_a.session_id != session_b.session_id


# ---------------------------------------------------------------------------
# Input validation — mutable defaults must not be shared across instances
# ---------------------------------------------------------------------------


def test_session_cookie_dicts_are_not_shared_between_instances():
    session_a = Session(user_id="a", role="admin", auth_type="form_login")
    session_b = Session(user_id="b", role="normal", auth_type="jwt")

    session_a.cookies["JSESSIONID"] = "abc"

    assert session_b.cookies == {}


def test_session_accepts_explicit_expiry_and_cookies():
    expires_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    session = Session(
        user_id="user-01",
        role="normal",
        auth_type="jwt",
        cookies={"JSESSIONID": "xyz"},
        headers={"Authorization": "Bearer abc"},
        expires_at=expires_at,
        is_valid=False,
    )

    assert session.cookies == {"JSESSIONID": "xyz"}
    assert session.headers == {"Authorization": "Bearer abc"}
    assert session.expires_at == expires_at
    assert session.is_valid is False


# ---------------------------------------------------------------------------
# to_row / from_row round trip (SQLite persistence, used by session_store.py)
# ---------------------------------------------------------------------------


def test_session_round_trips_through_row_serialisation():
    session = Session(
        user_id="user-01",
        role="normal",
        auth_type="jwt",
        cookies={"JSESSIONID": "xyz"},
        headers={"Authorization": "Bearer abc"},
        expires_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        is_valid=False,
    )

    restored = Session.from_row(session.to_row())

    assert restored == session


def test_session_round_trips_with_no_expiry():
    session = Session(user_id="admin-01", role="admin", auth_type="form_login")

    restored = Session.from_row(session.to_row())

    assert restored.expires_at is None
    assert restored == session
