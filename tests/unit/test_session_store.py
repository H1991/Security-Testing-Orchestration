"""Unit tests for Layer 5 — stof.session.session_store."""
from datetime import datetime, timezone

from stof.session.models import Session
from stof.session.session_store import SessionStore


def _session(role: str = "admin") -> Session:
    return Session(
        user_id=f"{role}-01",
        role=role,
        auth_type="form_login",
        cookies={"JSESSIONID": "abc"},
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_save_and_load_round_trips(tmp_path):
    store = SessionStore(db_path=tmp_path / "stof.db")
    session = _session("admin")

    store.save(session)
    loaded = store.load("admin")

    assert loaded == session


def test_load_all_returns_every_saved_role(tmp_path):
    store = SessionStore(db_path=tmp_path / "stof.db")
    admin_session = _session("admin")
    normal_session = _session("normal")

    store.save(admin_session)
    store.save(normal_session)

    all_sessions = store.load_all()

    assert all_sessions == {"admin": admin_session, "normal": normal_session}


def test_save_overwrites_existing_role_for_same_role(tmp_path):
    store = SessionStore(db_path=tmp_path / "stof.db")
    first = _session("admin")
    store.save(first)

    second = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "new"})
    store.save(second)

    loaded = store.load("admin")
    assert loaded.session_id == second.session_id
    assert loaded.cookies == {"JSESSIONID": "new"}
    assert len(store.load_all()) == 1


# ---------------------------------------------------------------------------
# Failure / missing-data cases
# ---------------------------------------------------------------------------


def test_load_missing_role_returns_none(tmp_path):
    store = SessionStore(db_path=tmp_path / "stof.db")

    assert store.load("nonexistent") is None


def test_load_all_on_empty_store_returns_empty_dict(tmp_path):
    store = SessionStore(db_path=tmp_path / "stof.db")

    assert store.load_all() == {}


def test_delete_removes_the_role(tmp_path):
    store = SessionStore(db_path=tmp_path / "stof.db")
    store.save(_session("admin"))

    store.delete("admin")

    assert store.load("admin") is None


def test_delete_missing_role_does_not_raise(tmp_path):
    store = SessionStore(db_path=tmp_path / "stof.db")

    store.delete("nonexistent")  # must not raise


# ---------------------------------------------------------------------------
# Input validation — persistence survives across store instances (crash-resume)
# ---------------------------------------------------------------------------


def test_sessions_persist_across_separate_store_instances(tmp_path):
    db_path = tmp_path / "stof.db"
    session = _session("admin")
    SessionStore(db_path=db_path).save(session)

    reloaded_store = SessionStore(db_path=db_path)
    loaded = reloaded_store.load("admin")

    assert loaded == session


def test_save_preserves_none_expiry_and_invalid_flag(tmp_path):
    store = SessionStore(db_path=tmp_path / "stof.db")
    session = Session(user_id="u", role="normal", auth_type="jwt", is_valid=False, expires_at=None)

    store.save(session)
    loaded = store.load("normal")

    assert loaded.expires_at is None
    assert loaded.is_valid is False
