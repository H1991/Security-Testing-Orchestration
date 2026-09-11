"""Unit tests for Layer 5 — stof.session.session_store."""
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


# ---------------------------------------------------------------------------
# Cross-target isolation -- the real bug two concurrent scans against
# different targets hit: `role` alone used to be the whole key, so a
# scan against target B's "admin" role would silently load and reuse
# target A's still-unexpired "admin" session (cookies included). See
# session_store.py's own module docstring for the live incident this
# closes.
# ---------------------------------------------------------------------------


def test_same_role_on_different_targets_does_not_collide(tmp_path):
    db_path = tmp_path / "stof.db"
    store_a = SessionStore(db_path=db_path, target="https://a.example")
    store_b = SessionStore(db_path=db_path, target="https://b.example")

    session_a = Session(user_id="admin-a", role="admin", auth_type="form_login", cookies={"JSESSIONID": "a-cookie"})
    session_b = Session(user_id="admin-b", role="admin", auth_type="form_login", cookies={"JSESSIONID": "b-cookie"})
    store_a.save(session_a)
    store_b.save(session_b)

    assert store_a.load("admin").cookies == {"JSESSIONID": "a-cookie"}
    assert store_b.load("admin").cookies == {"JSESSIONID": "b-cookie"}


def test_load_all_only_returns_sessions_for_this_store_own_target(tmp_path):
    db_path = tmp_path / "stof.db"
    store_a = SessionStore(db_path=db_path, target="https://a.example")
    store_b = SessionStore(db_path=db_path, target="https://b.example")
    store_a.save(_session("admin"))
    store_a.save(_session("normal"))
    store_b.save(_session("admin"))

    assert set(store_a.load_all()) == {"admin", "normal"}
    assert set(store_b.load_all()) == {"admin"}


def test_delete_on_one_target_does_not_affect_the_same_role_on_another_target(tmp_path):
    db_path = tmp_path / "stof.db"
    store_a = SessionStore(db_path=db_path, target="https://a.example")
    store_b = SessionStore(db_path=db_path, target="https://b.example")
    store_a.save(_session("admin"))
    store_b.save(_session("admin"))

    store_a.delete("admin")

    assert store_a.load("admin") is None
    assert store_b.load("admin") is not None


def test_save_overwrites_only_the_same_role_and_target_pair(tmp_path):
    db_path = tmp_path / "stof.db"
    store_a = SessionStore(db_path=db_path, target="https://a.example")
    store_b = SessionStore(db_path=db_path, target="https://b.example")
    store_a.save(_session("admin"))
    store_b.save(_session("admin"))

    updated = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "updated"})
    store_a.save(updated)

    assert store_a.load("admin").cookies == {"JSESSIONID": "updated"}
    assert store_b.load("admin").cookies == {"JSESSIONID": "abc"}  # untouched


def test_migrates_a_pre_existing_role_only_table_without_raising(tmp_path):
    """A `data/stof.db` created before per-target scoping existed had
    `role TEXT PRIMARY KEY` and no `target` column at all. Opening it
    with the new schema must migrate cleanly (dropping the old cache
    table, per this module's own docstring), not raise or silently
    keep the old, collision-prone schema."""
    import sqlite3

    db_path = tmp_path / "stof.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE sessions (
            role TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            auth_type TEXT NOT NULL,
            cookies TEXT NOT NULL,
            headers TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            is_valid INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO sessions VALUES ('admin', 'sid', 'uid', 'form_login', '{}', '{}', '2026-01-01T00:00:00+00:00', NULL, 1)"
    )
    conn.commit()
    conn.close()

    store = SessionStore(db_path=db_path, target="https://a.example")  # must not raise

    assert store.load("admin") is None  # old, pre-migration row is gone, not silently reused across targets
