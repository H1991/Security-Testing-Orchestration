"""Unit test for `stof.ui.server._activate_target`'s env-var sync.

Regression test for a real bug found while verifying TOTP/MFA against a
second target profile in a long-running console session: `_activate_target`
wrote the newly-activated target's password/TOTP secret into the `.env`
FILE correctly, but never updated this process's own `os.environ` --
`stof.config.loader.load_dotenv()` deliberately never overrides an
already-set env var (so a real shell `export` always wins), which meant
every activation after the very first silently kept using whichever
target activated first, for the rest of the server process's life (and
any scan subprocess it launches, which inherits this process's
environment). Confirmed live against `demo.testfire.net` then
`OWASP Juice Shop`: Verify Login kept authenticating with the first
target's credentials/TOTP secret against the second target's login page
until the server was restarted.
"""
import json
import os

from stof.ui import server
from stof.ui import targets as target_store


def _write_targets_doc(path, targets: list[dict]) -> None:
    path.write_text(json.dumps({"targets": targets, "active_target_id": None}, indent=2), encoding="utf-8")


def test_activating_a_second_target_updates_this_processs_own_env_vars(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("", encoding="utf-8")
    config_path = tmp_path / "config.json"
    config_path.write_text("{}", encoding="utf-8")
    users_path = tmp_path / "users.json"
    targets_path = tmp_path / "targets.json"

    monkeypatch.setattr(server, "ENV_PATH", env_path)
    monkeypatch.setattr(server, "CONFIG_PATH", config_path)
    monkeypatch.setattr(server, "USERS_PATH", users_path)
    monkeypatch.setattr(server, "TARGETS_PATH", targets_path)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("ADMIN_TOTP_SECRET", raising=False)

    first = target_store.new_profile("target-a", "Target A")
    first["base_url"] = "https://a.example"
    first["login_url"] = "https://a.example/login"
    target_store.set_role_credentials(first, "admin", "admin@a.example", "form_login")
    target_store.mark_password_set(first, "admin")
    target_store.set_role_totp_secret(first, "admin", "SECRETAAAAAAAAAA")
    server._write_dotenv_value(env_path, target_store.env_key("admin", "target-a"), "password-a")
    server._write_dotenv_value(env_path, target_store.totp_env_key("admin", "target-a"), "SECRETAAAAAAAAAA")

    second = target_store.new_profile("target-b", "Target B")
    second["base_url"] = "https://b.example"
    second["login_url"] = "https://b.example/login"
    target_store.set_role_credentials(second, "admin", "admin@b.example", "form_login")
    target_store.mark_password_set(second, "admin")
    target_store.set_role_totp_secret(second, "admin", "SECRETBBBBBBBBBB")
    server._write_dotenv_value(env_path, target_store.env_key("admin", "target-b"), "password-b")
    server._write_dotenv_value(env_path, target_store.totp_env_key("admin", "target-b"), "SECRETBBBBBBBBBB")

    _write_targets_doc(targets_path, [first, second])
    doc = target_store.load(targets_path)

    server._activate_target(doc, "target-a")
    assert os.environ["ADMIN_PASSWORD"] == "password-a"
    assert os.environ["ADMIN_TOTP_SECRET"] == "SECRETAAAAAAAAAA"

    # The actual regression: switching to a second target must overwrite
    # this process's live env vars, not just the .env file on disk.
    server._activate_target(doc, "target-b")
    assert os.environ["ADMIN_PASSWORD"] == "password-b"
    assert os.environ["ADMIN_TOTP_SECRET"] == "SECRETBBBBBBBBBB"
