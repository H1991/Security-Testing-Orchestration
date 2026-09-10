"""Unit tests for Layer 1 — Configuration (stof.config)."""
import json

import pytest

from stof.config import ConfigError, load_auth_tests, load_config, load_users

VALID_CONFIG = {
    "target": {
        "base_url": "https://demo.testfire.net",
        "login_url": "https://demo.testfire.net/bank/login.aspx",
    },
    "browser": {"headless": True, "slowmo_ms": 0, "proxy": None},
    "modules": {
        "crawler": True,
        "jwt_tests": True,
        "auth_tests": True,
        "idor_tests": False,
        "oauth_tests": False,
        "csrf_tests": False,
    },
    "output": {"reports_dir": "data/reports", "evidence_dir": "data/evidence"},
}

VALID_USERS = {
    "users": [
        {
            "id": "admin-01",
            "role": "admin",
            "username": "admin@target.com",
            "password": "{{env:ADMIN_PASSWORD}}",
            "auth_type": "form_login",
        },
        {
            "id": "user-01",
            "role": "normal",
            "username": "user@target.com",
            "password": "{{env:USER_PASSWORD}}",
            "auth_type": "jwt",
        },
    ]
}

VALID_AUTH_TESTS = {
    "tests": [
        {
            "id": "AUTH-001",
            "name": "Session Fixation",
            "module": "auth_tests",
            "enabled": True,
            "payloads": ["JSESSIONID=FIXED123"],
            "severity": "High",
        }
    ]
}


def _write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_load_config_happy_path(tmp_path):
    config_path = _write_json(tmp_path / "config.json", VALID_CONFIG)

    config = load_config(config_path)

    assert config.target.base_url == "https://demo.testfire.net"
    assert config.modules.jwt_tests is True
    assert config.modules.idor_tests is False
    assert config.browser.headless is True


def test_load_config_burp_defaults_to_disabled_and_empty_key(tmp_path):
    """No `burp` key at all in config.json (matches VALID_CONFIG /
    this project's shipped config.json) must not force every user to
    have a BURP_API_KEY env var set just to run a normal scan."""
    config_path = _write_json(tmp_path / "config.json", VALID_CONFIG)

    config = load_config(config_path)

    assert config.burp.enabled is False
    assert config.burp.api_key == ""
    assert config.burp.api_url == "http://127.0.0.1:1337"


def test_load_config_burp_disabled_with_empty_api_key_loads_without_the_env_var_set(tmp_path, monkeypatch):
    """Regression test: an earlier shipped config.json explicitly wrote
    burp.api_key as "{{env:BURP_API_KEY}}" even with burp.enabled=false,
    which made load_config() fail for anyone who hadn't set BURP_API_KEY
    -- for a feature they weren't even using. The fix is on the writer
    side (never emit a token for a field you don't need resolved): a
    disabled burp block with an empty literal string must always load
    cleanly, regardless of what's in the environment."""
    monkeypatch.delenv("BURP_API_KEY", raising=False)
    with_burp = json.loads(json.dumps(VALID_CONFIG))
    with_burp["burp"] = {"enabled": False, "api_url": "http://127.0.0.1:1337", "api_key": ""}
    config_path = _write_json(tmp_path / "config.json", with_burp)

    config = load_config(config_path)

    assert config.burp.enabled is False
    assert config.burp.api_key == ""


def test_load_config_unresolved_env_token_still_fails_even_when_burp_disabled(tmp_path, monkeypatch):
    """The other half of the same contract: an *explicit* {{env:VAR}}
    token is still a promise that the variable is set, whether or not
    the feature referencing it is enabled -- `configure` and this
    project's shipped config.json avoid this by never writing the token
    in the first place (see the test above), not by loosening this
    check."""
    monkeypatch.delenv("BURP_API_KEY", raising=False)
    with_burp = json.loads(json.dumps(VALID_CONFIG))
    with_burp["burp"] = {"enabled": False, "api_url": "http://127.0.0.1:1337", "api_key": "{{env:BURP_API_KEY}}"}
    config_path = _write_json(tmp_path / "config.json", with_burp)

    with pytest.raises(ConfigError, match="BURP_API_KEY"):
        load_config(config_path)


def test_load_config_burp_enabled_resolves_env_token(tmp_path, monkeypatch):
    monkeypatch.setenv("BURP_API_KEY", "s3cr3t-burp-key")
    with_burp = json.loads(json.dumps(VALID_CONFIG))
    with_burp["burp"] = {"enabled": True, "api_url": "http://192.168.1.69:1337", "api_key": "{{env:BURP_API_KEY}}"}
    config_path = _write_json(tmp_path / "config.json", with_burp)

    config = load_config(config_path)

    assert config.burp.enabled is True
    assert config.burp.api_key == "s3cr3t-burp-key"
    assert config.burp.api_url == "http://192.168.1.69:1337"


def test_load_users_happy_path_resolves_env_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "s3cr3t-admin")
    monkeypatch.setenv("USER_PASSWORD", "s3cr3t-user")
    users_path = _write_json(tmp_path / "users.json", VALID_USERS)

    users = load_users(users_path)

    assert users.users[0].password == "s3cr3t-admin"
    assert users.users[1].password == "s3cr3t-user"
    # Ensure the raw token never leaks through unresolved.
    assert "{{env:" not in users.users[0].password


def test_load_users_totp_secret_defaults_to_none(tmp_path, monkeypatch):
    """No `totp_secret` key in users.json at all -- the overwhelming
    common case (no MFA configured) -- must default to None, not error
    or require every existing users.json to be updated."""
    monkeypatch.setenv("ADMIN_PASSWORD", "s3cr3t-admin")
    monkeypatch.setenv("USER_PASSWORD", "s3cr3t-user")
    users_path = _write_json(tmp_path / "users.json", VALID_USERS)

    users = load_users(users_path)

    assert users.users[0].totp_secret is None


def test_load_users_totp_secret_resolves_env_token(tmp_path, monkeypatch):
    """`totp_secret` uses the exact same `{{env:VAR}}` convention as
    `password` -- `_resolve_env_tokens` is field-name-agnostic, so this
    should work with zero loader changes; this test is the proof."""
    monkeypatch.setenv("ADMIN_PASSWORD", "s3cr3t-admin")
    monkeypatch.setenv("USER_PASSWORD", "s3cr3t-user")
    monkeypatch.setenv("ADMIN_TOTP_SECRET", "JBSWY3DPEHPK3PXP")
    with_totp = json.loads(json.dumps(VALID_USERS))
    with_totp["users"][0]["totp_secret"] = "{{env:ADMIN_TOTP_SECRET}}"
    users_path = _write_json(tmp_path / "users.json", with_totp)

    users = load_users(users_path)

    assert users.users[0].totp_secret == "JBSWY3DPEHPK3PXP"
    assert "{{env:" not in users.users[0].totp_secret


def test_load_auth_tests_happy_path(tmp_path):
    auth_tests_path = _write_json(tmp_path / "auth_tests.json", VALID_AUTH_TESTS)

    auth_tests = load_auth_tests(auth_tests_path)

    assert auth_tests.tests[0].id == "AUTH-001"
    assert auth_tests.tests[0].severity == "High"


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------


def test_load_config_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "does_not_exist.json")


def test_load_config_malformed_json_raises_config_error(tmp_path):
    bad_path = tmp_path / "config.json"
    bad_path.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(ConfigError, match="invalid JSON"):
        load_config(bad_path)


def test_load_users_missing_env_var_raises_config_error(tmp_path, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("USER_PASSWORD", raising=False)
    users_path = _write_json(tmp_path / "users.json", VALID_USERS)

    with pytest.raises(ConfigError, match="ADMIN_PASSWORD"):
        load_users(users_path)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_load_config_missing_required_field_raises_config_error(tmp_path):
    invalid = json.loads(json.dumps(VALID_CONFIG))
    del invalid["target"]["base_url"]
    config_path = _write_json(tmp_path / "config.json", invalid)

    with pytest.raises(ConfigError, match="invalid config"):
        load_config(config_path)


def test_load_config_burp_enabled_without_api_key_raises_config_error(tmp_path):
    invalid = json.loads(json.dumps(VALID_CONFIG))
    invalid["burp"] = {"enabled": True, "api_url": "http://192.168.1.69:1337", "api_key": ""}
    config_path = _write_json(tmp_path / "config.json", invalid)

    with pytest.raises(ConfigError, match=r"burp\.api_key"):
        load_config(config_path)


def test_load_config_burp_enabled_without_api_url_raises_config_error(tmp_path):
    invalid = json.loads(json.dumps(VALID_CONFIG))
    invalid["burp"] = {"enabled": True, "api_url": "  ", "api_key": "some-key"}
    config_path = _write_json(tmp_path / "config.json", invalid)

    with pytest.raises(ConfigError, match=r"burp\.api_url"):
        load_config(config_path)


def test_load_users_invalid_auth_type_raises_config_error(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "x")
    monkeypatch.setenv("USER_PASSWORD", "y")
    invalid = json.loads(json.dumps(VALID_USERS))
    invalid["users"][0]["auth_type"] = "oauth"  # not allowed in Phase 1
    users_path = _write_json(tmp_path / "users.json", invalid)

    with pytest.raises(ConfigError, match="invalid users config"):
        load_users(users_path)


def test_load_users_duplicate_ids_raises_config_error(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "x")
    monkeypatch.setenv("USER_PASSWORD", "y")
    invalid = json.loads(json.dumps(VALID_USERS))
    invalid["users"][1]["id"] = invalid["users"][0]["id"]
    users_path = _write_json(tmp_path / "users.json", invalid)

    with pytest.raises(ConfigError, match="duplicate user id"):
        load_users(users_path)


def test_load_auth_tests_unknown_module_raises_config_error(tmp_path):
    invalid = json.loads(json.dumps(VALID_AUTH_TESTS))
    invalid["tests"][0]["module"] = "not_a_real_module"
    auth_tests_path = _write_json(tmp_path / "auth_tests.json", invalid)

    with pytest.raises(ConfigError, match="unknown module"):
        load_auth_tests(auth_tests_path)


def test_load_auth_tests_invalid_severity_raises_config_error(tmp_path):
    invalid = json.loads(json.dumps(VALID_AUTH_TESTS))
    invalid["tests"][0]["severity"] = "Super High"
    auth_tests_path = _write_json(tmp_path / "auth_tests.json", invalid)

    with pytest.raises(ConfigError, match="invalid auth tests config"):
        load_auth_tests(auth_tests_path)
