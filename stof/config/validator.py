"""Business-rule validation for STOF config contracts (Layer 1).

Pydantic (`schema.py`) enforces structural/type correctness. This module
enforces cross-field rules that a type system alone can't express, and is
the single place that raises `ConfigError` for those rules.
"""
from __future__ import annotations

from .schema import AuthTestsConfig, Config, UsersConfig

ALLOWED_TEST_MODULES = {
    "jwt_tests",
    "auth_tests",
    "idor_tests",
    "oauth_tests",
    "csrf_tests",
    "race_tests",
}


class ConfigError(Exception):
    """Raised for any config load or validation failure. Never let a raw
    exception (KeyError, ValidationError, JSONDecodeError, ...) escape
    the config layer — wrap it in ConfigError instead."""


def validate_config(config: Config) -> None:
    if not config.target.base_url.strip():
        raise ConfigError("target.base_url must not be empty")
    if not config.target.login_url.strip():
        raise ConfigError("target.login_url must not be empty")
    if not config.output.reports_dir.strip():
        raise ConfigError("output.reports_dir must not be empty")
    if not config.output.evidence_dir.strip():
        raise ConfigError("output.evidence_dir must not be empty")
    if config.browser.slowmo_ms < 0:
        raise ConfigError("browser.slowmo_ms must be >= 0")
    if config.burp.enabled:
        if not config.burp.api_url.strip():
            raise ConfigError("burp.api_url must not be empty when burp.enabled is true")
        if not config.burp.api_key.strip():
            raise ConfigError("burp.api_key must not be empty when burp.enabled is true")
        if "{{env:" in config.burp.api_key:
            raise ConfigError(
                f"burp.api_key still has an unresolved env token: "
                f"{config.burp.api_key!r} (loader should have resolved this)"
            )


def validate_users(users: UsersConfig) -> None:
    if not users.users:
        raise ConfigError("users.json must define at least one user")

    seen_ids: set[str] = set()
    for user in users.users:
        if user.id in seen_ids:
            raise ConfigError(f"duplicate user id: {user.id}")
        seen_ids.add(user.id)

        if not user.password.strip():
            raise ConfigError(f"user '{user.id}' has an empty password")
        if "{{env:" in user.password:
            raise ConfigError(
                f"user '{user.id}' still has an unresolved env token: "
                f"{user.password!r} (loader should have resolved this)"
            )


def validate_auth_tests(auth_tests: AuthTestsConfig) -> None:
    if not auth_tests.tests:
        raise ConfigError("auth_tests.json must define at least one test")

    seen_ids: set[str] = set()
    for test in auth_tests.tests:
        if test.id in seen_ids:
            raise ConfigError(f"duplicate test id: {test.id}")
        seen_ids.add(test.id)

        if test.module not in ALLOWED_TEST_MODULES:
            raise ConfigError(
                f"test '{test.id}' references unknown module '{test.module}' "
                f"(expected one of {sorted(ALLOWED_TEST_MODULES)})"
            )
