"""Layer 1 — Configuration loader.

This is the ONLY file in STOF that reads config JSON from disk. Every
other layer receives a `Config` / `UsersConfig` / `AuthTestsConfig`
object via dependency injection, never a raw file path.

Platform note: all paths go through `pathlib.Path` and all file I/O is
explicit UTF-8, so this module behaves identically on Linux, macOS, and
Windows.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .schema import AuthTestsConfig, Config, UsersConfig
from .validator import ConfigError, validate_auth_tests, validate_config, validate_users

_ENV_TOKEN_RE = re.compile(r"\{\{env:([A-Za-z_][A-Za-z0-9_]*)\}\}")

DEFAULT_CONFIG_PATH = Path("config/config.json")
DEFAULT_USERS_PATH = Path("config/users.json")
DEFAULT_AUTH_TESTS_PATH = Path("config/auth_tests.json")
DEFAULT_DOTENV_CANDIDATES = (Path(".env"), Path(".env.example"))


def load_dotenv(path: str | Path | None = None) -> None:
    """Populate `os.environ` from a `.env`-style file so `{{env:VAR}}`
    tokens resolve without the caller having to `export` anything first.

    Variables already set in the shell are never overridden. Values are
    taken verbatim from the raw text after the first `=` on each line —
    no shell quote parsing — so a payload-like value such as
    `ADMIN_PASSWORD='or''='` is preserved exactly as written instead of
    being mangled the way `bash source` would mangle it.

    If `path` is omitted, `.env` is used if present, else `.env.example`
    (so a fresh checkout with only the example file still runs).
    """
    if path is not None:
        candidates: tuple[Path, ...] = (Path(path),)
    else:
        candidates = DEFAULT_DOTENV_CANDIDATES

    dotenv_path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if dotenv_path is None:
        return

    for line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value


def _resolve_env_tokens(value: Any) -> Any:
    """Recursively replace `{{env:VAR}}` tokens with `os.environ[VAR]`.

    Raises ConfigError if a referenced environment variable is unset.
    """
    if isinstance(value, str):
        match = _ENV_TOKEN_RE.fullmatch(value)
        if match:
            var_name = match.group(1)
            resolved = os.environ.get(var_name)
            if resolved is None:
                raise ConfigError(
                    f"environment variable '{var_name}' referenced by "
                    f"'{{{{env:{var_name}}}}}' is not set"
                )
            return resolved
        return value
    if isinstance(value, dict):
        return {key: _resolve_env_tokens(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_env_tokens(item) for item in value]
    return value


def _read_json(path: str | Path) -> Any:
    resolved_path = Path(path)
    if not resolved_path.is_file():
        raise ConfigError(f"config file not found: {resolved_path}")

    try:
        text = resolved_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"could not read config file '{resolved_path}': {exc}") from exc

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in '{resolved_path}': {exc}") from exc


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> Config:
    """Load, resolve env tokens in, and validate `config/config.json`."""
    raw = _resolve_env_tokens(_read_json(path))
    try:
        config = Config.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid config in '{path}':\n{exc}") from exc

    validate_config(config)
    return config


def load_users(path: str | Path = DEFAULT_USERS_PATH) -> UsersConfig:
    """Load, resolve env tokens in, and validate `config/users.json`."""
    raw = _resolve_env_tokens(_read_json(path))
    try:
        users = UsersConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid users config in '{path}':\n{exc}") from exc

    validate_users(users)
    return users


def load_auth_tests(path: str | Path = DEFAULT_AUTH_TESTS_PATH) -> AuthTestsConfig:
    """Load and validate `config/auth_tests.json` (no env tokens expected)."""
    raw = _resolve_env_tokens(_read_json(path))
    try:
        auth_tests = AuthTestsConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid auth tests config in '{path}':\n{exc}") from exc

    validate_auth_tests(auth_tests)
    return auth_tests
