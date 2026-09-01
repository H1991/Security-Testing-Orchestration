"""Unit tests for Layer 4 — stof.auth's provider registry (__init__.py)."""
import pytest

from stof.auth import AUTH_PROVIDERS, ConfigError, FormLoginProvider, JWTAuthProvider, get_provider

# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_get_provider_jwt_needs_no_arguments():
    provider = get_provider("jwt")

    assert isinstance(provider, JWTAuthProvider)


def test_get_provider_form_login_forwards_kwargs():
    provider = get_provider(
        "form_login",
        login_url="https://x/login",
        username_selector="#u",
        password_selector="#p",
        submit_selector="#s",
    )

    assert isinstance(provider, FormLoginProvider)


def test_auth_providers_registry_has_both_phase1_types():
    assert set(AUTH_PROVIDERS) == {"form_login", "jwt"}


# ---------------------------------------------------------------------------
# Failure / input validation
# ---------------------------------------------------------------------------


def test_get_provider_unknown_auth_type_raises_config_error():
    with pytest.raises(ConfigError, match="Unknown auth_type"):
        get_provider("oauth")


def test_get_provider_form_login_missing_required_args_raises_type_error():
    with pytest.raises(TypeError):
        get_provider("form_login")
