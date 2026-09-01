"""Unit tests for Layer 4 — stof.auth.base (AuthProvider ABC + exceptions)."""
import pytest

from stof.auth.base import AuthExpiredError, AuthFailedError, AuthProvider


def test_auth_provider_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        AuthProvider()


def test_auth_failed_and_expired_errors_are_distinct_exception_types():
    assert issubclass(AuthFailedError, Exception)
    assert issubclass(AuthExpiredError, Exception)
    assert not issubclass(AuthFailedError, AuthExpiredError)
    assert not issubclass(AuthExpiredError, AuthFailedError)
