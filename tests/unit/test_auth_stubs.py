"""Unit test for the Layer 4 Phase-2 stubs — oauth.py / saml.py / mfa.py.

Per CLAUDE.md rule 4 ("stubs over gaps"): Phase 2 components must exist
as real files raising NotImplementedError, never a blank file or TODO.
"""
import pytest

from stof.auth.mfa import MFAProvider
from stof.auth.oauth import OAuthProvider
from stof.auth.saml import SAMLProvider


@pytest.mark.parametrize("provider_cls", [OAuthProvider, SAMLProvider, MFAProvider])
def test_phase2_auth_provider_raises_not_implemented(provider_cls):
    with pytest.raises(NotImplementedError, match="Phase 2"):
        provider_cls()
