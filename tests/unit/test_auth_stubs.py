"""Unit test for the Layer 4 Phase-2 stubs — oauth.py / saml.py — and
mfa.py's own, differently-shaped superseded-stub.

Per CLAUDE.md rule 4 ("stubs over gaps"): Phase 2 components must exist
as real files raising NotImplementedError, never a blank file or TODO.
"""
import pytest

from stof.auth.mfa import MFAProvider
from stof.auth.oauth import OAuthProvider
from stof.auth.saml import SAMLProvider


@pytest.mark.parametrize("provider_cls", [OAuthProvider, SAMLProvider])
def test_phase2_auth_provider_raises_not_implemented(provider_cls):
    with pytest.raises(NotImplementedError, match="Phase 2"):
        provider_cls()


def test_mfa_provider_stub_points_to_the_real_implementation():
    """`MFAProvider` is not a "not yet built" Phase-2 stub like OAuth/
    SAML -- TOTP/MFA IS built (see CLAUDE.md's "TOTP / MFA" section),
    just not as a standalone provider. This stub only exists so a stray
    `from stof.auth.mfa import MFAProvider` fails loudly with a pointer
    to where the real implementation lives, instead of silently doing
    nothing or raising an unhelpful bare error."""
    with pytest.raises(NotImplementedError, match="FormLoginProvider"):
        MFAProvider()
