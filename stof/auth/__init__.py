"""Layer 4 — Authentication Manager public API + provider registry.

CLAUDE.md's registry example calls `AUTH_PROVIDERS[auth_type]()` with no
arguments. `JWTAuthProvider()` really can be built that way (its
constructor args are all optional), but `FormLoginProvider` needs
`login_url`/selectors that describe the target's login form -- fields
that don't exist anywhere in Phase 1's `UserConfig`/`Config` schema
(Layer 1), so they can't come from `users.json` implicitly. `get_provider`
therefore accepts `**kwargs` and forwards them to the provider's
constructor; called with none, it behaves exactly as documented.
"""
from __future__ import annotations

from stof.config import ConfigError

from .base import AuthExpiredError, AuthFailedError, AuthProvider
from .form_login import FormLoginProvider
from .jwt_auth import JWTAuthProvider

AUTH_PROVIDERS: dict[str, type[AuthProvider]] = {
    "form_login": FormLoginProvider,
    "jwt": JWTAuthProvider,
    # Phase 2:
    # "oauth": OAuthProvider,
    # "saml":  SAMLProvider,
}


def get_provider(auth_type: str, **kwargs: object) -> AuthProvider:
    provider_cls = AUTH_PROVIDERS.get(auth_type)
    if provider_cls is None:
        raise ConfigError(f"Unknown auth_type: {auth_type}")
    return provider_cls(**kwargs)


__all__ = [
    "AUTH_PROVIDERS",
    "AuthExpiredError",
    "AuthFailedError",
    "AuthProvider",
    "FormLoginProvider",
    "JWTAuthProvider",
    "get_provider",
]
