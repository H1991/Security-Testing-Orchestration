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

from .assisted_login import AssistedLoginProvider
from .base import AuthExpiredError, AuthFailedError, AuthProvider
from .form_login import FormLoginProvider
from .jwt_auth import JWTAuthProvider
from .workflow_login import WorkflowLoginProvider

AUTH_PROVIDERS: dict[str, type[AuthProvider]] = {
    "form_login": FormLoginProvider,
    "jwt": JWTAuthProvider,
    # Selected by UserConfig.auth_type == "recorded_workflow" --
    # WorkflowLoginProvider needs a WorkflowRepository, unlike the two
    # above's kwarg-optional constructors, so `get_provider("recorded_
    # workflow")` with no kwargs will raise; `stof/main.py`'s own
    # session-manager wiring constructs it directly with one instead of
    # going through this registry (same reason `FormLoginProvider`
    # itself is built directly there too, per this file's own opening
    # docstring).
    "recorded_workflow": WorkflowLoginProvider,
    # Not auto-selected by any UserConfig.auth_type value -- a target
    # opts into this by setting TargetConfig.requires_assisted_login,
    # which swaps `FormLoginProvider` out for this one entirely for
    # that target's scan (see stof/main.py), rather than requiring a
    # separate per-user auth_type value.
    "assisted_manual": AssistedLoginProvider,
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
    "AssistedLoginProvider",
    "AuthExpiredError",
    "AuthFailedError",
    "AuthProvider",
    "FormLoginProvider",
    "JWTAuthProvider",
    "WorkflowLoginProvider",
    "get_provider",
]
