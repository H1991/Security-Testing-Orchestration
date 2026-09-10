"""Layer 4 — superseded stub.

TOTP/app-based MFA is real and implemented (see CLAUDE.md's "TOTP / MFA"
section under Layer 4) -- but NOT here, and NOT as a standalone
`AuthProvider` a target could select instead of `form_login`. A real
TOTP code is never a standalone login mechanism; it's always entered on
a page reached only after primary credentials were already submitted
and accepted, so a separate provider selectable via `UserConfig.
auth_type` wouldn't match how any real target actually works. It's
built as a second step layered directly onto `FormLoginProvider`
instead (`_maybe_complete_totp`, `stof/auth/form_login.py`), driven by
the optional `UserConfig.totp_secret` field.

This file is kept (not deleted) only so a stray `from stof.auth.mfa
import MFAProvider` fails loudly and points here, rather than with a
bare `ModuleNotFoundError` that gives no hint where the real
implementation actually lives.
"""
from __future__ import annotations


class MFAProvider:
    def __init__(self, *args: object, **kwargs: object) -> None:
        raise NotImplementedError(
            "MFAProvider was never built as a standalone provider -- TOTP/MFA is implemented as a "
            "second login step in FormLoginProvider (stof/auth/form_login.py's _maybe_complete_totp), "
            "driven by UserConfig.totp_secret. See CLAUDE.md's 'TOTP / MFA' section for why."
        )
