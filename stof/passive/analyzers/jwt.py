"""JWTAnalyzer -- feeds TC-057 (JWT Role Manipulation).

Decodes an observed `Authorization: Bearer <jwt>` request header --
never a signature check, never a mutation, just reads the claims
already sent. Flags a candidate for the existing active TC-057
techniques (`jwt_tests.py`) when the token carries an authorization-
relevant claim; does not itself attempt any manipulation.
"""
from __future__ import annotations

import base64
import json

from ..models import Observation, RequestExchange
from .base import PassiveAnalyzer

_ROLE_CLAIM_NAMES = ("role", "roles", "isadmin", "is_admin", "permissions", "scope", "scopes")


def _decode_jwt_payload(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
        decoded = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


class JWTAnalyzer(PassiveAnalyzer):
    def analyze_request(self, exchange: RequestExchange) -> list[Observation]:
        auth_header = next((v for k, v in exchange.headers.items() if k.lower() == "authorization"), None)
        if not auth_header or not auth_header.lower().startswith("bearer "):
            return []
        token = auth_header.split(" ", 1)[1].strip()
        claims = _decode_jwt_payload(token)
        if claims is None:
            return []

        role_claims = [name for name in _ROLE_CLAIM_NAMES if name in claims]
        if not role_claims:
            return []

        return [Observation(
            kind="jwt_role_claim",
            testcase_ids=("TC-057",),
            endpoint_url=exchange.url,
            method=exchange.method,
            detail=f"JWT carries authorization-relevant claim(s): {role_claims}",
            value=", ".join(f"{name}={claims[name]!r}" for name in role_claims),
        )]
