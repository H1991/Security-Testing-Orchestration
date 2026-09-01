"""Layer 9 — Vulnerability Modules (plugins)."""
from __future__ import annotations

from .base import VulnModule
from .idor_tests import IdorTestConfig, IdorTestsModule
from .jwt_tests import JwtTestConfig, JwtTestsModule
from .registry import MODULE_FACTORIES, build_modules

__all__ = [
    "MODULE_FACTORIES",
    "IdorTestConfig",
    "IdorTestsModule",
    "JwtTestConfig",
    "JwtTestsModule",
    "VulnModule",
    "build_modules",
]
