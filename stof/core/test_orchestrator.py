"""Layer 8 — configuration-driven test orchestrator.

Marked "Phase 2 — Do Not Implement Yet" in CLAUDE.md's own roadmap table;
built now at explicit user request, ahead of Layer 9.

Scope note: CLAUDE.md's Layer 9 section documents `modules/registry.py`
doing nearly identical work ("reads config.modules and only instantiates
modules where the flag is true"). Layer 9's actual `VulnModule` plugin
classes don't exist yet in this incremental build, so this module can't
literally instantiate plugins -- it resolves `Config.modules` (Layer 1)
down to an ordered list of enabled module *names*. When Layer 9 lands,
its `registry.py` is expected to consume `build_test_plan()` rather than
duplicate this flag-reading logic.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from stof.config.schema import Config

_log = get_logger("core.test_orchestrator")

# crawler (Layer 7) always runs first when enabled -- vulnerability
# modules read endpoints.json, which only exists once it has. The rest
# follow ModulesConfig's declared field order.
MODULE_EXECUTION_ORDER = (
    "crawler",
    "jwt_tests",
    "auth_tests",
    "idor_tests",
    "sqli_tests",
    "xss_tests",
    "configuration_tests",
    "disclosure_tests",
    "graphql_tests",
    "deserialization_tests",
    "oauth_tests",
    "csrf_tests",
)


@dataclass
class TestPlan:
    """Which module names are enabled, in the order they should run."""

    enabled_modules: list[str]

    def is_enabled(self, module_name: str) -> bool:
        return module_name in self.enabled_modules


def build_test_plan(config: "Config") -> TestPlan:
    """Resolve `config.modules` into an ordered `TestPlan` -- config-
    driven selective execution: e.g. `jwt_tests: true, idor_tests: true,
    auth_tests: true, csrf_tests: false` activates only jwt_tests/
    auth_tests/idor_tests."""
    flags = config.modules
    enabled = [name for name in MODULE_EXECUTION_ORDER if getattr(flags, name, False)]
    _log.info(f"test plan resolved: {enabled}")
    return TestPlan(enabled_modules=enabled)
