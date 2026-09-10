"""Layer 9 — module loader.

Reads `config.modules` (via Layer 8's `build_test_plan()`, exactly as
that module's own docstring anticipated: "When Layer 9 lands, its
registry.py is expected to consume build_test_plan() rather than
duplicate this flag-reading logic") and only instantiates `VulnModule`
plugins where the flag is true. Adding a new module = create a new file
+ register it here; no other module changes.

`idor_tests`, `configuration_tests`, `disclosure_tests`,
`graphql_tests`, `deserialization_tests`, `sqli_tests`, and
`xss_tests` are auto-registered: each constructs correctly with zero
arguments (sensible "admin"/"normal" role defaults, same convention
`IdorTestsModule` itself uses).

`auth_tests`, `jwt_tests`, and `mfa_tests` are NOT auto-registered here,
for the same reason: `AuthTestsModule` needs `login_json_endpoint`/
`change_password_url`/... (target-specific URLs `Config.modules`'s
plain boolean flag can't express), `JwtTestsModule` needs `roles=[...]`
(which roles are JWT-authenticated), and `MfaTestsModule` needs
`login_url`/`test_username`/`test_password`/`totp_secret` for the role
under test (from `UserConfig`, which `build_modules()` here never
receives). All three exist and are Phase 1 -- `stof/main.py`'s own
`_build_module_builders()` is the real construction site, reading the
needed config/`UserConfig` data. `build_modules()` still logs a warning
rather than crashing if a caller enables any of them through this
simpler path.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from stof.core.logger import get_logger
from stof.core.module_registry import verify_registry_consistency
from stof.core.test_orchestrator import build_test_plan

from .base import VulnModule
from .business_logic_tests import BusinessLogicTestsModule
from .cache_tests import CacheTestsModule
from .configuration_tests import ConfigurationTestsModule
from .deserialization_tests import DeserializationTestsModule
from .disclosure_tests import DisclosureTestsModule
from .file_upload_tests import FileUploadTestsModule
from .graphql_tests import GraphQLTestsModule
from .idor_tests import IdorTestsModule
from .injection_variants_tests import InjectionVariantsTestsModule
from .sqli_tests import SqliTestsModule
from .ssrf_tests import SsrfTestsModule
from .xss_tests import XssTestsModule

if TYPE_CHECKING:
    from stof.config.schema import Config

_log = get_logger("modules.registry")

MODULE_FACTORIES: dict[str, Callable[[], VulnModule]] = {
    "idor_tests": IdorTestsModule,
    "business_logic_tests": BusinessLogicTestsModule,
    "injection_variants_tests": InjectionVariantsTestsModule,
    "cache_tests": CacheTestsModule,
    "configuration_tests": ConfigurationTestsModule,
    "disclosure_tests": DisclosureTestsModule,
    "file_upload_tests": FileUploadTestsModule,
    "graphql_tests": GraphQLTestsModule,
    "deserialization_tests": DeserializationTestsModule,
    "sqli_tests": SqliTestsModule,
    "ssrf_tests": SsrfTestsModule,
    "xss_tests": XssTestsModule,
}

# Layer 7's crawler flag lives in the same `Config.modules` block and
# rides through `build_test_plan()`, but it isn't a VulnModule -- it's
# run separately, before this registry is ever consulted. Not a warning
# case, just not a factory entry.
_NOT_A_VULN_MODULE = {"crawler"}

# Runs at import time -- both `main.py` and `ui/server.py` import this
# module unconditionally, so this check is enforced everywhere without
# either needing to remember to call it. See module_registry.py's own
# docstring for the real, live bug this closes (5 modules silently
# missing from every default scan for an unknown number of sessions).
verify_registry_consistency(MODULE_FACTORIES)


def build_modules(config: "Config") -> list[VulnModule]:
    plan = build_test_plan(config)
    modules: list[VulnModule] = []
    for name in plan.enabled_modules:
        if name in _NOT_A_VULN_MODULE:
            continue
        factory = MODULE_FACTORIES.get(name)
        if factory is None:
            _log.warning(f"module '{name}' is enabled in config but not yet implemented -- skipping")
            continue
        modules.append(factory())
    return modules
