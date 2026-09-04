"""Layer 2 — the ONE authoritative list of module names STOF knows
about, derived directly from `stof.config.schema.ModulesConfig`'s own
Pydantic field declarations rather than hand-copied into yet another
tuple somewhere else.

Real bug this fixes: before this file existed, "which modules exist"
was answered independently by FIVE different places --
`ModulesConfig`'s fields, `modules/registry.py`'s `MODULE_FACTORIES`,
`core/test_orchestrator.py`'s `MODULE_EXECUTION_ORDER`, `main.py`'s
`_KNOWN_MODULES`, and `ui/server.py`'s `_KNOWN_MODULES`. They drifted:
a real scan silently dropped 5 real, enabled modules (ssrf_tests,
injection_variants_tests, cache_tests, business_logic_tests,
file_upload_tests) from every default run for an unknown number of
prior sessions, with no error, no warning -- confirmed live by
comparing a scan's own "Modules" log line against `config.json`.

Every other module that needs "the list of modules" now imports it
from here instead of maintaining its own copy. `verify_registry_
consistency()` is the second half of the fix: it doesn't just prevent
new hand-copied lists, it makes a future drift (e.g. a new module
added to `ModulesConfig` but never wired into `registry.py`)
fail loudly at import time instead of silently dropping coverage
again.
"""
from __future__ import annotations

from stof.config.schema import ModulesConfig

# Every field ModulesConfig declares, in declaration order -- the
# single authoritative source `MODULE_EXECUTION_ORDER` (test_
# orchestrator.py) is now derived FROM, not copied alongside.
ALL_MODULE_NAMES: tuple[str, ...] = tuple(ModulesConfig.model_fields.keys())

# Not a vulnerability module at all -- Layer 7's discovery pass, run
# separately before any vuln module is ever consulted. Excluded from
# "selectable vuln modules" lists, kept in ALL_MODULE_NAMES/execution
# order since it's still a real config.modules.* flag.
_DISCOVERY_ONLY = frozenset({"crawler"})

# Declared in ModulesConfig (so `config.modules.oauth_tests: true` is
# valid config and doesn't error) but genuinely not implemented yet --
# CLAUDE.md rule 9, Phase 2, on purpose. Excluded from the consistency
# check below rather than treated as a drift bug.
NOT_YET_IMPLEMENTED = frozenset({"oauth_tests"})

# Built by `main.py`'s own `_build_module_builders()` (they need
# target-specific config -- login URLs, role names -- ModulesConfig's
# plain boolean flag can't express) rather than `registry.py`'s
# zero-argument `MODULE_FACTORIES`. Documented already in registry.py's
# own module docstring; listed again here so the consistency check
# below knows not to flag their absence from MODULE_FACTORIES as a bug.
SPECIALLY_CONSTRUCTED = frozenset({"jwt_tests", "auth_tests", "csrf_tests"})

# Every module a "run everything enabled" scan or the UI's module list
# should ever be able to select -- i.e. every declared module minus
# discovery-only (crawler) and not-yet-implemented (oauth_tests).
VULN_MODULE_NAMES: tuple[str, ...] = tuple(
    name for name in ALL_MODULE_NAMES if name not in _DISCOVERY_ONLY and name not in NOT_YET_IMPLEMENTED
)


def verify_registry_consistency(module_factories: dict) -> None:
    """Called once, from `modules/registry.py` at import time (so
    importing it -- which both `main.py` and `ui/server.py` always do
    -- always runs this check without either needing to remember to
    call it themselves). Raises `RuntimeError` immediately, with the
    exact missing module name(s), if a module declared in
    `ModulesConfig` has no way to actually be constructed -- the
    silent-drop failure mode this whole file exists to prevent,
    surfaced at startup instead of discovered by comparing a scan log
    against config.json after the fact."""
    expected = set(VULN_MODULE_NAMES) - SPECIALLY_CONSTRUCTED
    missing = expected - set(module_factories.keys())
    if missing:
        raise RuntimeError(
            f"Module registry inconsistency: {sorted(missing)} declared in "
            "ModulesConfig but missing from modules/registry.py's MODULE_FACTORIES -- "
            "a scan would silently skip these even when enabled in config.json. "
            "Add a factory entry (or, if genuinely not implemented yet, add the name "
            "to stof.core.module_registry.NOT_YET_IMPLEMENTED)."
        )
