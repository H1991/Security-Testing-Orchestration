"""Unit tests for Layer 2 -- stof.core.module_registry.

The single-source-of-truth fix for a real, confirmed bug: before this
module existed, ModulesConfig's fields, registry.py's MODULE_FACTORIES,
test_orchestrator.py's MODULE_EXECUTION_ORDER, and two separate
_KNOWN_MODULES tuples (main.py, ui/server.py) were five independently
hand-maintained lists. They drifted -- a real scan silently dropped 5
enabled modules with no error at all.
"""
from stof.config.schema import ModulesConfig
from stof.core.module_registry import (
    ALL_MODULE_NAMES,
    NOT_YET_IMPLEMENTED,
    SPECIALLY_CONSTRUCTED,
    VULN_MODULE_NAMES,
    verify_registry_consistency,
)
from stof.core.test_orchestrator import MODULE_EXECUTION_ORDER
from stof.main import _KNOWN_MODULES as MAIN_KNOWN_MODULES
from stof.modules.registry import MODULE_FACTORIES
from stof.ui.server import _KNOWN_MODULES as SERVER_KNOWN_MODULES


def test_all_module_names_matches_modules_config_fields_exactly():
    assert tuple(ModulesConfig.model_fields.keys()) == ALL_MODULE_NAMES


def test_vuln_module_names_excludes_crawler_and_not_yet_implemented():
    assert "crawler" not in VULN_MODULE_NAMES
    for name in NOT_YET_IMPLEMENTED:
        assert name not in VULN_MODULE_NAMES


def test_vuln_module_names_includes_every_other_declared_module():
    expected = set(ALL_MODULE_NAMES) - {"crawler"} - NOT_YET_IMPLEMENTED
    assert set(VULN_MODULE_NAMES) == expected


def test_verify_registry_consistency_passes_for_the_real_module_factories():
    # The real regression test: this must not raise for the actual,
    # current MODULE_FACTORIES -- if a module is ever added to
    # ModulesConfig without a matching factory (and isn't declared
    # NOT_YET_IMPLEMENTED or SPECIALLY_CONSTRUCTED), this fails loudly.
    verify_registry_consistency(MODULE_FACTORIES)


def test_verify_registry_consistency_raises_when_a_module_is_missing():
    import pytest

    incomplete = dict(MODULE_FACTORIES)
    del incomplete["sqli_tests"]
    with pytest.raises(RuntimeError, match="sqli_tests"):
        verify_registry_consistency(incomplete)


def test_verify_registry_consistency_does_not_flag_specially_constructed_modules():
    # jwt_tests/auth_tests/csrf_tests are legitimately absent from
    # MODULE_FACTORIES (built by main.py's own _build_module_builders
    # instead) -- must not be treated as a drift bug.
    factories_without_specials = {k: v for k, v in MODULE_FACTORIES.items() if k not in SPECIALLY_CONSTRUCTED}
    verify_registry_consistency(factories_without_specials)


def test_module_execution_order_is_derived_from_all_module_names():
    assert MODULE_EXECUTION_ORDER == ALL_MODULE_NAMES


def test_module_execution_order_starts_with_crawler():
    # Vuln modules read endpoints.json, which only exists once crawler
    # has run -- this ordering isn't cosmetic.
    assert MODULE_EXECUTION_ORDER[0] == "crawler"


def test_main_and_server_known_modules_agree_on_the_vuln_module_set():
    # main.py's list has no crawler (crawler isn't selectable via
    # --module); server.py's list does (it displays crawler in the UI).
    # Minus that one intentional difference, they must be identical --
    # this is exactly the invariant that broke silently before.
    assert set(MAIN_KNOWN_MODULES) == set(VULN_MODULE_NAMES)
    assert set(SERVER_KNOWN_MODULES) == {"crawler", *VULN_MODULE_NAMES}


def test_every_currently_known_real_module_survives_in_all_three_lists():
    # The exact 5 modules that were silently dropped by the old
    # hardcoded MODULE_EXECUTION_ORDER -- pinned here so a regression
    # of that specific bug fails immediately, not just a generic drift.
    previously_dropped = {
        "ssrf_tests", "injection_variants_tests", "cache_tests",
        "business_logic_tests", "file_upload_tests",
    }
    for name in previously_dropped:
        assert name in MODULE_EXECUTION_ORDER, f"{name} missing from MODULE_EXECUTION_ORDER"
        assert name in VULN_MODULE_NAMES, f"{name} missing from VULN_MODULE_NAMES"
        assert name in MAIN_KNOWN_MODULES, f"{name} missing from main.py's _KNOWN_MODULES"
        assert name in SERVER_KNOWN_MODULES, f"{name} missing from server.py's _KNOWN_MODULES"
        assert name in MODULE_FACTORIES, f"{name} missing from registry.py's MODULE_FACTORIES"
