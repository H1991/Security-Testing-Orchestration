"""Unit tests for Layer 8 — stof.core.test_orchestrator."""
from stof.config.schema import Config, ModulesConfig, OutputConfig, TargetConfig
from stof.core.test_orchestrator import MODULE_EXECUTION_ORDER, build_test_plan


def _config(modules: ModulesConfig) -> Config:
    return Config(
        target=TargetConfig(base_url="https://x", login_url="https://x/login"),
        modules=modules,
        output=OutputConfig(reports_dir="data/reports", evidence_dir="data/evidence"),
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_build_test_plan_matches_the_documented_selective_execution_example():
    """Mirrors the SVG's own example: jwt: true, idor: true, auth: true,
    csrf: false -> selective execution of exactly those three."""
    config = _config(
        ModulesConfig(
            crawler=False, jwt_tests=True, auth_tests=True, idor_tests=True,
            oauth_tests=False, csrf_tests=False,
        )
    )

    plan = build_test_plan(config)

    assert plan.enabled_modules == ["jwt_tests", "auth_tests", "idor_tests"]


def test_build_test_plan_all_enabled_preserves_execution_order():
    config = _config(
        ModulesConfig(
            crawler=True, jwt_tests=True, auth_tests=True, idor_tests=True,
            business_logic_tests=True, file_upload_tests=True, cache_tests=True,
            sqli_tests=True, xss_tests=True, ssrf_tests=True, injection_variants_tests=True,
            configuration_tests=True, disclosure_tests=True, graphql_tests=True, deserialization_tests=True,
            oauth_tests=True, csrf_tests=True,
        )
    )

    plan = build_test_plan(config)

    assert plan.enabled_modules == list(MODULE_EXECUTION_ORDER)


def test_is_enabled_reflects_the_plan():
    config = _config(ModulesConfig(crawler=True, jwt_tests=True))

    plan = build_test_plan(config)

    assert plan.is_enabled("crawler") is True
    assert plan.is_enabled("jwt_tests") is True
    assert plan.is_enabled("auth_tests") is False


# ---------------------------------------------------------------------------
# Input validation / edge cases
# ---------------------------------------------------------------------------


def test_build_test_plan_all_disabled_returns_empty_plan():
    config = _config(
        ModulesConfig(
            crawler=False, jwt_tests=False, auth_tests=False, idor_tests=False,
            oauth_tests=False, csrf_tests=False,
        )
    )

    plan = build_test_plan(config)

    assert plan.enabled_modules == []
    assert plan.is_enabled("crawler") is False


def test_build_test_plan_uses_modules_config_defaults():
    """ModulesConfig defaults crawler=True and every test module=False
    (see Layer 1's schema.py) -- confirms build_test_plan respects those
    defaults rather than assuming anything on its own."""
    config = _config(ModulesConfig())

    plan = build_test_plan(config)

    assert plan.enabled_modules == ["crawler"]
