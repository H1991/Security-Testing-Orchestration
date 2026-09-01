"""Unit tests for Layer 9 — stof.modules.registry."""
from stof.config.schema import Config, ModulesConfig, OutputConfig, TargetConfig
from stof.modules.idor_tests import IdorTestsModule
from stof.modules.registry import build_modules


def _config(modules: ModulesConfig) -> Config:
    return Config(
        target=TargetConfig(base_url="https://x", login_url="https://x/login"),
        modules=modules,
        output=OutputConfig(reports_dir="data/reports", evidence_dir="data/evidence"),
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_build_modules_instantiates_idor_tests_when_enabled():
    config = _config(ModulesConfig(crawler=False, idor_tests=True))

    modules = build_modules(config)

    assert len(modules) == 1
    assert isinstance(modules[0], IdorTestsModule)


def test_build_modules_empty_when_idor_tests_disabled():
    config = _config(ModulesConfig(crawler=False, idor_tests=False))

    assert build_modules(config) == []


def test_build_modules_ignores_crawler_flag_silently():
    """crawler=True shouldn't produce a VulnModule -- Layer 7 runs
    separately, before this registry is consulted."""
    config = _config(ModulesConfig(crawler=True, idor_tests=False))

    assert build_modules(config) == []


# ---------------------------------------------------------------------------
# Input validation — enabled-but-not-yet-implemented modules
# ---------------------------------------------------------------------------


def test_build_modules_skips_not_yet_implemented_module_without_crashing(caplog):
    config = _config(ModulesConfig(crawler=False, auth_tests=True, idor_tests=True))

    modules = build_modules(config)

    assert len(modules) == 1
    assert isinstance(modules[0], IdorTestsModule)
    assert any("auth_tests" in record.message for record in caplog.records)
