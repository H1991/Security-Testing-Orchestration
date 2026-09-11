"""Unit tests for Layer 9 -- stof.modules.tls_tests (TC-145-TC-148).

sslyze itself performs a real TLS handshake over the network -- never
exercised here. Every `run_techniques()` test monkeypatches the
module's own `_run_sslyze_scan` (the one function that actually talks
to a socket) with a fake, already-completed scan result built from
real sslyze enum/dataclass shapes, matching this project's own
"mock the I/O boundary, not the library" convention."""
from types import SimpleNamespace

from sslyze import RobotScanResultEnum, ScanCommandAttemptStatusEnum

from stof.crawler.endpoint_store import Endpoint
from stof.modules.results import ERROR, FAIL, PASS, SKIPPED
from stof.modules.tls_tests import TlsTestConfig, TlsTestsModule, _is_weak_cipher_name

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_is_weak_cipher_name_flags_null_export_rc4_des_anon():
    assert _is_weak_cipher_name("TLS_RSA_WITH_NULL_SHA") is True
    assert _is_weak_cipher_name("TLS_RSA_EXPORT_WITH_RC4_40_MD5") is True
    assert _is_weak_cipher_name("TLS_RSA_WITH_RC4_128_SHA") is True
    assert _is_weak_cipher_name("TLS_RSA_WITH_3DES_EDE_CBC_SHA") is True
    assert _is_weak_cipher_name("TLS_DH_anon_WITH_AES_128_CBC_SHA") is True


def test_is_weak_cipher_name_passes_modern_aead_suite():
    assert _is_weak_cipher_name("TLS_RSA_WITH_AES_256_GCM_SHA384") is False
    assert _is_weak_cipher_name("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256") is False


def test_target_host_port_parses_https_url_with_explicit_port():
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com:8443/login"))
    assert module._target_host_port([]) == ("example.com", 8443)


def test_target_host_port_defaults_to_443():
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com/login"))
    assert module._target_host_port([]) == ("example.com", 443)


def test_target_host_port_none_for_plain_http():
    module = TlsTestsModule(config=TlsTestConfig(base_url="http://example.com"))
    assert module._target_host_port([]) is None


def test_target_host_port_falls_back_to_first_endpoint():
    module = TlsTestsModule()
    endpoints = [Endpoint(url="https://discovered.example/x", method="GET", endpoint_type="page")]
    assert module._target_host_port(endpoints) == ("discovered.example", 443)


def test_target_host_port_none_when_nothing_to_go_on():
    module = TlsTestsModule()
    assert module._target_host_port([]) is None


# ---------------------------------------------------------------------------
# run_techniques() -- fake sslyze scan results
# ---------------------------------------------------------------------------


def _attempt(status=ScanCommandAttemptStatusEnum.COMPLETED, result=None, error_reason=None):
    return SimpleNamespace(status=status, result=result, error_reason=error_reason)


def _cipher_attempt(accepted_names: list[str]):
    accepted = [SimpleNamespace(cipher_suite=SimpleNamespace(name=n)) for n in accepted_names]
    return _attempt(result=SimpleNamespace(accepted_cipher_suites=accepted))


def _clean_attempts(**overrides):
    base = dict(
        ssl_2_0_cipher_suites=_cipher_attempt([]),
        ssl_3_0_cipher_suites=_cipher_attempt([]),
        tls_1_0_cipher_suites=_cipher_attempt([]),
        tls_1_1_cipher_suites=_cipher_attempt([]),
        tls_1_2_cipher_suites=_cipher_attempt(["TLS_RSA_WITH_AES_256_GCM_SHA384"]),
        heartbleed=_attempt(result=SimpleNamespace(is_vulnerable_to_heartbleed=False)),
        robot=_attempt(result=SimpleNamespace(robot_result=RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE)),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _scan_result(attempts, connectivity_error_trace=None):
    return SimpleNamespace(connectivity_error_trace=connectivity_error_trace, scan_result=attempts)


async def _run(module, endpoints=None):
    return await module.run_techniques(endpoints or [], session_manager=None, session_pool=None, evidence=None)


def _patch_scan(monkeypatch, result):
    import stof.modules.tls_tests as tls_tests_module

    monkeypatch.setattr(tls_tests_module, "_run_sslyze_scan", lambda hostname, port: result)


async def test_run_techniques_skips_a_plain_http_target():
    module = TlsTestsModule(config=TlsTestConfig(base_url="http://example.com"))
    results = await _run(module)
    assert len(results) == 4
    assert all(r.status == SKIPPED for r in results)
    assert {r.technique_id for r in results} == {"TC-145", "TC-146", "TC-147", "TC-148"}


async def test_run_techniques_reports_error_on_connectivity_failure(monkeypatch):
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://unreachable.example"))
    _patch_scan(monkeypatch, _scan_result(_clean_attempts(), connectivity_error_trace="Connection refused"))
    results = await _run(module)
    assert all(r.status == ERROR for r in results)
    assert "Connection refused" in results[0].detail


async def test_run_techniques_reports_error_when_the_scan_itself_raises(monkeypatch):
    import stof.modules.tls_tests as tls_tests_module

    def _boom(hostname, port):
        raise RuntimeError("nassl exploded")

    monkeypatch.setattr(tls_tests_module, "_run_sslyze_scan", _boom)
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    results = await _run(module)
    assert all(r.status == ERROR for r in results)
    assert "nassl exploded" in results[0].detail


async def test_run_techniques_all_pass_on_a_clean_target(monkeypatch):
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    _patch_scan(monkeypatch, _scan_result(_clean_attempts()))
    results = await _run(module)
    assert all(r.status == PASS for r in results)


async def test_deprecated_protocol_fails_when_tls_1_0_accepted(monkeypatch):
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    attempts = _clean_attempts(tls_1_0_cipher_suites=_cipher_attempt(["TLS_RSA_WITH_AES_128_CBC_SHA"]))
    _patch_scan(monkeypatch, _scan_result(attempts))
    results = await _run(module)
    deprecated = next(r for r in results if r.technique_id == "TC-145")
    assert deprecated.status == FAIL
    assert deprecated.finding is not None
    assert deprecated.finding.severity == "Medium"
    assert "TLS 1.0" in deprecated.finding.description
    # Every other technique is unaffected by this one's finding.
    assert all(r.status == PASS for r in results if r.technique_id != "TC-145")


async def test_weak_cipher_fails_and_is_high_severity_for_rc4(monkeypatch):
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    attempts = _clean_attempts(tls_1_2_cipher_suites=_cipher_attempt(["TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_RC4_128_SHA"]))
    _patch_scan(monkeypatch, _scan_result(attempts))
    results = await _run(module)
    weak = next(r for r in results if r.technique_id == "TC-146")
    assert weak.status == FAIL
    assert weak.finding.severity == "High"
    assert "RC4" in weak.finding.description


async def test_weak_cipher_is_critical_severity_for_null_cipher(monkeypatch):
    """NULL/anonymous ciphers provide no encryption at all -- strictly
    worse than an outdated-but-real cipher like RC4, so this is flagged
    more severely than the RC4 case above."""
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    attempts = _clean_attempts(tls_1_2_cipher_suites=_cipher_attempt(["TLS_RSA_WITH_NULL_SHA"]))
    _patch_scan(monkeypatch, _scan_result(attempts))
    results = await _run(module)
    weak = next(r for r in results if r.technique_id == "TC-146")
    assert weak.status == FAIL
    assert weak.finding.severity == "Critical"
    assert "no real encryption" in weak.finding.description


async def test_weak_cipher_passes_when_only_modern_ciphers_accepted(monkeypatch):
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    _patch_scan(monkeypatch, _scan_result(_clean_attempts()))
    results = await _run(module)
    weak = next(r for r in results if r.technique_id == "TC-146")
    assert weak.status == PASS


async def test_heartbleed_fails_when_vulnerable(monkeypatch):
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    attempts = _clean_attempts(heartbleed=_attempt(result=SimpleNamespace(is_vulnerable_to_heartbleed=True)))
    _patch_scan(monkeypatch, _scan_result(attempts))
    results = await _run(module)
    heartbleed = next(r for r in results if r.technique_id == "TC-147")
    assert heartbleed.status == FAIL
    assert heartbleed.finding.severity == "High"
    assert "CVE-2014-0160" in heartbleed.finding.description


async def test_heartbleed_reports_error_when_the_probe_itself_failed(monkeypatch):
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    attempts = _clean_attempts(heartbleed=_attempt(status=ScanCommandAttemptStatusEnum.ERROR, error_reason="connection reset"))
    _patch_scan(monkeypatch, _scan_result(attempts))
    results = await _run(module)
    heartbleed = next(r for r in results if r.technique_id == "TC-147")
    assert heartbleed.status == ERROR


async def test_robot_fails_with_high_severity_for_weak_oracle(monkeypatch):
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    attempts = _clean_attempts(robot=_attempt(result=SimpleNamespace(robot_result=RobotScanResultEnum.VULNERABLE_WEAK_ORACLE)))
    _patch_scan(monkeypatch, _scan_result(attempts))
    results = await _run(module)
    robot = next(r for r in results if r.technique_id == "TC-148")
    assert robot.status == FAIL
    assert robot.finding.severity == "High"


async def test_robot_fails_with_critical_severity_for_strong_oracle(monkeypatch):
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    attempts = _clean_attempts(robot=_attempt(result=SimpleNamespace(robot_result=RobotScanResultEnum.VULNERABLE_STRONG_ORACLE)))
    _patch_scan(monkeypatch, _scan_result(attempts))
    results = await _run(module)
    robot = next(r for r in results if r.technique_id == "TC-148")
    assert robot.status == FAIL
    assert robot.finding.severity == "Critical"


async def test_robot_reports_error_on_inconsistent_results(monkeypatch):
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    attempts = _clean_attempts(robot=_attempt(result=SimpleNamespace(robot_result=RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS)))
    _patch_scan(monkeypatch, _scan_result(attempts))
    results = await _run(module)
    robot = next(r for r in results if r.technique_id == "TC-148")
    assert robot.status == ERROR


async def test_robot_passes_when_rsa_key_exchange_not_supported(monkeypatch):
    """A server that doesn't offer RSA key exchange at all can't have a
    Bleichenbacher oracle for it -- a real, distinct PASS reason from
    "oracle present but not exploitable", both mapped to PASS here."""
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    attempts = _clean_attempts(robot=_attempt(result=SimpleNamespace(robot_result=RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED)))
    _patch_scan(monkeypatch, _scan_result(attempts))
    results = await _run(module)
    robot = next(r for r in results if r.technique_id == "TC-148")
    assert robot.status == PASS


async def test_run_returns_findings_only_for_failed_techniques(monkeypatch):
    """The public run() (VulnModule's abstract contract) returns Findings
    only -- PASS/SKIPPED/ERROR results carry no Finding, matching every
    other module's run()/run_techniques() split."""
    module = TlsTestsModule(config=TlsTestConfig(base_url="https://example.com"))
    attempts = _clean_attempts(heartbleed=_attempt(result=SimpleNamespace(is_vulnerable_to_heartbleed=True)))
    _patch_scan(monkeypatch, _scan_result(attempts))
    findings = await module.run([], session_manager=None, session_pool=None, evidence=None)
    assert len(findings) == 1
    assert findings[0].vuln_type == "Weak TLS/SSL Transport Configuration"
