"""Unit tests for Recon Engine — stof.recon.target_profile."""
from stof.recon.recon_engine import ReconReport
from stof.recon.target_profile import TargetProfile, build_target_profile


def _report(tech_stack: list[dict]) -> ReconReport:
    return ReconReport(target="https://x", scanned_at="2026-01-01T00:00:00Z", pages_analyzed=len(tech_stack), tech_stack=tech_stack)


def test_build_target_profile_returns_unknown_when_report_is_none():
    profile = build_target_profile(None)
    assert profile.stack_family == "unknown"
    assert profile.confidence == "none"
    assert profile.detected_tech == []


def test_build_target_profile_returns_unknown_when_no_tech_detected():
    report = _report([{"url": "https://x/", "tech": []}])
    profile = build_target_profile(report)
    assert profile.stack_family == "unknown"


def test_build_target_profile_detects_java_from_header_and_url_extension():
    """Real-world case: demo.testfire.net -- Apache-Coyote/1.1 header
    plus .jsp URLs, two independent signals agreeing -> high confidence."""
    report = _report([
        {"url": "https://x/index.jsp", "tech": ["Apache-Coyote/1.1"]},
        {"url": "https://x/feedback.jsp", "tech": ["Apache-Coyote/1.1"]},
    ])
    profile = build_target_profile(report)
    assert profile.stack_family == "java"
    assert profile.confidence == "high"
    assert "Apache-Coyote/1.1" in profile.detected_tech


def test_build_target_profile_detects_php_from_wordpress_signature():
    report = _report([{"url": "https://x/", "tech": ["WordPress"]}])
    profile = build_target_profile(report)
    assert profile.stack_family == "php"


def test_build_target_profile_detects_dotnet_from_header():
    report = _report([{"url": "https://x/default.aspx", "tech": ["ASP.NET"]}])
    profile = build_target_profile(report)
    assert profile.stack_family == "dotnet"


def test_build_target_profile_low_confidence_on_single_weak_signal():
    """Only a URL extension, no corroborating header/cookie -- still
    classifies (never a false 'unknown' that would over-narrow), but
    at low confidence."""
    report = _report([{"url": "https://x/legacy.php", "tech": []}])
    profile = build_target_profile(report)
    assert profile.stack_family == "php"
    assert profile.confidence == "low"


def test_build_target_profile_stays_unknown_on_ambiguous_tie():
    """One PHP signal and one Java signal, both single-vote -- a real
    tie should never be silently resolved by guessing; this is the
    guard against a wrong classification narrowing real coverage."""
    report = _report([
        {"url": "https://x/a.php", "tech": []},
        {"url": "https://x/b.jsp", "tech": []},
    ])
    profile = build_target_profile(report)
    assert profile.stack_family == "unknown"
    assert "url-extension:.php" in profile.detected_tech
    assert "url-extension:.jsp" in profile.detected_tech


def test_target_profile_default_construction():
    profile = TargetProfile()
    assert profile.stack_family == "unknown"
    assert profile.detected_tech == []
    assert profile.confidence == "none"
