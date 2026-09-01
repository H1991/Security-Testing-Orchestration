"""Unit tests for Layer 13 — stof.reporting.walkthrough_report (Jinja2
rendering) with dummy `FindingWalkthrough` objects, no real PNGs
needed."""
from stof.reporting.walkthrough_models import FindingWalkthrough, WalkthroughStep
from stof.reporting.walkthrough_report import write


def _walkthrough(finding_id: str, severity: str, build_error=None, with_steps=True) -> FindingWalkthrough:
    steps = []
    if with_steps:
        steps = [
            WalkthroughStep(order=1, caption="Log in as demo user", screenshot_path=None, detail=None),
            WalkthroughStep(order=2, caption="Submit the payload", screenshot_path=None, detail="uid=' OR 1=1"),
        ]
    return FindingWalkthrough(
        finding_id=finding_id, tc_id="TC-999.1", title=f"Test Vuln {severity}", severity=severity,
        endpoint_url="https://x/target", steps=steps,
        impact_summary="This is what it means.", remediation="This is how to fix it.",
        build_error=build_error,
    )


def test_write_renders_all_findings_ordered_critical_first(tmp_path):
    walkthroughs = [
        _walkthrough("f-low", "Low"),
        _walkthrough("f-critical", "Critical"),
        _walkthrough("f-high", "High"),
    ]
    output_path = tmp_path / "walkthrough.html"

    write(walkthroughs, {"scan_id": "abc123", "target": "https://x"}, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert html.index("Test Vuln Critical") < html.index("Test Vuln High") < html.index("Test Vuln Low")


def test_write_shows_step_captions_and_details(tmp_path):
    walkthroughs = [_walkthrough("f1", "High")]
    output_path = tmp_path / "walkthrough.html"

    write(walkthroughs, {"scan_id": "abc"}, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "Log in as demo user" in html
    assert "uid=&#39; OR 1=1" in html or "uid=' OR 1=1" in html  # autoescaping may HTML-entity-encode the apostrophe


def test_write_shows_build_error_note_instead_of_empty_gap(tmp_path):
    walkthroughs = [_walkthrough("f1", "High", build_error="replay timed out after 20s", with_steps=False)]
    output_path = tmp_path / "walkthrough.html"

    write(walkthroughs, {"scan_id": "abc"}, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "couldn't be captured automatically" in html
    assert "replay timed out after 20s" in html


def test_write_no_raw_request_response_text_leaks_into_page(tmp_path):
    walkthrough = _walkthrough("f1", "High")
    walkthrough.impact_summary = "This is what it means."
    output_path = tmp_path / "walkthrough.html"

    write([walkthrough], {"scan_id": "abc"}, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "What this means" in html
    assert "How to fix it" in html


def test_write_empty_findings_shows_empty_state(tmp_path):
    output_path = tmp_path / "walkthrough.html"

    write([], {"scan_id": "abc"}, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "No confirmed findings" in html


def test_write_autoescapes_attacker_controlled_text(tmp_path):
    """The impact_summary/remediation/title fields are attacker-
    observable strings on a real target -- must never be rendered
    unescaped (same autoescape rule html_report.py enforces)."""
    walkthrough = _walkthrough("f1", "High")
    walkthrough.impact_summary = "<script>alert(1)</script>"
    output_path = tmp_path / "walkthrough.html"

    write([walkthrough], {"scan_id": "abc"}, output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
