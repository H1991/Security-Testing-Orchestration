"""Unit tests for Layer 13 — stof.reporting.html_report."""
import base64
from datetime import datetime, timezone

from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding
from stof.reporting.html_report import _evidence_images, _split_by_priority, _summarize_recon, write


def _finding(**overrides) -> Finding:
    endpoint = Endpoint(url="https://x/bank/showAccount", method="GET", endpoint_type="api", parameters=["listAccounts"])
    defaults = dict(
        module_id="idor_tests", vuln_type="Insecure Direct Object Reference (IDOR)", severity="High",
        cvss_score=8.1, endpoint=endpoint, user_role="admin", request_raw="GET x", response_raw="HTTP 200",
        description="A single session accessed multiple accounts.", recommendation="Enforce ownership checks.",
        discovered_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# _evidence_images
# ---------------------------------------------------------------------------


def test_evidence_images_encodes_real_png(tmp_path):
    png_path = tmp_path / "shot.png"
    png_path.write_bytes(b"\x89PNG\r\n\x1a\nfakepngbytes")

    images = _evidence_images([str(png_path), str(tmp_path / "cookies.json")])

    assert len(images) == 1
    assert images[0]["data_uri"].startswith("data:image/png;base64,")
    decoded = base64.b64decode(images[0]["data_uri"].split(",", 1)[1])
    assert decoded == png_path.read_bytes()


def test_evidence_images_labels_known_filenames(tmp_path):
    screenshot = tmp_path / "screenshot.png"
    screenshot.write_bytes(b"\x89PNG\r\n\x1a\nfakepngbytes")
    req_resp = tmp_path / "request_response.png"
    req_resp.write_bytes(b"\x89PNG\r\n\x1a\nfakepngbytes")

    images = _evidence_images([str(screenshot), str(req_resp)])

    labels = {img["label"] for img in images}
    assert labels == {"Browser Screenshot", "Request / Response"}


def test_evidence_images_empty_when_no_png_present():
    assert _evidence_images(["data/evidence/cookies.json"]) == []


def test_evidence_images_empty_when_file_missing(tmp_path):
    assert _evidence_images([str(tmp_path / "missing.png")]) == []


# ---------------------------------------------------------------------------
# write — happy path
# ---------------------------------------------------------------------------


def test_write_produces_html_containing_finding_details(tmp_path):
    findings = [_finding()]
    path = write(findings, {"scan_id": "abc123", "target": "https://x"}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "Insecure Direct Object Reference (IDOR)" in html
    assert "https://x/bank/showAccount" in html
    assert "Enforce ownership checks." in html
    assert "abc123" in html


def test_write_embeds_screenshot_as_base64_when_available(tmp_path):
    png_path = tmp_path / "shot.png"
    png_path.write_bytes(b"\x89PNG\r\n\x1a\nfakepngbytes")
    findings = [_finding(evidence_refs=[str(png_path)])]

    path = write(findings, {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "data:image/png;base64," in html


def test_write_labels_cvss_score_as_illustrative_not_a_real_cvss(tmp_path):
    """Same fix as excel_report.py's Severity Score column, applied to
    the HTML badge -- the report must never present the numeric score
    as an unqualified "CVSS" label a client could mistake for something
    with no independently-verifiable backing."""
    findings = [_finding()]
    path = write(findings, {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "CVSS 8.1" not in html  # the old, unqualified label
    assert "Severity Score 8.1" in html


def test_write_shows_a_real_cvss_vector_when_one_reproduces_the_score(tmp_path):
    """cvss_score is now backed by a real, independently-recomputable
    CVSS v3.1 vector whenever one exists for that exact score (see
    stof.findings.cvss) -- the report shows it, not a disclaimer that
    none was ever computed."""
    finding = _finding(vuln_type="Insecure Direct Object Reference (IDOR)", cvss_score=8.1)
    finding.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H"

    path = write([finding], {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H" in html


def test_write_is_honest_when_no_vector_reproduces_the_score(tmp_path):
    finding = _finding()
    finding.cvss_vector = None

    path = write([finding], {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "not available for this exact score" in html


def test_write_with_no_findings_shows_empty_state(tmp_path):
    path = write([], {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "No Critical or High severity findings" in html
    assert "No additional findings" in html


def test_write_escapes_html_in_finding_fields(tmp_path):
    findings = [_finding(description="<script>alert(1)</script>")]
    path = write(findings, {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# _summarize_recon
# ---------------------------------------------------------------------------


def _recon_report(**overrides) -> dict:
    defaults = dict(
        target="https://x", scanned_at="2026-01-01T00:00:00+00:00", pages_analyzed=3,
        tech_stack=[{"url": "https://x/", "tech": ["Apache Tomcat", "Java"]}, {"url": "https://x/2", "tech": ["Java"]}],
        missing_security_headers={"https://x/": ["content-security-policy"]},
        exposed_paths=[{"url": "https://x/.git/config", "status_code": 200}],
        error_disclosures=[],
        secrets=[],
        parameters={"GET https://x/a": [{"name": "id", "guessed_type": "id"}]},
    )
    defaults.update(overrides)
    return defaults


def test_summarize_recon_none_when_no_report():
    assert _summarize_recon(None) is None


def test_summarize_recon_dedupes_tech_across_pages():
    summary = _summarize_recon(_recon_report())

    assert summary["distinct_tech"] == ["Apache Tomcat", "Java"]
    assert summary["missing_headers_count"] == 1
    assert summary["parameters_count"] == 1


# ---------------------------------------------------------------------------
# write — recon + module_notes sections
# ---------------------------------------------------------------------------


def test_write_includes_recon_section_when_supplied(tmp_path):
    path = write([], {}, tmp_path / "report.html", recon_report=_recon_report())

    html = path.read_text(encoding="utf-8")
    assert "Reconnaissance" in html
    assert "Apache Tomcat" in html
    assert ".git/config" in html


def test_write_omits_recon_section_when_not_supplied(tmp_path):
    path = write([], {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "Reconnaissance" not in html


def test_write_includes_module_notes(tmp_path):
    metadata = {"module_notes": [
        {"module": "idor_tests", "finding_count": 2, "note": None},
        {"module": "jwt_tests", "finding_count": 0, "note": "Not applicable -- session-cookie based authentication."},
    ]}

    path = write([], metadata, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "idor_tests" in html
    assert "Not applicable -- session-cookie based authentication." in html


# ---------------------------------------------------------------------------
# _split_by_priority / the report's Critical-High-first structure
# ---------------------------------------------------------------------------


def test_split_by_priority_separates_critical_high_from_the_rest():
    findings = [
        _finding(severity="Medium", cvss_score=5.3).to_dict(),
        _finding(severity="Critical", cvss_score=9.5).to_dict(),
        _finding(severity="Low", cvss_score=2.6).to_dict(),
        _finding(severity="High", cvss_score=8.1).to_dict(),
    ]

    priority, other = _split_by_priority(findings)

    assert [f["severity"] for f in priority] == ["Critical", "High"]
    assert [f["severity"] for f in other] == ["Medium", "Low"]


def test_split_by_priority_orders_critical_before_high():
    findings = [
        _finding(severity="High", cvss_score=7.5, finding_id="a").to_dict(),
        _finding(severity="Critical", cvss_score=9.5, finding_id="b").to_dict(),
    ]

    priority, _other = _split_by_priority(findings)

    assert [f["finding_id"] for f in priority] == ["b", "a"]


def test_write_leads_with_the_critical_high_section(tmp_path):
    findings = [_finding(severity="Medium", cvss_score=5.3), _finding(severity="Critical", cvss_score=9.5)]

    path = write(findings, {}, tmp_path / "report.html")
    html = path.read_text(encoding="utf-8")

    priority_idx = html.index("Requires Action")
    additional_idx = html.index("Additional Findings")
    assert priority_idx < additional_idx


def test_write_shows_confirmation_badge_only_for_likely_findings(tmp_path):
    findings = [
        _finding(confidence="likely", vuln_type="Timing-Based SSRF Signal"),
        _finding(confidence="confirmed", vuln_type="Confirmed BFLA"),
    ]

    path = write(findings, {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert html.count("Needs Manual Confirmation") == 1


def test_write_shows_clean_state_when_no_priority_findings(tmp_path):
    findings = [_finding(severity="Low", cvss_score=2.6)]

    path = write(findings, {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "No Critical or High severity findings" in html


def test_write_shows_tentative_badge_for_tentative_confidence_findings(tmp_path):
    findings = [_finding(confidence="tentative", vuln_type="Bare Fingerprint Signal")]

    path = write(findings, {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "Low-Confidence Signal" in html


def test_write_includes_skipped_techniques_section(tmp_path):
    metadata = {"skipped_techniques": [
        {"technique_id": "TC-128.4", "technique": "Stored Cross-Site Scripting", "module_id": "xss_tests", "reason": "allow_state_changing_probes is disabled"},
    ]}

    path = write([], metadata, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "Techniques Not Run" in html
    assert "TC-128.4" in html
    assert "allow_state_changing_probes is disabled" in html


def test_write_omits_skipped_techniques_section_when_none_skipped(tmp_path):
    path = write([], {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "Techniques Not Run" not in html
