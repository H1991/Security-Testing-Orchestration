"""Unit tests for Layer 13 — stof.reporting.html_report."""
import base64
from datetime import datetime, timezone

from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding
from stof.reporting.html_report import _evidence_images, _summarize_recon, write


def _finding(**overrides) -> Finding:
    endpoint = Endpoint(url="https://x/bank/showAccount", method="GET", endpoint_type="api", parameters=["listAccounts"])
    defaults = dict(
        module_id="idor_tests", vuln_type="Insecure Direct Object Reference (IDOR)", severity="Critical",
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
    the HTML badge -- every cvss_score value is a hardcoded illustrative
    constant (never computed from a real CVSS vector), so the report
    must never present it as an unqualified "CVSS" score a client could
    mistake for a calculated one."""
    findings = [_finding()]
    path = write(findings, {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "CVSS 8.1" not in html  # the old, unqualified label
    assert "Severity Score 8.1" in html
    assert "not a calculated CVSS vector" in html


def test_write_with_no_findings_shows_empty_state(tmp_path):
    path = write([], {}, tmp_path / "report.html")

    html = path.read_text(encoding="utf-8")
    assert "No findings were confirmed" in html


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
