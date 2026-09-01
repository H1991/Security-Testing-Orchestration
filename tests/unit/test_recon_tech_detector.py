"""Unit tests for Recon Engine — stof.recon.tech_detector."""
from stof.recon.tech_detector import detect_tech, extract_title

# ---------------------------------------------------------------------------
# extract_title
# ---------------------------------------------------------------------------


def test_extract_title_finds_title_tag():
    assert extract_title("<html><head><title>Altoro Mutual</title></head></html>") == "Altoro Mutual"


def test_extract_title_collapses_whitespace():
    assert extract_title("<title>\n  Altoro   Mutual  \n</title>") == "Altoro Mutual"


def test_extract_title_returns_none_when_absent():
    assert extract_title("<html><body>no title here</body></html>") is None


# ---------------------------------------------------------------------------
# detect_tech — header-based
# ---------------------------------------------------------------------------


def test_detect_tech_from_server_header():
    tech = detect_tech({"server": "Apache/2.4.41"}, [], "")
    assert "Apache/2.4.41" in tech


def test_detect_tech_from_powered_by_header():
    tech = detect_tech({"x-powered-by": "Express"}, [], "")
    assert "Express" in tech


# ---------------------------------------------------------------------------
# detect_tech — cookie-based
# ---------------------------------------------------------------------------


def test_detect_tech_from_jsessionid_cookie():
    tech = detect_tech({}, ["JSESSIONID"], "")
    assert "Java (JSP/Servlet)" in tech


def test_detect_tech_from_laravel_cookie():
    tech = detect_tech({}, ["laravel_session"], "")
    assert "Laravel" in tech


# ---------------------------------------------------------------------------
# detect_tech — body-based
# ---------------------------------------------------------------------------


def test_detect_tech_from_react_body_signature():
    tech = detect_tech({}, [], '<div id="root" data-reactroot=""></div>')
    assert "React" in tech


def test_detect_tech_from_nextjs_signature():
    tech = detect_tech({}, [], '<script id="__NEXT_DATA__">{}</script>')
    assert "Next.js" in tech


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_detect_tech_returns_empty_list_for_no_signals():
    assert detect_tech({}, [], "<html><body>plain</body></html>") == []


def test_detect_tech_deduplicates_repeated_cookie_signatures():
    tech = detect_tech({"server": "nginx"}, ["JSESSIONID", "jsessionid_backup"], "")
    assert tech == ["Java (JSP/Servlet)", "nginx"]
