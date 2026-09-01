"""Unit tests for Recon Engine — stof.recon.secrets_scanner."""
from unittest.mock import AsyncMock

import pytest

from stof.recon.secrets_scanner import find_secrets, scan_page_for_secrets

# ---------------------------------------------------------------------------
# find_secrets — pure regex scan
# ---------------------------------------------------------------------------


def test_find_secrets_detects_jwt():
    text = "const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';"
    findings = find_secrets(text, "https://x/app.js")
    assert any(f.label == "JWT" for f in findings)


def test_find_secrets_detects_aws_key():
    text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    findings = find_secrets(text, "https://x/config.js")
    assert any(f.label == "AWS Access Key" for f in findings)


def test_find_secrets_detects_generic_api_key_assignment():
    text = 'const apiKey = "sk_live_51H8x9zK2eZvKYlo2C000000";'
    findings = find_secrets(text, "https://x/app.js")
    assert any(f.label == "Generic API Key Assignment" for f in findings)


def test_find_secrets_detects_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."
    findings = find_secrets(text, "https://x/id_rsa.txt")
    assert any(f.label == "Private Key Block" for f in findings)


def test_find_secrets_detects_internal_path_hint():
    text = "fetch('/internal/admin-api/users')"
    findings = find_secrets(text, "https://x/app.js")
    assert any(f.label == "Internal/Debug Path Hint" for f in findings)


def test_find_secrets_clean_text_finds_nothing():
    assert find_secrets("function greet() { return 'hello world'; }", "https://x/app.js") == []


def test_find_secrets_never_leaks_the_full_match():
    text = "AKIAIOSFODNN7EXAMPLE"
    findings = find_secrets(text, "https://x/app.js")
    assert findings[0].match_preview != text
    assert "..." in findings[0].match_preview


def test_find_secrets_sets_source_url_on_every_finding():
    findings = find_secrets("AKIAIOSFODNN7EXAMPLE", "https://x/vendor.js")
    assert all(f.source_url == "https://x/vendor.js" for f in findings)


# ---------------------------------------------------------------------------
# scan_page_for_secrets — Playwright wiring
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_page_for_secrets_scans_inline_scripts_and_comments():
    page = AsyncMock()
    page.url = "https://x/app"
    page.evaluate = AsyncMock(
        return_value={
            "inline": ["const key = 'AKIAIOSFODNN7EXAMPLE';"],
            "external": [],
            "comments": [" TODO: remove debug token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.4pcPyMD09olPSyXnrXCjTwXyr4BsezdI1AVTmud2fU4 "],
        }
    )

    findings = await scan_page_for_secrets(page)

    labels = {f.label for f in findings}
    assert "AWS Access Key" in labels
    assert "JWT" in labels


@pytest.mark.asyncio
async def test_scan_page_for_secrets_fetches_external_scripts():
    page = AsyncMock()
    page.url = "https://x/app"
    page.evaluate = AsyncMock(return_value={"inline": [], "external": ["/static/vendor.js"], "comments": []})
    response = AsyncMock()
    response.text = AsyncMock(return_value="aws_key = AKIAIOSFODNN7EXAMPLE")
    page.context.request.get = AsyncMock(return_value=response)

    findings = await scan_page_for_secrets(page)

    page.context.request.get.assert_awaited_once_with("https://x/static/vendor.js", timeout=8000)
    assert any(f.source_url == "https://x/static/vendor.js" for f in findings)


@pytest.mark.asyncio
async def test_scan_page_for_secrets_continues_past_a_failed_script_fetch():
    page = AsyncMock()
    page.url = "https://x/app"
    page.evaluate = AsyncMock(return_value={"inline": [], "external": ["/broken.js"], "comments": []})
    page.context.request.get = AsyncMock(side_effect=RuntimeError("network error"))

    findings = await scan_page_for_secrets(page)  # must not raise

    assert findings == []
