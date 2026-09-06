"""Unit tests for Recon Engine — stof.recon.secrets_scanner."""
from unittest.mock import AsyncMock

import pytest

from stof.recon.secrets_scanner import find_routes, find_secrets, scan_page_for_secrets_and_routes

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


def test_find_secrets_does_not_flag_i18n_translation_strings_as_secrets():
    """Regression: scanning a real i18n-heavy JS bundle produced 34
    "Generic Secret Assignment" false positives, every one a
    translation-dictionary entry like `password: "パスワードを変更する"`
    (Japanese for "change password") or `password: "รหัสผ่าน"` (Thai
    for "password") -- the old character class (`[^'"\\s]{8,}`) only
    excludes ASCII whitespace, and CJK/Thai text has no ASCII spaces to
    exclude it in the first place."""
    assert find_secrets('password: "パスワードを変更する"', "x") == []
    assert find_secrets('password: "รหัสผ่าน"', "x") == []
    assert find_secrets('token: "アクセストークンがありません"', "x") == []
    # No ASCII whitespace at all -- exercises the actual regression
    # (a single accented word), not the space-exclusion the old
    # pattern already handled correctly.
    assert find_secrets('password: "contraseña"', "x") == []


def test_find_secrets_does_not_flag_ascii_language_translations_of_the_word_password():
    """Same false-positive class as the test above, one layer deeper:
    the character-class fix alone still matched "password" translated
    into ASCII-representable languages -- German "Passwort", Dutch
    "Wachtwoord", Finnish "Salasana", Danish "Adgangskode" -- since
    none of those contain non-ASCII characters either. The actual
    discriminator is that no human-language dictionary word contains a
    digit, while a real generated secret/token/API key virtually
    always does."""
    for word in ("Password", "Passwort", "Wachtwoord", "Salasana", "Adgangskode"):
        assert find_secrets(f'password:"{word}"', "x") == [], word


def test_find_secrets_never_leaks_the_full_match():
    text = "AKIAIOSFODNN7EXAMPLE"
    findings = find_secrets(text, "https://x/app.js")
    assert findings[0].match_preview != text
    assert "..." in findings[0].match_preview


def test_find_secrets_sets_source_url_on_every_finding():
    findings = find_secrets("AKIAIOSFODNN7EXAMPLE", "https://x/vendor.js")
    assert all(f.source_url == "https://x/vendor.js" for f in findings)


# ---------------------------------------------------------------------------
# find_routes — pure regex scan
# ---------------------------------------------------------------------------


def test_find_routes_detects_a_router_config_path_string():
    text = '{ path: "/kauthor/categories", component: CategoryList }'
    assert find_routes(text) == ["/kauthor/categories"]


def test_find_routes_detects_single_and_double_quoted_paths():
    text = "path: '/admin/users', path: \"/admin/roles\""
    assert find_routes(text) == ["/admin/users", "/admin/roles"]


def test_find_routes_deduplicates_repeated_paths():
    text = 'path:"/x/y" ... path:"/x/y"'
    assert find_routes(text) == ["/x/y"]


def test_find_routes_skips_static_asset_extensions():
    text = 'path:"/assets/logo.png"'
    assert find_routes(text) == []


def test_find_routes_skips_bare_root():
    text = 'path:"/"'
    assert find_routes(text) == []


def test_find_routes_clean_text_finds_nothing():
    assert find_routes("function greet() { return 'hello world'; }") == []


# ---------------------------------------------------------------------------
# scan_page_for_secrets_and_routes — Playwright wiring
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_page_for_secrets_and_routes_scans_inline_scripts_and_comments():
    page = AsyncMock()
    page.url = "https://x/app"
    page.evaluate = AsyncMock(
        return_value={
            "inline": ["const key = 'AKIAIOSFODNN7EXAMPLE';"],
            "external": [],
            "comments": [" TODO: remove debug token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.4pcPyMD09olPSyXnrXCjTwXyr4BsezdI1AVTmud2fU4 "],
        }
    )

    findings, routes = await scan_page_for_secrets_and_routes(page)

    labels = {f.label for f in findings}
    assert "AWS Access Key" in labels
    assert "JWT" in labels
    assert routes == []


@pytest.mark.asyncio
async def test_scan_page_for_secrets_and_routes_fetches_external_scripts():
    page = AsyncMock()
    page.url = "https://x/app"
    page.evaluate = AsyncMock(return_value={"inline": [], "external": ["/static/vendor.js"], "comments": []})
    response = AsyncMock()
    response.text = AsyncMock(return_value="aws_key = AKIAIOSFODNN7EXAMPLE")
    page.context.request.get = AsyncMock(return_value=response)

    findings, routes = await scan_page_for_secrets_and_routes(page)

    page.context.request.get.assert_awaited_once_with("https://x/static/vendor.js", timeout=20000)
    assert any(f.source_url == "https://x/static/vendor.js" for f in findings)
    assert routes == []


@pytest.mark.asyncio
async def test_scan_page_for_secrets_and_routes_finds_routes_in_an_external_bundle():
    page = AsyncMock()
    page.url = "https://x/app"
    page.evaluate = AsyncMock(return_value={"inline": [], "external": ["/static/router.js"], "comments": []})
    response = AsyncMock()
    response.text = AsyncMock(return_value='{path:"/kauthor/workflow-management"}')
    page.context.request.get = AsyncMock(return_value=response)

    findings, routes = await scan_page_for_secrets_and_routes(page)

    assert routes == ["/kauthor/workflow-management"]
    assert findings == []


@pytest.mark.asyncio
async def test_scan_page_for_secrets_and_routes_continues_past_a_failed_script_fetch():
    page = AsyncMock()
    page.url = "https://x/app"
    page.evaluate = AsyncMock(return_value={"inline": [], "external": ["/broken.js"], "comments": []})
    page.context.request.get = AsyncMock(side_effect=RuntimeError("network error"))

    findings, routes = await scan_page_for_secrets_and_routes(page)  # must not raise

    assert findings == []
    assert routes == []
