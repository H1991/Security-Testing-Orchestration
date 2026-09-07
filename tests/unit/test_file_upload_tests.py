"""Unit tests for Layer 9 -- stof.modules.file_upload_tests (TC-099/TC-100)."""
from unittest.mock import AsyncMock

import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.file_upload_tests import (
    FileUploadTestConfig,
    FileUploadTestsModule,
    _find_file_upload_endpoint,
    _looks_accepted,
)
from stof.modules.results import FAIL, PASS, SKIPPED

# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------


def _upload_endpoint(**kwargs):
    defaults = dict(
        url="https://x/upload", method="POST", endpoint_type="form",
        parameters=["avatar", "description"],
        param_locations={"avatar": "file", "description": "body"},
    )
    defaults.update(kwargs)
    return Endpoint(**defaults)


def test_find_file_upload_endpoint_matches_file_location():
    endpoints = [
        Endpoint(url="https://x/login", method="POST", endpoint_type="form", parameters=["username"], param_locations={"username": "body"}),
        _upload_endpoint(),
    ]
    found = _find_file_upload_endpoint(endpoints)
    assert found is not None
    endpoint, file_param = found
    assert endpoint.url == "https://x/upload"
    assert file_param == "avatar"


def test_find_file_upload_endpoint_none_when_no_file_input():
    endpoints = [Endpoint(url="https://x/login", method="POST", endpoint_type="form", parameters=["username"], param_locations={"username": "body"})]
    assert _find_file_upload_endpoint(endpoints) is None


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (200, "Upload successful", True),
        (200, "", True),
        (400, "Upload successful", False),  # error status always rejected
        (200, "This file type is not allowed", False),
        (200, "Invalid extension for uploads", False),
    ],
)
def test_looks_accepted_pure_helper(status, body, expected):
    assert _looks_accepted(status, body) == expected


# ---------------------------------------------------------------------------
# run_techniques() / individual techniques -- async
# ---------------------------------------------------------------------------


def _response(status: int, body: str):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    return resp


def _fake_context(post_side_effect=None):
    context = AsyncMock()
    if post_side_effect is not None:
        context.request.post = AsyncMock(side_effect=post_side_effect)
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


def _by_id(results):
    return {r.technique_id: r for r in results}


@pytest.mark.asyncio
async def test_run_techniques_skipped_when_no_file_upload_endpoint():
    module = FileUploadTestsModule(config=FileUploadTestConfig(allow_state_changing_probes=True))
    pool = _pool_with_context(_fake_context())

    results = await module.run_techniques([], None, pool)

    by_id = _by_id(results)
    assert len(by_id) == 2
    assert all(r.status == SKIPPED for r in by_id.values())


@pytest.mark.asyncio
async def test_run_techniques_gated_skip_when_probes_disabled():
    endpoints = [_upload_endpoint()]
    module = FileUploadTestsModule()  # allow_state_changing_probes defaults False
    pool = _pool_with_context(_fake_context())

    results = await module.run_techniques(endpoints, None, pool)

    by_id = _by_id(results)
    assert all(r.status == SKIPPED for r in by_id.values())
    assert "allow_state_changing_probes" in by_id["TC-099.1"].detail


@pytest.mark.asyncio
async def test_dangerous_extension_fails_when_upload_accepted():
    endpoints = [_upload_endpoint()]

    def fake_post(url, multipart=None, max_redirects=0):
        return _response(200, "Upload successful")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = FileUploadTestsModule(config=FileUploadTestConfig(allow_state_changing_probes=True))

    result = await module._technique_dangerous_extension(endpoints, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "High"
    assert result.finding.vuln_type == "File Upload -- Dangerous Extension Accepted"
    # Regression: the finding's own description says STOF "did not
    # attempt to retrieve or execute the uploaded file to confirm
    # actual code execution -- this needs manual verification".
    assert result.finding.confidence == "likely"


@pytest.mark.asyncio
async def test_dangerous_extension_passes_when_every_payload_rejected():
    endpoints = [_upload_endpoint()]

    def fake_post(url, multipart=None, max_redirects=0):
        return _response(415, "Unsupported file type")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = FileUploadTestsModule(config=FileUploadTestConfig(allow_state_changing_probes=True))

    result = await module._technique_dangerous_extension(endpoints, pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_dangerous_extension_tries_next_payload_when_one_probe_errors():
    endpoints = [_upload_endpoint()]
    call_count = {"n": 0}

    def fake_post(url, multipart=None, max_redirects=0):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ConnectionError("transient network error")
        return _response(415, "Unsupported file type")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = FileUploadTestsModule(config=FileUploadTestConfig(allow_state_changing_probes=True))

    result = await module._technique_dangerous_extension(endpoints, pool, evidence=None)

    assert result.status == PASS
    assert call_count["n"] > 1


@pytest.mark.asyncio
async def test_double_extension_fails_when_upload_accepted():
    endpoints = [_upload_endpoint()]

    def fake_post(url, multipart=None, max_redirects=0):
        return _response(200, "Upload successful")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = FileUploadTestsModule(config=FileUploadTestConfig(allow_state_changing_probes=True))

    result = await module._technique_double_extension(endpoints, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding.vuln_type == "File Upload -- Double Extension Bypass Accepted"


@pytest.mark.asyncio
async def test_upload_multipart_places_file_under_the_discovered_file_param():
    endpoints = [_upload_endpoint()]
    captured = {}

    def fake_post(url, multipart=None, max_redirects=0):
        captured.update(multipart or {})
        return _response(415, "Unsupported file type")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = FileUploadTestsModule(config=FileUploadTestConfig(allow_state_changing_probes=True))

    await module._technique_dangerous_extension(endpoints, pool, evidence=None)

    assert "avatar" in captured
    assert isinstance(captured["avatar"], dict)
    assert captured["avatar"]["name"].startswith("stof-probe")
    assert "description" in captured  # non-file field also sent
