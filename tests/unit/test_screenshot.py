"""Unit tests for Layer 3B — stof.engine.screenshot."""
from unittest.mock import AsyncMock

import pytest

from stof.engine.screenshot import capture

# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capture_writes_under_output_dir_and_returns_path(tmp_path):
    page = AsyncMock()

    path = await capture(page, output_dir=tmp_path, label="AUTH-001")

    assert path.parent == tmp_path
    assert path.name.startswith("AUTH-001_")
    assert path.suffix == ".png"
    page.screenshot.assert_awaited_once()
    kwargs = page.screenshot.await_args.kwargs
    assert kwargs["path"] == str(path)
    assert kwargs["full_page"] is True


@pytest.mark.asyncio
async def test_capture_creates_missing_output_dir(tmp_path):
    page = AsyncMock()
    nested = tmp_path / "scan-1" / "AUTH-007"

    path = await capture(page, output_dir=nested, label="finding")

    assert nested.is_dir()
    assert path.parent == nested


# ---------------------------------------------------------------------------
# Input validation — label sanitisation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capture_sanitises_unsafe_characters_in_label(tmp_path):
    page = AsyncMock()

    path = await capture(page, output_dir=tmp_path, label="AUTH-001: Session/Fixation!!")

    assert "/" not in path.name
    assert ":" not in path.name
    assert path.name.startswith("AUTH-001_Session_Fixation")


@pytest.mark.asyncio
async def test_capture_falls_back_to_default_name_for_empty_label(tmp_path):
    page = AsyncMock()

    path = await capture(page, output_dir=tmp_path, label="!!!")

    assert path.name.startswith("screenshot_")
