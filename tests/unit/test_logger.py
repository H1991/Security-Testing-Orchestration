"""Unit tests for Layer 2 — stof.core.logger."""
import io
import logging

import pytest

import stof.core.logger as logger_module
from stof.core.logger import configure_logging, get_logger


@pytest.fixture(autouse=True)
def _isolated_stof_logger():
    """`configure_logging()` mutates process-global logging state (installs
    a handler on the shared `stof` root logger and sets `propagate = False`
    so its own handler doesn't double-print through Python's root logger).
    That's correct for a real process, but this file used to only reset
    state *before* each test (a plain `_fresh_root()` helper) -- so
    `propagate` stayed `False` after the *last* test here ran, for the rest
    of the pytest session. `caplog` relies on propagation to the root
    logger, so that leak silently broke it for every unrelated test
    elsewhere that checks a `stof.*` log message afterwards -- the real
    cause of a previously-flaky-looking failure in
    test_modules_registry.py's skip-warning assertion (passed alone,
    failed in the full suite, regardless of run order). Restoring here
    after every test, regardless of outcome, keeps this file's global-state
    pokes from leaking into the rest of the suite.
    """
    root = logging.getLogger("stof")
    original_handlers = list(root.handlers)
    original_propagate = root.propagate
    original_configured = logger_module._configured
    root.handlers.clear()
    logger_module._configured = False
    yield
    root.handlers.clear()
    root.handlers.extend(original_handlers)
    root.propagate = original_propagate
    logger_module._configured = original_configured


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_configure_logging_formats_with_layer_tag():
    buffer = io.StringIO()
    configure_logging(level=logging.INFO, stream=buffer)

    log = get_logger("auth.form_login")
    log.info("Authenticated as admin (form_login)")

    output = buffer.getvalue()
    assert "[AUTH] Authenticated as admin (form_login)" in output


def test_get_logger_namespaces_under_stof():
    log = get_logger("crawler")
    assert log.name == "stof.crawler"


# ---------------------------------------------------------------------------
# Failure / idempotency
# ---------------------------------------------------------------------------


def test_configure_logging_is_idempotent_and_does_not_duplicate_handlers():
    buffer = io.StringIO()
    configure_logging(level=logging.INFO, stream=buffer)
    configure_logging(level=logging.INFO, stream=buffer)

    root = logging.getLogger("stof")
    assert len(root.handlers) == 1


# ---------------------------------------------------------------------------
# Input validation — unknown layer prefix falls back to the default tag
# ---------------------------------------------------------------------------


def test_unrecognised_logger_prefix_falls_back_to_stof_tag():
    buffer = io.StringIO()
    configure_logging(level=logging.INFO, stream=buffer)

    log = get_logger("some_future_layer_nobody_registered")
    log.info("hello")

    assert "[STOF] hello" in buffer.getvalue()
