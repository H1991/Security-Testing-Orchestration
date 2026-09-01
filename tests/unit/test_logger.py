"""Unit tests for Layer 2 — stof.core.logger."""
import io
import logging

from stof.core.logger import configure_logging, get_logger


def _fresh_root():
    """Reset the shared `stof` logger between tests so handler
    installation/format assertions don't leak across test cases."""
    import stof.core.logger as logger_module

    root = logging.getLogger("stof")
    root.handlers.clear()
    logger_module._configured = False
    return root


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_configure_logging_formats_with_layer_tag():
    _fresh_root()
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
    _fresh_root()
    buffer = io.StringIO()
    configure_logging(level=logging.INFO, stream=buffer)
    configure_logging(level=logging.INFO, stream=buffer)

    root = logging.getLogger("stof")
    assert len(root.handlers) == 1


# ---------------------------------------------------------------------------
# Input validation — unknown layer prefix falls back to the default tag
# ---------------------------------------------------------------------------


def test_unrecognised_logger_prefix_falls_back_to_stof_tag():
    _fresh_root()
    buffer = io.StringIO()
    configure_logging(level=logging.INFO, stream=buffer)

    log = get_logger("some_future_layer_nobody_registered")
    log.info("hello")

    assert "[STOF] hello" in buffer.getvalue()
