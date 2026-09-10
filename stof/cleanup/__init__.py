"""Cleanup/teardown tracking for state-changing techniques.

See `registry.py` for the real thing this closes: STOF's safety posture
has always claimed "gated, off by default, candidate-detect only" for
state-changing probes, but nothing tracked what those probes actually
created (accounts, planted stored-XSS/SQLi/CSV content, uploaded files)
or attempted to remove it afterward -- a real, previously-unaddressed
gap flagged by external review.
"""
from .registry import (
    NOT_ATTEMPTED,
    REVERT_FAILED,
    REVERTED,
    CleanupRegistry,
    configure,
    mark_cleanup_result,
    record_planted_state,
    summary_for_current_scan,
)

__all__ = [
    "NOT_ATTEMPTED",
    "REVERTED",
    "REVERT_FAILED",
    "CleanupRegistry",
    "configure",
    "mark_cleanup_result",
    "record_planted_state",
    "summary_for_current_scan",
]
