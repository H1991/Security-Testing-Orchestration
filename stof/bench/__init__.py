"""Precision/recall benchmarking against known-vulnerable/known-clean
targets. See `score.py` for the real gap this closes.
"""
from .score import BenchmarkScore, FalsePositiveScore, score_false_positives, score_recall

__all__ = ["BenchmarkScore", "FalsePositiveScore", "score_false_positives", "score_recall"]
