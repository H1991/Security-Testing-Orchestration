"""Unit tests for the Test Coverage page's data functions in
stof/ui/server.py (`_top_level_technique_counts`, `_test_catalog_entries`).

These run against the real repo state (real stof/modules/*.py files,
real config/testcases.json, real config/test_catalog_summaries.json) --
same as `_technique_counts`/`_module_testcases`, which this module's own
docstrings document as deliberately "ground truth from source" rather
than something that can be meaningfully mocked. The tests here protect
the one invariant that actually matters for a client-demo-facing page:
every top-level test case genuinely implemented in code is present,
accurately counted, and never silently falls back to un-curated text.
"""
from stof.ui.server import (
    _KNOWN_MODULES,
    _technique_counts,
    _test_catalog_entries,
    _top_level_technique_counts,
)


def test_top_level_technique_counts_sum_matches_per_module_ground_truth():
    """Two different aggregations of the exact same source-code scan
    (grouped by declared module vs. grouped by top-level TC-id) must
    total to the same number of real techniques -- a divergence here
    would mean one of the two counting paths is silently dropping or
    double-counting real coverage."""
    per_module_total = sum(_technique_counts().values())
    per_top_level_total = sum(_top_level_technique_counts().values())
    assert per_module_total == per_top_level_total


def test_top_level_technique_counts_are_all_positive():
    counts = _top_level_technique_counts()
    assert counts
    assert all(n >= 1 for n in counts.values())


def test_test_catalog_entries_covers_every_module_with_real_techniques():
    """Every module that _technique_counts() reports as having >0
    techniques must contribute at least one catalog entry -- a real
    module silently missing from the catalog would under-represent
    STOF's actual capability on the one page meant to showcase it."""
    per_module = _technique_counts()
    entries = _test_catalog_entries()
    modules_in_catalog = {e["module_id"] for e in entries}
    for mod_id in _KNOWN_MODULES:
        if mod_id == "crawler" or per_module.get(mod_id, 0) == 0:
            continue
        assert mod_id in modules_in_catalog, f"{mod_id} has real techniques but no catalog entry"


def test_test_catalog_entries_have_no_duplicate_ids():
    entries = _test_catalog_entries()
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids))


def test_test_catalog_entries_every_entry_has_a_curated_summary():
    """A summary that's identical to the raw technical_detail means no
    curated entry exists in test_catalog_summaries.json for that id --
    still functionally correct (the page falls back gracefully) but a
    real content gap on a page meant to read as client-safe prose, not
    engineering notes. Fails loudly here rather than silently shipping
    an uncurated card the next time a new top-level technique lands."""
    entries = _test_catalog_entries()
    uncurated = [e["id"] for e in entries if e["summary"] == e["technical_detail"]]
    assert not uncurated, f"missing curated summaries for: {uncurated}"


def test_test_catalog_entries_technique_count_matches_top_level_counts():
    counts = _top_level_technique_counts()
    entries = _test_catalog_entries()
    for entry in entries:
        assert entry["technique_count"] == counts[entry["id"]]


def test_test_catalog_entries_severity_is_a_known_value():
    entries = _test_catalog_entries()
    known = {"Critical", "High", "Medium", "Low", "Info"}
    for entry in entries:
        assert entry["severity"] in known, f"{entry['id']} has unexpected severity {entry['severity']!r}"
