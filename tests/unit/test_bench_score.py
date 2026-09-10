"""Unit tests for stof.bench.score -- precision/recall benchmarking,
the "turn 154 techniques into a measured claim" feature every one of
four independent external reviews named as the highest-leverage
validation work."""
from stof.bench.score import score_false_positives, score_recall


def _finding(technique_id, endpoint_url, vuln_type="X"):
    return {"technique_id": technique_id, "vuln_type": vuln_type, "endpoint": {"url": endpoint_url}}


def _manifest(name, target, expected_findings):
    return {"name": name, "target": target, "expected_findings": expected_findings}


def _report(target, findings):
    return {"target": target, "findings": findings}


# ---------------------------------------------------------------------------
# score_recall
# ---------------------------------------------------------------------------


def test_exact_technique_id_and_endpoint_substring_match_counts_as_detected():
    manifest = _manifest("Juice Shop", "https://x", [
        {"technique_id": "TC-022.1", "endpoint_pattern": "/rest/user/login", "description": "default creds"},
    ])
    report = _report("https://x", [_finding("TC-022.1", "https://x/rest/user/login")])

    score = score_recall(report, manifest)

    assert score.expected_total == 1
    assert len(score.detected) == 1
    assert score.missed == []
    assert score.recall == 1.0


def test_top_level_family_expectation_matches_any_sub_technique():
    """A manifest can name just the top-level family ("TC-022") when
    it doesn't matter WHICH sub-technique catches it, only that the
    vulnerability class was found."""
    manifest = _manifest("m", "https://x", [{"technique_id": "TC-022", "endpoint_pattern": "/login", "description": "d"}])
    report = _report("https://x", [_finding("TC-022.3", "https://x/admin/login")])

    score = score_recall(report, manifest)

    assert len(score.detected) == 1


def test_wrong_technique_id_does_not_match_even_with_matching_endpoint():
    manifest = _manifest("m", "https://x", [{"technique_id": "TC-022.1", "endpoint_pattern": "/rest/user/login", "description": "d"}])
    report = _report("https://x", [_finding("TC-128.1", "https://x/rest/user/login")])

    score = score_recall(report, manifest)

    assert score.detected == []
    assert len(score.missed) == 1
    assert score.recall == 0.0


def test_wrong_endpoint_does_not_match_even_with_matching_technique():
    manifest = _manifest("m", "https://x", [{"technique_id": "TC-022.1", "endpoint_pattern": "/rest/user/login", "description": "d"}])
    report = _report("https://x", [_finding("TC-022.1", "https://x/rest/products")])

    score = score_recall(report, manifest)

    assert score.detected == []
    assert score.recall == 0.0


def test_partial_recall_across_multiple_expectations():
    manifest = _manifest("m", "https://x", [
        {"technique_id": "TC-022.1", "endpoint_pattern": "/rest/user/login", "description": "default creds"},
        {"technique_id": "TC-128.5", "endpoint_pattern": "/#/search", "description": "DOM XSS"},
        {"technique_id": "TC-127.1", "endpoint_pattern": "/rest/products/search", "description": "SQLi"},
    ])
    report = _report("https://x", [
        _finding("TC-022.1", "https://x/rest/user/login"),
        _finding("TC-128.5", "https://x/#/search"),
        # TC-127.1 never fires -- a genuine miss
    ])

    score = score_recall(report, manifest)

    assert score.expected_total == 3
    assert len(score.detected) == 2
    assert len(score.missed) == 1
    assert score.missed[0]["technique_id"] == "TC-127.1"
    assert score.recall == 2 / 3


def test_empty_manifest_yields_zero_recall_not_a_crash():
    score = score_recall(_report("https://x", []), _manifest("m", "https://x", []))
    assert score.expected_total == 0
    assert score.recall == 0.0


def test_to_dict_shape():
    manifest = _manifest("Juice Shop", "https://x", [{"technique_id": "TC-022.1", "endpoint_pattern": "/login", "description": "d"}])
    report = _report("https://x", [_finding("TC-022.1", "https://x/login")])

    data = score_recall(report, manifest).to_dict()

    assert data["manifest_name"] == "Juice Shop"
    assert data["expected_total"] == 1
    assert data["detected_count"] == 1
    assert data["missed_count"] == 0
    assert data["recall"] == 1.0


# ---------------------------------------------------------------------------
# score_false_positives
# ---------------------------------------------------------------------------


def test_every_finding_in_a_clean_target_report_is_a_false_positive():
    report = _report("https://clean-app.example", [
        _finding("TC-127.1", "https://clean-app.example/search", vuln_type="SQL Injection"),
        _finding("TC-128.1", "https://clean-app.example/comment", vuln_type="Reflected XSS"),
    ])

    score = score_false_positives(report)

    assert score.false_positive_count == 2
    assert {fp["technique_id"] for fp in score.false_positives} == {"TC-127.1", "TC-128.1"}


def test_no_findings_means_zero_false_positives():
    score = score_false_positives(_report("https://clean-app.example", []))
    assert score.false_positive_count == 0
    assert score.false_positives == []


def test_false_positive_to_dict_shape():
    report = _report("https://clean-app.example", [_finding("TC-127.1", "https://x/search")])
    data = score_false_positives(report).to_dict()

    assert data["target"] == "https://clean-app.example"
    assert data["false_positive_count"] == 1
    assert len(data["false_positives"]) == 1
