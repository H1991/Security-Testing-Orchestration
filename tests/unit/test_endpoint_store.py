"""Unit tests for Layer 7 — stof.crawler.endpoint_store."""
from datetime import datetime, timezone

from stof.crawler.endpoint_store import Endpoint, EndpointDB, dedupe, load, merge, write_endpoints


def _endpoint(**overrides) -> Endpoint:
    defaults = dict(url="https://x/api/users", method="GET", endpoint_type="api", parameters=["id"])
    defaults.update(overrides)
    return Endpoint(**defaults)


# ---------------------------------------------------------------------------
# Happy path — to_dict/from_dict, write/load round trip
# ---------------------------------------------------------------------------


def test_endpoint_round_trips_through_dict():
    endpoint = _endpoint(discovered_at=datetime(2026, 1, 1, tzinfo=timezone.utc))

    restored = Endpoint.from_dict(endpoint.to_dict())

    assert restored == endpoint


def test_write_and_load_round_trips(tmp_path):
    endpoints = [_endpoint(url="https://x/a"), _endpoint(url="https://x/b", method="POST")]
    path = write_endpoints(endpoints, path=tmp_path / "endpoints.json")

    loaded = load(path)

    assert len(loaded) == 2
    assert {e.url for e in loaded} == {"https://x/a", "https://x/b"}


def test_load_missing_file_returns_empty_list(tmp_path):
    assert load(tmp_path / "does_not_exist.json") == []


# ---------------------------------------------------------------------------
# dedupe()
# ---------------------------------------------------------------------------


def test_dedupe_merges_same_method_and_url_keeping_first_and_union_of_params():
    first = _endpoint(url="https://x/api/users", parameters=["id"])
    second = _endpoint(url="https://x/api/users", parameters=["name"])

    deduped = dedupe([first, second])

    assert len(deduped) == 1
    assert deduped[0] is first
    assert deduped[0].parameters == ["id", "name"]


def test_dedupe_keeps_distinct_method_url_pairs_separate():
    get_ep = _endpoint(url="https://x/api/users", method="GET")
    post_ep = _endpoint(url="https://x/api/users", method="POST")

    deduped = dedupe([get_ep, post_ep])

    assert len(deduped) == 2


# ---------------------------------------------------------------------------
# param_locations
# ---------------------------------------------------------------------------


def test_location_for_defaults_to_query_for_untagged_param():
    endpoint = _endpoint(parameters=["id"], param_locations={})

    assert endpoint.location_for("id") == "query"


def test_location_for_returns_explicit_tag():
    endpoint = _endpoint(parameters=["id"], param_locations={"id": "body"})

    assert endpoint.location_for("id") == "body"


def test_endpoint_round_trips_param_locations_through_dict():
    endpoint = _endpoint(
        parameters=["id", "csrf"],
        param_locations={"id": "body", "csrf": "header"},
        discovered_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    restored = Endpoint.from_dict(endpoint.to_dict())

    assert restored == endpoint
    assert restored.param_locations == {"id": "body", "csrf": "header"}


def test_endpoint_from_dict_defaults_param_locations_for_legacy_data():
    """A pre-Wave-1 endpoints.json entry has no "param_locations" key at
    all -- every param on it must still resolve to "query", not crash."""
    legacy = {
        "url": "https://x/api/users",
        "method": "GET",
        "endpoint_type": "api",
        "parameters": ["id"],
        "auth_required": False,
        "discovered_at": datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
    }

    endpoint = Endpoint.from_dict(legacy)

    assert endpoint.param_locations == {}
    assert endpoint.location_for("id") == "query"


def test_dedupe_unions_param_locations_first_seen_wins():
    first = _endpoint(url="https://x/api/users", parameters=["id"], param_locations={"id": "query"})
    second = _endpoint(
        url="https://x/api/users", parameters=["id", "name"],
        param_locations={"id": "body", "name": "body"},
    )

    deduped = dedupe([first, second])

    assert len(deduped) == 1
    assert deduped[0].param_locations == {"id": "query", "name": "body"}


# ---------------------------------------------------------------------------
# merge() — cross-role endpoint union
# ---------------------------------------------------------------------------


def test_merge_unions_endpoints_discovered_by_different_roles():
    """An admin-only endpoint role B's crawl reveals must survive a
    merge with role A's crawl, which never saw it -- and vice versa."""
    admin_only = [_endpoint(url="https://x/admin/users", parameters=["id"])]
    normal_role = [_endpoint(url="https://x/account", parameters=["id"])]

    merged = merge(admin_only, normal_role)

    assert {e.url for e in merged} == {"https://x/admin/users", "https://x/account"}


def test_merge_unions_params_for_endpoint_seen_by_both_roles():
    first = [_endpoint(url="https://x/api/users", parameters=["id"], param_locations={"id": "query"})]
    second = [_endpoint(url="https://x/api/users", parameters=["role"], param_locations={"role": "body"})]

    merged = merge(first, second)

    assert len(merged) == 1
    assert merged[0].parameters == ["id", "role"]
    assert merged[0].param_locations == {"id": "query", "role": "body"}


def test_merge_with_empty_existing_returns_new_unchanged():
    new = [_endpoint(url="https://x/a")]

    merged = merge([], new)

    assert len(merged) == 1
    assert merged[0].url == "https://x/a"


# ---------------------------------------------------------------------------
# EndpointDB
# ---------------------------------------------------------------------------


def test_endpoint_db_save_and_load_scan_round_trips(tmp_path):
    db = EndpointDB(db_path=tmp_path / "stof.db")
    endpoints = [_endpoint(url="https://x/a"), _endpoint(url="https://x/b", auth_required=True)]

    db.save("scan-1", endpoints)
    loaded = db.load_scan("scan-1")

    assert {e.url for e in loaded} == {"https://x/a", "https://x/b"}


def test_endpoint_db_keeps_scans_separate(tmp_path):
    db = EndpointDB(db_path=tmp_path / "stof.db")
    db.save("scan-1", [_endpoint(url="https://x/a")])
    db.save("scan-2", [_endpoint(url="https://x/b")])

    assert [e.url for e in db.load_scan("scan-1")] == ["https://x/a"]
    assert [e.url for e in db.load_scan("scan-2")] == ["https://x/b"]
    assert db.list_scan_ids() == ["scan-1", "scan-2"]


def test_endpoint_db_load_unknown_scan_returns_empty(tmp_path):
    db = EndpointDB(db_path=tmp_path / "stof.db")

    assert db.load_scan("nonexistent") == []
