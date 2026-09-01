"""Unit tests for the stof.payloads model/registry/generator layer --
Step 1 of the payload-engine review: models + registry + generators
with no behavior change to any existing module. Nothing here is wired
into idor_tests.py/auth_tests.py/jwt_tests.py yet; that migration is a
separate follow-up.
"""
import pytest

from stof.payloads.generators import PayloadGenerator, StaticValueGenerator
from stof.payloads.models import Payload, ProbeContext
from stof.payloads.registry import KNOWN_TESTCASES, PayloadRegistry, UnknownTestCaseError, top_level_id

# ---------------------------------------------------------------------------
# Payload / ProbeContext
# ---------------------------------------------------------------------------


def test_payload_applies_to_matching_testcase_and_context():
    payload = Payload(payload_id="p1", testcase_id="TC-053.2", family="object_id", value="800001", contexts=("query", "path"))
    context = ProbeContext(testcase_id="TC-053.2", location="query")

    assert payload.applies_to(context) is True


def test_payload_does_not_apply_to_a_different_testcase():
    payload = Payload(payload_id="p1", testcase_id="TC-053.2", family="object_id", value="800001", contexts=("query",))
    context = ProbeContext(testcase_id="TC-054.1", location="query")

    assert payload.applies_to(context) is False


def test_payload_does_not_apply_to_an_unlisted_context():
    """A JSON-body payload must not be offered for a query-string
    probe -- the exact "trying a JSON payload against a form endpoint"
    mistake the review flagged."""
    payload = Payload(payload_id="p1", testcase_id="TC-053.3", family="object_id", value={"orderId": "1"}, contexts=("json",))
    context = ProbeContext(testcase_id="TC-053.3", location="query")

    assert payload.applies_to(context) is False


def test_payload_is_frozen():
    payload = Payload(payload_id="p1", testcase_id="TC-053.2", family="object_id", value="1", contexts=("query",))
    with pytest.raises(AttributeError):
        payload.value = "2"


def test_payload_defaults():
    payload = Payload(payload_id="p1", testcase_id="TC-053.2", family="object_id", value="1", contexts=("query",))
    assert payload.risk == "read_only"
    assert payload.state_changing is False
    assert payload.tags == ()


# ---------------------------------------------------------------------------
# top_level_id
# ---------------------------------------------------------------------------


def test_top_level_id_strips_sub_technique_suffix():
    assert top_level_id("TC-053.2") == "TC-053"


def test_top_level_id_passes_through_a_bare_id():
    assert top_level_id("TC-053") == "TC-053"


def test_top_level_id_rejects_non_testcase_string():
    with pytest.raises(UnknownTestCaseError):
        top_level_id("not-a-testcase")


# ---------------------------------------------------------------------------
# PayloadRegistry -- the frozen-catalog enforcement is the whole point
# ---------------------------------------------------------------------------


def test_known_testcases_is_non_empty_and_matches_the_real_catalog_shape():
    # 69 from the original sprint-plan-derived catalog + Wave 2's TC-127
    # (SQL Injection) / TC-128 (Reflected XSS) + Wave 3's TC-129
    # (Session/Rate-Limit Weaknesses) / TC-130 (CSRF) + Wave 4's TC-131
    # (Tenant Isolation BOLA), none of which had a generic top-level
    # entry before their respective modules existed.
    assert len(KNOWN_TESTCASES) == 74
    assert "TC-053" in KNOWN_TESTCASES
    assert "TC-055" in KNOWN_TESTCASES
    assert "TC-127" in KNOWN_TESTCASES
    assert "TC-128" in KNOWN_TESTCASES
    assert "TC-129" in KNOWN_TESTCASES
    assert "TC-130" in KNOWN_TESTCASES


def test_register_accepts_a_payload_for_a_known_testcase():
    registry = PayloadRegistry()
    payload = Payload(payload_id="p1", testcase_id="TC-053.2", family="object_id", value="1", contexts=("query",))

    registry.register(payload)

    assert registry.for_testcase("TC-053.2") == [payload]


def test_register_rejects_a_payload_for_an_unknown_testcase():
    """The core rule from this review round: the payload layer must
    never define a new vulnerability, only supply inputs for an
    existing TC-*. A made-up TC-999 must be rejected at registration
    time, not silently accepted."""
    registry = PayloadRegistry()
    payload = Payload(payload_id="p1", testcase_id="TC-999.1", family="made_up", value="1", contexts=("query",))

    with pytest.raises(UnknownTestCaseError, match="TC-999"):
        registry.register(payload)


def test_register_rejects_a_payload_for_a_real_but_unlisted_testcase_number():
    """TC-500 isn't in the sprint-plan catalog at all -- distinct from
    the TC-999 case, this checks a plausible-looking id still gets
    rejected rather than only ids that are obviously fake."""
    registry = PayloadRegistry()
    payload = Payload(payload_id="p1", testcase_id="TC-500.1", family="made_up", value="1", contexts=("query",))

    with pytest.raises(UnknownTestCaseError):
        registry.register(payload)


def test_register_all_registers_every_payload():
    registry = PayloadRegistry()
    payloads = [
        Payload(payload_id="p1", testcase_id="TC-053.2", family="object_id", value="1", contexts=("query",)),
        Payload(payload_id="p2", testcase_id="TC-053.2", family="object_id", value="2", contexts=("query",)),
    ]

    registry.register_all(payloads)

    assert registry.for_testcase("TC-053.2") == payloads


def test_register_all_rejects_the_whole_batch_on_the_first_unknown_id():
    registry = PayloadRegistry()
    payloads = [
        Payload(payload_id="p1", testcase_id="TC-053.2", family="object_id", value="1", contexts=("query",)),
        Payload(payload_id="p2", testcase_id="TC-999.1", family="made_up", value="2", contexts=("query",)),
    ]

    with pytest.raises(UnknownTestCaseError):
        registry.register_all(payloads)


def test_for_testcase_returns_empty_list_for_unregistered_testcase():
    registry = PayloadRegistry()
    assert registry.for_testcase("TC-053.2") == []


def test_for_context_filters_by_location():
    registry = PayloadRegistry()
    query_payload = Payload(payload_id="p1", testcase_id="TC-053.2", family="object_id", value="1", contexts=("query",))
    json_payload = Payload(payload_id="p2", testcase_id="TC-053.2", family="object_id", value={"id": "1"}, contexts=("json",))
    registry.register_all([query_payload, json_payload])

    result = registry.for_context(ProbeContext(testcase_id="TC-053.2", location="query"))

    assert result == [query_payload]


def test_registries_do_not_share_state_across_instances():
    registry_a = PayloadRegistry()
    registry_b = PayloadRegistry()
    registry_a.register(Payload(payload_id="p1", testcase_id="TC-053.2", family="object_id", value="1", contexts=("query",)))

    assert registry_b.for_testcase("TC-053.2") == []


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------


def test_static_value_generator_produces_one_payload_per_value():
    generator = StaticValueGenerator("TC-053.2", "object_id", ["1", "2", "3"], contexts=("query", "path"))

    payloads = list(generator.generate())

    assert [p.value for p in payloads] == ["1", "2", "3"]
    assert all(p.testcase_id == "TC-053.2" for p in payloads)
    assert all(p.contexts == ("query", "path") for p in payloads)


def test_static_value_generator_payload_ids_are_unique():
    generator = StaticValueGenerator("TC-053.2", "object_id", ["1", "2", "3"], contexts=("query",))
    ids = [p.payload_id for p in generator.generate()]
    assert len(ids) == len(set(ids))


def test_static_value_generator_passes_through_risk_and_state_changing():
    generator = StaticValueGenerator(
        "TC-053.3", "object_id", ["1"], contexts=("json",), risk="active", state_changing=True,
    )
    payload = next(generator.generate())
    assert payload.risk == "active"
    assert payload.state_changing is True


def test_static_value_generator_output_registers_cleanly():
    """End to end: generate -> register -> query, the exact flow a
    module would use."""
    generator = StaticValueGenerator("TC-053.2", "object_id", ["800000", "800001"], contexts=("query",))
    registry = PayloadRegistry()

    registry.register_all(list(generator.generate()))

    context = ProbeContext(testcase_id="TC-053.2", location="query")
    assert [p.value for p in registry.for_context(context)] == ["800000", "800001"]


def test_payload_generator_base_class_requires_subclassing():
    generator = PayloadGenerator()
    with pytest.raises(NotImplementedError):
        generator.generate()
