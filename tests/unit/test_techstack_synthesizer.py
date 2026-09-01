"""Unit tests for stof.tools.techstack_synthesizer."""
from stof.tools.httpx_runner import HttpxResult
from stof.tools.nuclei_runner import NucleiFinding
from stof.tools.techstack_synthesizer import classify_tech_items, synthesize_techstack

# ---------------------------------------------------------------------------
# classify_tech_items -- pure classification
# ---------------------------------------------------------------------------


def test_classify_tech_items_buckets_by_category():
    buckets = classify_tech_items(["React", "Spring Boot", "Nginx", "Java", "Cloudflare"])

    assert buckets["frontend"] == {"React"}
    assert buckets["backend"] == {"Spring Boot"}
    assert buckets["server"] == {"Nginx"}
    assert buckets["language"] == {"Java"}
    assert buckets["cdn"] == {"Cloudflare"}


def test_classify_tech_items_matches_the_real_apache_coyote_signature():
    """Regression: this project's own demo target reports the server as
    "Apache-Coyote/1.1", which must map to the Apache Tomcat bucket."""
    buckets = classify_tech_items(["Apache-Coyote/1.1"])

    assert buckets["server"] == {"Apache Tomcat"}


def test_classify_tech_items_ignores_unrecognised_strings():
    assert classify_tech_items(["some-unknown-thing-xyz"]) == {}


def test_classify_tech_items_is_case_insensitive():
    buckets = classify_tech_items(["REACT", "spring boot"])
    assert buckets["frontend"] == {"React"}
    assert buckets["backend"] == {"Spring Boot"}


# ---------------------------------------------------------------------------
# synthesize_techstack -- happy path
# ---------------------------------------------------------------------------


def test_synthesize_techstack_produces_the_requested_shape():
    httpx_results = [HttpxResult(url="https://x/", tech=["React", "Nginx"], webserver="nginx")]

    summary = synthesize_techstack("https://x/", httpx_results=httpx_results)

    assert summary.frontend == {"framework": "React", "version": None}
    assert summary.server == "Nginx"
    assert summary.sources == ["httpx"]


def test_synthesize_techstack_prefers_extracted_results_over_generic_template_name():
    """Regression: confirmed against this project's own demo target.
    httpx reports server tech ["Apache Tomcat"] (specific); nuclei's
    apache-detect template matches with the generic name "Apache
    Detection" but extracts the precise banner "Apache-Coyote/1.1".
    Before this fix, "Apache Detection" got classified too (as the
    more generic "Apache HTTP Server"), and an alphabetical tie-break
    ("Apache HTTP Server" < "Apache Tomcat") silently picked the less
    specific, less-confirmed answer over one two sources agreed on."""
    httpx_results = [HttpxResult(url="https://x/", tech=["Apache Tomcat", "Java"], webserver="Apache-Coyote/1.1")]
    nuclei_findings = [
        NucleiFinding(
            template_id="apache-detect", name="Apache Detection", severity="info",
            matched_at="https://x/", tags=["tech", "apache"], extracted_results=["Apache-Coyote/1.1"],
        )
    ]

    summary = synthesize_techstack("https://x/", httpx_results=httpx_results, nuclei_findings=nuclei_findings)

    assert summary.server == "Apache Tomcat"


def test_synthesize_techstack_falls_back_to_name_when_nothing_extracted():
    nuclei_findings = [
        NucleiFinding(
            template_id="waf-detect", name="WAF Detection", severity="info",
            matched_at="https://x/", tags=["waf"], extracted_results=[],
        )
    ]

    summary = synthesize_techstack("https://x/", nuclei_findings=nuclei_findings)

    assert summary.waf == "Generic/unidentified WAF"


def test_synthesize_techstack_merges_httpx_and_nuclei():
    httpx_results = [HttpxResult(url="https://x/", tech=["Java"])]
    nuclei_findings = [NucleiFinding(template_id="waf-detect", name="WAF Detection", severity="info", matched_at="https://x/", tags=["waf"])]

    summary = synthesize_techstack("https://x/", httpx_results=httpx_results, nuclei_findings=nuclei_findings)

    assert summary.language == "Java"
    assert summary.waf is not None
    assert summary.sources == ["httpx", "nuclei"]


def test_synthesize_techstack_detects_authentication_and_apis():
    httpx_results = [HttpxResult(url="https://x/", tech=["JWT", "GraphQL", "Swagger"])]

    summary = synthesize_techstack("https://x/", httpx_results=httpx_results)

    assert "JWT" in summary.authentication
    assert "GraphQL" in summary.apis
    assert "REST (OpenAPI/Swagger)" in summary.apis


# ---------------------------------------------------------------------------
# Input validation / honesty about unknowns
# ---------------------------------------------------------------------------


def test_synthesize_techstack_with_no_input_leaves_everything_empty():
    summary = synthesize_techstack("https://x/")

    assert summary.frontend == {}
    assert summary.backend == {}
    assert summary.server is None
    assert summary.database is None
    assert summary.sources == []


def test_synthesize_techstack_notes_missing_database_and_cdn():
    summary = synthesize_techstack("https://x/", httpx_results=[HttpxResult(url="https://x/", tech=["Java"])])

    assert any("database" in note for note in summary.confidence_notes)
    assert any("cdn" in note for note in summary.confidence_notes)


def test_synthesize_techstack_to_dict_is_json_serialisable():
    import json

    summary = synthesize_techstack("https://x/", httpx_results=[HttpxResult(url="https://x/", tech=["React"])])

    round_tripped = json.loads(json.dumps(summary.to_dict()))
    assert round_tripped["target"] == "https://x/"
