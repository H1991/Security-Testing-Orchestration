"""Unit tests for Recon Engine — stof.recon.parameter_discovery."""
from stof.crawler.endpoint_store import Endpoint
from stof.recon.parameter_discovery import discover_parameters, guess_param_type

# ---------------------------------------------------------------------------
# guess_param_type
# ---------------------------------------------------------------------------


def test_guess_param_type_email():
    assert guess_param_type("email_addr") == "email"
    assert guess_param_type("userEmail") == "email"


def test_guess_param_type_boolean():
    assert guess_param_type("isAdmin") == "boolean"
    assert guess_param_type("enabled") == "boolean"


def test_guess_param_type_date():
    assert guess_param_type("startDate") == "date"
    assert guess_param_type("createdAt") == "date"


def test_guess_param_type_number():
    assert guess_param_type("transferAmount") == "number"
    assert guess_param_type("qty") == "number"


def test_guess_param_type_id():
    assert guess_param_type("userId") == "id"
    assert guess_param_type("id") == "id"


def test_guess_param_type_defaults_to_string():
    assert guess_param_type("comments") == "string"
    assert guess_param_type("name") == "string"


# ---------------------------------------------------------------------------
# discover_parameters
# ---------------------------------------------------------------------------


def test_discover_parameters_builds_one_entry_per_endpoint():
    endpoints = [
        Endpoint(url="https://x/doTransfer", method="POST", endpoint_type="form", parameters=["fromAccount", "transferAmount"]),
        Endpoint(url="https://x/search.jsp", method="GET", endpoint_type="form", parameters=["query"]),
    ]

    result = discover_parameters(endpoints)

    assert "POST https://x/doTransfer" in result
    assert "GET https://x/search.jsp" in result
    names = {p.name for p in result["POST https://x/doTransfer"]}
    assert names == {"fromAccount", "transferAmount"}


def test_discover_parameters_skips_endpoints_with_no_parameters():
    endpoints = [Endpoint(url="https://x/", method="GET", endpoint_type="page", parameters=[])]

    result = discover_parameters(endpoints)

    assert result == {}


def test_discover_parameters_includes_type_guesses():
    endpoints = [Endpoint(url="https://x/doTransfer", method="POST", endpoint_type="form", parameters=["transferAmount"])]

    result = discover_parameters(endpoints)

    param = result["POST https://x/doTransfer"][0]
    assert param.name == "transferAmount"
    assert param.guessed_type == "number"
