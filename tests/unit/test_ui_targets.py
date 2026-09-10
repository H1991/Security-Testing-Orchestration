"""Unit tests for stof.ui.targets -- the pure Target Profile transforms
behind the console's multi-application support (see the module's own
docstring for why disk I/O is deliberately kept out of this module and
tested at the server.py call sites instead, matching test_server_
dashboard_summary.py's precedent)."""
import json

from stof.ui import targets

# ---------------------------------------------------------------------------
# slugify / new_target_id
# ---------------------------------------------------------------------------


def test_slugify_lowercases_and_hyphenates():
    assert targets.slugify("Kapture KM Staging") == "kapture-km-staging"


def test_slugify_empty_falls_back_to_target():
    assert targets.slugify("   ") == "target"


def test_new_target_id_is_unique_against_existing_ids():
    assert targets.new_target_id("Acme", {"acme"}) == "acme-2"
    assert targets.new_target_id("Acme", {"acme", "acme-2"}) == "acme-3"


def test_new_target_id_no_collision_returns_base_slug():
    assert targets.new_target_id("Fresh App", set()) == "fresh-app"


# ---------------------------------------------------------------------------
# env_key
# ---------------------------------------------------------------------------


def test_env_key_admin_vs_normal_prefix():
    assert targets.env_key("admin", "acme") == "ADMIN_PASSWORD__ACME"
    assert targets.env_key("normal", "acme") == "USER_PASSWORD__ACME"


def test_env_key_sanitizes_non_alnum_target_id():
    assert targets.env_key("admin", "kapture-km-staging") == "ADMIN_PASSWORD__KAPTURE_KM_STAGING"


# ---------------------------------------------------------------------------
# load / save
# ---------------------------------------------------------------------------


def test_load_missing_file_returns_default_store(tmp_path):
    doc = targets.load(tmp_path / "targets.json")
    assert doc == {"targets": [], "active_target_id": None}


def test_load_malformed_json_falls_back_to_default(tmp_path):
    path = tmp_path / "targets.json"
    path.write_text("{not json", encoding="utf-8")
    assert targets.load(path) == {"targets": [], "active_target_id": None}


def test_save_then_load_roundtrips(tmp_path):
    path = tmp_path / "targets.json"
    doc = {"targets": [targets.new_profile("acme", "Acme")], "active_target_id": "acme"}
    targets.save(path, doc)
    loaded = targets.load(path)
    assert loaded["active_target_id"] == "acme"
    assert loaded["targets"][0]["id"] == "acme"
    assert json.loads(path.read_text(encoding="utf-8"))["active_target_id"] == "acme"


# ---------------------------------------------------------------------------
# find / new_profile
# ---------------------------------------------------------------------------


def test_find_returns_none_when_absent():
    doc = {"targets": [targets.new_profile("acme", "Acme")]}
    assert targets.find(doc, "nope") is None


def test_find_returns_matching_profile():
    doc = {"targets": [targets.new_profile("acme", "Acme")]}
    assert targets.find(doc, "acme")["name"] == "Acme"


def test_new_profile_defaults():
    profile = targets.new_profile("acme", "Acme")
    assert profile["app_type"] == "web"
    assert profile["environment"] == "production"
    assert profile["scan_intensity"] == "standard"
    assert profile["allow_state_changing_probes"] is False
    assert profile["admin_password_set"] is False
    assert profile["normal_password_set"] is False
    assert profile["created_at"] == profile["updated_at"]


def test_load_backfills_environment_for_a_profile_saved_before_the_field_existed(tmp_path):
    path = tmp_path / "targets.json"
    profile = targets.new_profile("acme", "Acme")
    del profile["environment"]  # simulates targets.json written before this field existed
    path.write_text(json.dumps({"targets": [profile], "active_target_id": "acme"}), encoding="utf-8")
    loaded = targets.load(path)
    assert loaded["targets"][0]["environment"] == "production"


# ---------------------------------------------------------------------------
# apply_fields
# ---------------------------------------------------------------------------


def test_apply_fields_sets_direct_fields():
    profile = targets.new_profile("acme", "Acme")
    targets.apply_fields(profile, {"base_url": "https://a.example", "login_url": "https://a.example/login", "app_type": "api"})
    assert profile["base_url"] == "https://a.example"
    assert profile["login_url"] == "https://a.example/login"
    assert profile["app_type"] == "api"


def test_apply_fields_leaves_omitted_fields_untouched():
    profile = targets.new_profile("acme", "Acme")
    profile["base_url"] = "https://existing.example"
    targets.apply_fields(profile, {"app_type": "api"})
    assert profile["base_url"] == "https://existing.example"


def test_apply_fields_sets_environment():
    profile = targets.new_profile("acme", "Acme")
    targets.apply_fields(profile, {"environment": "staging"})
    assert profile["environment"] == "staging"


def test_apply_fields_none_never_overwrites():
    profile = targets.new_profile("acme", "Acme")
    profile["base_url"] = "https://existing.example"
    targets.apply_fields(profile, {"base_url": None})
    assert profile["base_url"] == "https://existing.example"


def test_apply_fields_empty_string_clears_selector():
    profile = targets.new_profile("acme", "Acme")
    profile["username_selector"] = "#user"
    targets.apply_fields(profile, {"username_selector": ""})
    assert profile["username_selector"] is None


def test_apply_fields_bool_flags_accept_explicit_false():
    profile = targets.new_profile("acme", "Acme")
    profile["allow_state_changing_probes"] = True
    targets.apply_fields(profile, {"allow_state_changing_probes": False})
    assert profile["allow_state_changing_probes"] is False


def test_apply_fields_updates_timestamp():
    profile = targets.new_profile("acme", "Acme")
    before = profile["updated_at"]
    targets.apply_fields(profile, {"app_type": "api"})
    assert profile["updated_at"] >= before


# ---------------------------------------------------------------------------
# set_role_credentials / mark_password_set
# ---------------------------------------------------------------------------


def test_set_role_credentials_sets_username_and_auth_type():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "jwt")
    assert profile["admin_username"] == "admin@acme.com"
    assert profile["admin_auth_type"] == "jwt"


def test_set_role_credentials_empty_string_clears_role():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "jwt")
    profile["admin_password_set"] = True
    targets.set_role_credentials(profile, "admin", "", None)
    assert profile["admin_username"] is None
    assert profile["admin_auth_type"] == "form_login"
    assert profile["admin_password_set"] is False


def test_set_role_credentials_both_none_is_a_noop():
    profile = targets.new_profile("acme", "Acme")
    profile["admin_username"] = "existing"
    targets.set_role_credentials(profile, "admin", None, None)
    assert profile["admin_username"] == "existing"


def test_mark_password_set():
    profile = targets.new_profile("acme", "Acme")
    targets.mark_password_set(profile, "normal")
    assert profile["normal_password_set"] is True


def test_set_role_credentials_empty_string_clears_totp_flag_too():
    """Removing an account removes whatever MFA was configured for it
    -- a stale totp_secret_set flag with no username behind it would
    silently keep referencing a .env key for an account that no longer
    exists in this profile."""
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_credentials(profile, "admin", "admin@acme.com", "form_login")
    profile["admin_totp_secret_set"] = True
    targets.set_role_credentials(profile, "admin", "", None)
    assert profile["admin_totp_secret_set"] is False


# ---------------------------------------------------------------------------
# set_role_totp_secret
# ---------------------------------------------------------------------------


def test_set_role_totp_secret_marks_set_for_a_real_value():
    profile = targets.new_profile("acme", "Acme")
    targets.set_role_totp_secret(profile, "admin", "JBSWY3DPEHPK3PXP")
    assert profile["admin_totp_secret_set"] is True


def test_set_role_totp_secret_empty_string_clears_the_flag():
    profile = targets.new_profile("acme", "Acme")
    profile["admin_totp_secret_set"] = True
    targets.set_role_totp_secret(profile, "admin", "")
    assert profile["admin_totp_secret_set"] is False


def test_set_role_totp_secret_none_is_a_noop():
    profile = targets.new_profile("acme", "Acme")
    profile["admin_totp_secret_set"] = True
    targets.set_role_totp_secret(profile, "admin", None)
    assert profile["admin_totp_secret_set"] is True  # untouched, not reset


def test_totp_env_key_shape():
    assert targets.totp_env_key("admin", "kapture-km-staging") == "ADMIN_TOTP_SECRET__KAPTURE_KM_STAGING"
    assert targets.totp_env_key("normal", "kapture-km-staging") == "USER_TOTP_SECRET__KAPTURE_KM_STAGING"


# ---------------------------------------------------------------------------
# target_block / testing_block / user_entries
# ---------------------------------------------------------------------------


def test_target_block_includes_only_set_selectors():
    profile = targets.new_profile("acme", "Acme")
    profile["base_url"] = "https://a.example"
    profile["login_url"] = "https://a.example/login"
    profile["username_selector"] = "#user"
    block = targets.target_block(profile)
    assert block == {
        "base_url": "https://a.example",
        "login_url": "https://a.example/login",
        "requires_assisted_login": False,
        "username_selector": "#user",
    }


def test_target_block_includes_crawler_exclusions_and_idor_candidate_ids_when_set():
    """Regression test for a real bug caught via live testing: these two
    TargetConfig fields (stof/config/schema.py) were dropped entirely by
    an earlier version of target_block(), which silently wiped a real
    target's tuned crawler_exclude_patterns/idor_candidate_ids on the
    very next activation."""
    profile = targets.new_profile("acme", "Acme")
    profile["base_url"] = "https://a.example"
    profile["login_url"] = "https://a.example/login"
    profile["crawler_exclude_patterns"] = ["survey_questions", "privacypolicy"]
    profile["idor_candidate_ids"] = ["800000", "800001"]
    block = targets.target_block(profile)
    assert block["crawler_exclude_patterns"] == ["survey_questions", "privacypolicy"]
    assert block["idor_candidate_ids"] == ["800000", "800001"]


def test_apply_fields_sets_list_fields():
    profile = targets.new_profile("acme", "Acme")
    targets.apply_fields(profile, {"crawler_exclude_patterns": ["a", "b"], "idor_candidate_ids": ["1", "2"]})
    assert profile["crawler_exclude_patterns"] == ["a", "b"]
    assert profile["idor_candidate_ids"] == ["1", "2"]


def test_apply_fields_empty_list_clears_list_field():
    profile = targets.new_profile("acme", "Acme")
    profile["crawler_exclude_patterns"] = ["a", "b"]
    targets.apply_fields(profile, {"crawler_exclude_patterns": []})
    assert profile["crawler_exclude_patterns"] is None


def test_apply_fields_none_list_field_leaves_untouched():
    profile = targets.new_profile("acme", "Acme")
    profile["crawler_exclude_patterns"] = ["a", "b"]
    targets.apply_fields(profile, {"crawler_exclude_patterns": None})
    assert profile["crawler_exclude_patterns"] == ["a", "b"]


def test_testing_block_reflects_profile_safety_settings():
    profile = targets.new_profile("acme", "Acme")
    profile["scan_intensity"] = "cautious"
    profile["allow_state_changing_probes"] = True
    assert targets.testing_block(profile) == {"allow_state_changing_probes": True, "scan_intensity": "cautious"}


def test_user_entries_includes_only_roles_with_a_username():
    profile = targets.new_profile("acme", "Acme")
    profile["admin_username"] = "admin@acme.com"
    entries = targets.user_entries(profile)
    assert len(entries) == 1
    assert entries[0] == {
        "id": "admin-01",
        "role": "admin",
        "username": "admin@acme.com",
        "password": "{{env:ADMIN_PASSWORD}}",
        "auth_type": "form_login",
    }


def test_user_entries_empty_when_no_roles_configured():
    profile = targets.new_profile("acme", "Acme")
    assert targets.user_entries(profile) == []


def test_user_entries_normal_role_uses_user_password_token():
    profile = targets.new_profile("acme", "Acme")
    profile["normal_username"] = "user@acme.com"
    profile["normal_auth_type"] = "jwt"
    entries = targets.user_entries(profile)
    assert entries[0]["password"] == "{{env:USER_PASSWORD}}"
    assert entries[0]["auth_type"] == "jwt"


def test_user_entries_includes_totp_secret_token_when_configured():
    profile = targets.new_profile("acme", "Acme")
    profile["admin_username"] = "admin@acme.com"
    profile["admin_totp_secret_set"] = True
    entries = targets.user_entries(profile)
    assert entries[0]["totp_secret"] == "{{env:ADMIN_TOTP_SECRET}}"


def test_user_entries_omits_totp_secret_key_entirely_when_not_configured():
    """Matches UserConfig.totp_secret's own None default -- most users
    have no MFA at all, so the key shouldn't even be present (not a
    null value) in the generated users.json entry."""
    profile = targets.new_profile("acme", "Acme")
    profile["admin_username"] = "admin@acme.com"
    entries = targets.user_entries(profile)
    assert "totp_secret" not in entries[0]


def test_user_entries_normal_role_totp_uses_user_totp_secret_token():
    profile = targets.new_profile("acme", "Acme")
    profile["normal_username"] = "user@acme.com"
    profile["normal_totp_secret_set"] = True
    entries = targets.user_entries(profile)
    assert entries[0]["totp_secret"] == "{{env:USER_TOTP_SECRET}}"
