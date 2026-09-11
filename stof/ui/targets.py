"""Target Profile store -- the STOF Console's multi-application layer.

STOF's actual scan engine (`stof.config.schema.Config`, `stof/main.py`,
every vulnerability module) stays genuinely single-target per run, by
design: one `Config` object, dependency-injected, read from
`config/config.json`, exactly as CLAUDE.md's Layer 1 has always
specified -- the CLI (`stof scan --config ... --users ...`) is completely
unaffected by anything in this module.

This module adds a layer ABOVE that, owned entirely by the console: a
named, reusable "Target Profile" (one saved application -- base URL,
login, credentials, application type, per-target scan safety) an
operator can create, edit, and switch between from New Scan.
"Activating" a profile writes its fields into `config.json`'s
`target`/`testing` blocks and `users.json` -- the exact files
`stof/main.py` has always read -- so the scan engine never learns a
multi-target concept exists; it only ever sees "the" target for
whatever run is about to happen, same as before this module existed.
This mirrors how Acunetix/AppScan/Veracode DAST separate a reusable
Target/Application profile from the engine's own per-scan config.

Passwords are never written to `targets.json` -- same `{{env:VAR}}`-token
philosophy `users.json` already uses (CLAUDE.md rule 6), just with a
per-profile env var name so two profiles' credentials for the same role
never collide in `.env`. Only a `password_set` boolean is persisted per
role for the UI to show "configured" without ever reading a secret back
-- same convention `burp.api_key_set` already uses in `stof/ui/server.py`.

Roles: a profile's `roles` field is a LIST (`[{"id": ..., "role": ...,
"username": ..., "auth_type": ..., "password_set": ..., "totp_secret_
set": ...}, ...]`), not a fixed pair -- a real tester often has exactly
one account for a target, sometimes three (Admin/Support/Read-only),
never reliably two named "admin"/"normal". This matches how Invicti's
own form-auth setup defaults to one identity block and Fortify
WebInspect's multi-user login is an explicit opt-in, not a mandatory
second slot (see the console's New Scan Credentials card for the
tester-facing side of this). `role` is a free-text display label the
operator types (no fixed enum) -- `id` is a separate, stable handle
assigned once when the role is first added and never recomputed
afterward, because every `.env` key name is derived from it (see
`env_key()`/`totp_env_key()` below); renaming the display label later
must never orphan an already-written secret. This project's original
two roles ("admin"/"normal", exact lowercase match) keep their
historical `admin-01`/`user-01` ids and `ADMIN_PASSWORD`/`USER_PASSWORD`
env var prefixes -- an existing install's `.env` file keeps resolving
with zero migration. Any other role name gets a fresh id derived from
its own slug (deduped the same way `new_target_id()` dedupes target
ids), which by construction can never collide with another role's env
var name within the same profile.

Disk I/O (reading/writing `targets.json`, `.env`, `config.json`,
`users.json`) deliberately stays OUT of this module -- it only builds
and transforms plain dicts. `stof/ui/server.py` owns every file path and
every write, matching this project's own `tests/unit/test_server_
dashboard_summary.py` precedent of testing pure aggregation helpers
without spinning up the FastAPI app or touching disk.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_TYPES = ("web", "api", "mobile_api", "other")
AUTH_TYPES = ("form_login", "jwt")
SCAN_INTENSITIES = ("cautious", "standard", "aggressive")

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_ENV_KEY_RE = re.compile(r"[^A-Z0-9]+")

# This project's original two roles -- exact lowercase match only (a
# tester who types "Admin" with a capital A gets a fresh id/env-var
# pair, not this historical one; the two are different free-text
# labels as far as this module is concerned). Kept solely so an
# existing install's .env file (ADMIN_PASSWORD__..., USER_PASSWORD__...)
# keeps resolving after this module moved from a fixed admin/normal
# pair to an arbitrary-length roles list.
_DEFAULT_ROLE_IDS = {"admin": "admin-01", "normal": "user-01"}
_DEFAULT_ENV_PREFIXES = {"admin": "ADMIN", "normal": "USER"}


def slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", name.strip().lower()).strip("-")
    return slug or "target"


def new_target_id(name: str, existing_ids: Any) -> str:
    """A short, readable, unique id derived from the profile's name
    (e.g. "Kapture KM Staging" -> "kapture-km-staging"), not a raw
    UUID -- this id shows up in `.env` key names, so a slug is worth
    the tiny extra work over `uuid4().hex`."""
    existing = set(existing_ids)
    base = slugify(name)
    candidate = base
    n = 2
    while candidate in existing:
        candidate = f"{base}-{n}"
        n += 1
    return candidate


def _role_id_for(role: str, existing_ids: set[str]) -> str:
    """Stable id for a newly-added role entry, used as `users.json`'s
    per-entry `"id"` field -- purely a display/bookkeeping handle, NOT
    what env var names are derived from (see `_env_prefix_for_role()`
    below, which works off the free-text label directly, matching this
    module's original contract). "admin"/"normal" keep their historical
    ids when available; everything else falls back to the same
    slug+dedupe scheme `new_target_id()` uses for target ids."""
    default = _DEFAULT_ROLE_IDS.get(role)
    if default and default not in existing_ids:
        return default
    base = slugify(role)
    candidate = base
    n = 2
    while candidate in existing_ids:
        candidate = f"{base}-{n}"
        n += 1
    return candidate


def _env_prefix_for_role(role: str) -> str:
    """"admin" -> "ADMIN", "normal" -> "USER" (exact historical prefixes,
    preserved so an existing install's `.env` file keeps resolving with
    zero migration); any other free-text role label is sanitized
    directly into a prefix. Note this means two custom role names that
    sanitize to the same text (e.g. "Support!" and "Support?") would
    share an env var prefix within one profile -- an accepted, narrow
    edge case for a human-typed, small (1-3 role) list, not one this
    module tries to fully rule out with extra bookkeeping."""
    if role in _DEFAULT_ENV_PREFIXES:
        return _DEFAULT_ENV_PREFIXES[role]
    return _ENV_KEY_RE.sub("_", role.upper()).strip("_") or "ROLE"


def plain_env_var(role: str) -> str:
    """The un-suffixed `.env` key name a role's password resolves
    through once a profile carrying it is activated (the actual token
    `{{env:...}}` written into `config/users.json` by `user_entries()`
    below) -- single source of truth also used by `env_key()` and by
    `stof/ui/server.py`'s activation step, so the two can never drift
    out of sync with each other."""
    return f"{_env_prefix_for_role(role)}_PASSWORD"


def plain_totp_env_var(role: str) -> str:
    return f"{_env_prefix_for_role(role)}_TOTP_SECRET"


def env_key(role: str, target_id: str) -> str:
    """`ADMIN_PASSWORD__KAPTURE_KM_STAGING` / `USER_PASSWORD__...` -- the
    per-profile `.env` key a role's stored password/token lives under."""
    suffix = _ENV_KEY_RE.sub("_", target_id.upper()).strip("_")
    return f"{plain_env_var(role)}__{suffix}"


def totp_env_key(role: str, target_id: str) -> str:
    """Same per-profile `.env` scoping shape as `env_key()`, for the
    optional TOTP/MFA secret (`stof.config.schema.UserConfig.
    totp_secret`) instead of the password."""
    suffix = _ENV_KEY_RE.sub("_", target_id.upper()).strip("_")
    return f"{plain_totp_env_var(role)}__{suffix}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_store() -> dict:
    return {"targets": [], "active_target_id": None}


def _migrate_profile_roles(profile: dict) -> None:
    """Additive migration for a `targets.json` written before roles
    became a list: an old profile carried exactly `admin_username`/
    `admin_auth_type`/`admin_password_set`/`admin_totp_secret_set` and
    the same four keys prefixed `normal_` directly on the profile dict.
    Converts those into `profile["roles"]`, in place, dropping the old
    flat keys entirely (not left around as dead weight -- this project's
    own rule against backwards-compatibility cruft once a clean
    migration exists). A profile that already has a `"roles"` key was
    either created fresh under the new shape or already migrated; never
    reprocessed."""
    if "roles" in profile:
        return
    roles: list[dict] = []
    for role, role_id in _DEFAULT_ROLE_IDS.items():
        username = profile.pop(f"{role}_username", None)
        auth_type = profile.pop(f"{role}_auth_type", "form_login")
        password_set = bool(profile.pop(f"{role}_password_set", False))
        totp_secret_set = bool(profile.pop(f"{role}_totp_secret_set", False))
        if username:
            roles.append({
                "id": role_id, "role": role, "username": username,
                "auth_type": auth_type, "password_set": password_set,
                "totp_secret_set": totp_secret_set,
            })
    profile["roles"] = roles


def load(path: Path) -> dict:
    if not path.is_file():
        return default_store()
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default_store()
    if not isinstance(doc, dict):
        return default_store()
    doc.setdefault("targets", [])
    doc.setdefault("active_target_id", None)
    for profile in doc["targets"]:
        # Additive migration for a targets.json written before
        # "environment" existed -- same convention findings/store.py's
        # own schema migration uses for an on-disk file predating a
        # newer field.
        profile.setdefault("environment", "production")
        _migrate_profile_roles(profile)
    return doc


def save(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def find(doc: dict, target_id: str) -> dict | None:
    return next((t for t in doc["targets"] if t["id"] == target_id), None)


def new_profile(target_id: str, name: str) -> dict:
    """A fresh profile with every field defaulted -- callers layer
    `apply_fields`/`set_role_credentials` on top for whatever the
    create request actually supplied, so this is the one place
    new-profile defaults live. `roles` starts empty: a brand new
    profile legitimately has zero accounts configured yet, the same
    "from one account up" state the Credentials card already supports
    for an existing profile."""
    now = _now()
    return {
        "id": target_id,
        "name": name,
        "app_type": "web",
        # Pure metadata, same as app_type -- never read by the scan
        # engine or by any technique's own logic. Exists so an operator
        # running STOF against several real deployments of the same
        # application (staging vs. production) can tell them apart on
        # the Applications/Scans pages, the same environment tagging
        # every enterprise DAST console (Acunetix, AppScan, Invicti)
        # already shows next to a target's name.
        "environment": "production",
        "base_url": "",
        "login_url": "",
        "username_selector": None,
        "password_selector": None,
        "submit_selector": None,
        "crawler_exclude_patterns": None,
        "idor_candidate_ids": None,
        "requires_assisted_login": False,
        "roles": [],
        "scan_intensity": "standard",
        "allow_state_changing_probes": False,
        "created_at": now,
        "updated_at": now,
    }


def apply_fields(profile: dict, updates: dict) -> None:
    """Partial update -- the exact convention every other config
    endpoint in this codebase already uses (see `/api/config/target`):
    a field absent from `updates` (or explicitly `None`) is left
    untouched; `""` on a clearable selector field resets it back to
    auto-detect."""
    for field in ("name", "app_type", "environment", "base_url", "login_url", "scan_intensity"):
        value = updates.get(field)
        if value:
            profile[field] = value
    if updates.get("requires_assisted_login") is not None:
        profile["requires_assisted_login"] = bool(updates["requires_assisted_login"])
    if updates.get("allow_state_changing_probes") is not None:
        profile["allow_state_changing_probes"] = bool(updates["allow_state_changing_probes"])
    # Clearable fields (string selectors + list fields share one rule):
    # `None` in updates means untouched; an empty string/list clears
    # back to the generic auto-detected default.
    for field in ("username_selector", "password_selector", "submit_selector", "crawler_exclude_patterns", "idor_candidate_ids"):
        if field in updates and updates[field] is not None:
            profile[field] = updates[field] or None
    profile["updated_at"] = _now()


def _find_role_entry(profile: dict, role: str) -> dict | None:
    return next((r for r in profile.get("roles", []) if r["role"] == role), None)


def set_role_credentials(profile: dict, role: str, username: str | None, auth_type: str | None) -> None:
    """Sets username/auth_type for `role` (any free-text label, not
    just "admin"/"normal") on the profile -- creating the role entry
    (with a freshly-assigned, stable `id`) the first time it's seen.
    `username=""` clears that role's credentials entirely (mirrors
    `remove_role()` below, just expressed as a value instead of a
    dedicated call for a role the caller already knows exists). The
    caller is still responsible for writing the matching `.env` key via
    `env_key()`; this only updates the profile document."""
    if username is None and auth_type is None:
        return
    entry = _find_role_entry(profile, role)
    if username == "":
        if entry is not None:
            entry["username"] = None
            entry["auth_type"] = "form_login"
            entry["password_set"] = False
            # Removing the account removes whatever MFA was configured
            # for it too -- a stale totp_secret_set flag with no
            # username behind it would silently keep referencing a
            # .env key for an account that no longer exists. Same
            # reasoning for login_workflow_id: a "form_login" role
            # pointing at a leftover recorded-workflow id would be a
            # confusing, meaningless combination.
            entry["totp_secret_set"] = False
            entry["login_workflow_id"] = None
            profile["updated_at"] = _now()
        return
    if entry is None:
        if username is None:  # only auth_type given for a role that doesn't exist yet -- nothing to create
            return
        existing_ids = {r["id"] for r in profile.get("roles", [])}
        entry = {
            "id": _role_id_for(role, existing_ids), "role": role, "username": None,
            "auth_type": "form_login", "password_set": False, "totp_secret_set": False,
            "login_workflow_id": None,
        }
        profile.setdefault("roles", []).append(entry)
    if username is not None:
        entry["username"] = username
    if auth_type is not None:
        entry["auth_type"] = auth_type
    profile["updated_at"] = _now()


def set_role_login_workflow(profile: dict, role: str, login_workflow_id: str | None) -> None:
    """Which saved recording (`GET /api/workflows`) this role's login
    replays -- only meaningful when the role's `auth_type` is
    `"recorded_workflow"`, but stored regardless so switching a role
    back and forth between login methods doesn't lose the choice.
    Mirrors `set_role_totp_secret`'s exact shape: `None` (omitted)
    leaves whatever's configured untouched, `""` explicitly clears it,
    any other value sets/replaces it. No-op for a role that doesn't
    exist (nothing to attach a workflow choice to)."""
    if login_workflow_id is None:
        return
    entry = _find_role_entry(profile, role)
    if entry is not None:
        entry["login_workflow_id"] = login_workflow_id or None
        profile["updated_at"] = _now()


def remove_role(profile: dict, role: str) -> dict | None:
    """Drops a role entry entirely -- the UI's per-role "Remove" action.
    Returns the removed entry (its `id` is what a caller needs to
    address the matching `.env` keys, though this project's existing
    convention -- see `set_role_credentials`'s own `username=""` branch
    above -- is to leave an orphaned `.env` value in place rather than
    delete it, since `password_set`/`totp_secret_set` being gone from
    the profile is what actually stops it from ever being read again).
    `None` if no such role existed on this profile."""
    entry = _find_role_entry(profile, role)
    if entry is None:
        return None
    profile["roles"] = [r for r in profile.get("roles", []) if r is not entry]
    profile["updated_at"] = _now()
    return entry


def mark_password_set(profile: dict, role: str) -> None:
    entry = _find_role_entry(profile, role)
    if entry is not None:
        entry["password_set"] = True
        profile["updated_at"] = _now()


def set_role_totp_secret(profile: dict, role: str, totp_secret: str | None) -> None:
    """Sets/clears `role`'s TOTP-configured flag -- mirrors
    `mark_password_set`'s shape, but (unlike a password) TOTP is
    genuinely optional per account, so this also handles turning it
    back OFF. `totp_secret=None` (omitted from the request) leaves the
    flag untouched; `""` explicitly clears it (2FA turned off for this
    test account, or the operator made a mistake and wants to remove
    it); any other non-empty value marks it set. The caller is still
    responsible for writing the matching `.env` key via
    `totp_env_key()` -- this only updates the profile document, same
    division of responsibility as `set_role_credentials`/
    `mark_password_set`. No-op if the role doesn't exist (TOTP without
    a username to attach it to is meaningless)."""
    if totp_secret is None:
        return
    entry = _find_role_entry(profile, role)
    if entry is not None:
        entry["totp_secret_set"] = bool(totp_secret)
        profile["updated_at"] = _now()


def target_block(profile: dict) -> dict:
    """The exact shape `config.json`'s `target` key needs, derived from
    a profile -- written by the caller into `CONFIG_PATH` on
    activation. Selector overrides are included only when actually
    set, matching `TargetConfig`'s own "unset means auto-detect"
    philosophy (`stof/config/schema.py`)."""
    block: dict[str, Any] = {
        "base_url": profile["base_url"],
        "login_url": profile["login_url"],
        "requires_assisted_login": bool(profile.get("requires_assisted_login", False)),
    }
    for field in ("username_selector", "password_selector", "submit_selector", "crawler_exclude_patterns", "idor_candidate_ids"):
        if profile.get(field):
            block[field] = profile[field]
    return block


def testing_block(profile: dict) -> dict:
    """The fields of `config.json`'s `testing` block this profile owns.
    Merged into whatever's already there (not a full replace) by the
    caller, since `testing` may hold other keys this module doesn't
    know about."""
    return {
        "allow_state_changing_probes": bool(profile.get("allow_state_changing_probes", False)),
        "scan_intensity": profile.get("scan_intensity", "standard"),
    }


def user_entries(profile: dict) -> list[dict]:
    """The `users` list `config/users.json` needs for this profile's
    roles -- a role is included only if it has BOTH a username AND a
    password actually configured (single-account targets are normal
    and already supported: a fresh profile's `roles` list starts
    empty). Username alone is not enough: the entry always carries a
    `{{env:...}}` password token pointing at a per-role env var, and
    `stof.config.loader.load_users()` raises if that token can't
    resolve -- a role saved with only a username (a real, easy-to-hit
    state: a tester fills in what they know and saves, meaning to add
    the password moments later) would otherwise poison the WHOLE
    users.json, breaking every other already-fully-configured role
    along with it, not just leave its own entry out. Iterates
    `profile["roles"]` directly rather than a fixed admin/normal pair,
    so any number of roles with any free-text label works identically."""
    entries = []
    for r in profile.get("roles", []):
        username = r.get("username")
        if not username or not r.get("password_set"):
            continue
        entry = {
            "id": r["id"],
            "role": r["role"],
            "username": username,
            "password": f"{{{{env:{plain_env_var(r['role'])}}}}}",
            "auth_type": r.get("auth_type", "form_login"),
        }
        if r.get("totp_secret_set"):
            entry["totp_secret"] = f"{{{{env:{plain_totp_env_var(r['role'])}}}}}"
        if r.get("login_workflow_id"):
            entry["login_workflow_id"] = r["login_workflow_id"]
        entries.append(entry)
    return entries
