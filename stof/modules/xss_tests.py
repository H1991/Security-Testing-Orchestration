"""Layer 9 — `stof/modules/xss_tests.py`: Reflected Cross-Site
Scripting (TC-128).

Wave 2's second injection module, sharing `_injection_shared.py` with
`sqli_tests.py` (candidate discovery, benign param filling, request
dispatch) -- not `_idor_shared.py`, per this project's own rule against
reaching into a sibling authorization-family's private helpers for an
unrelated oracle shape.

Safety boundary, matching `sqli_tests.py`'s own: this module is
signal-only, response-inspection detection, never a real exploit.
- Every payload embeds a **unique, per-run-random marker**
  (`stofxss<8 hex chars>`, generated once per module instance --
  matching how `crawler.py`'s own placeholder-data tags are randomized
  per run) so a hit can never be confused with a previous scan's
  leftover reflected data still sitting in some cached/logged
  response.
- Every payload's JS side effect is a harmless `confirm(...)` call
  (the same "auto-dismissible dialog, never a real state change"
  precedent `crawler.py`'s own form-submission probing already
  established for `window.confirm`/`alert`) -- never a `fetch()`
  call, a DOM-mutation-persisting write, or anything with a
  persistent/stored side effect. Stored XSS (submit as one role, view
  as another) is explicitly deferred -- it needs a submit-then-view
  workflow this project doesn't have yet, a natural fit for a future
  role-play/session wave, not this one.
- Detection is **response-inspection only**, never actually rendered
  in a browser: a Finding here means "this marker reflected unencoded
  in a position that looks executable," not "STOF confirmed the
  script actually ran." `reflects_unencoded()`'s own docstring explains
  why a byte-for-byte match on the special characters (not a bare
  substring search for the marker alone) is the real signal, and why
  an HTML-comment position is excluded.

Three context variants, one `_technique_*` per sub-TC (same shape as
`graphql_tests.py`'s field-level/object-level split): a raw HTML-body
tag injection (TC-128.1), an HTML-attribute quote breakout
(TC-128.2), and an inline-script/event-handler string breakout
(TC-128.3) -- so different injection contexts are actually exercised,
not just one payload shape repeated.

**TC-128.5 DOM-based XSS**: a fifth technique, and the one genuine
exception to this module's own response-inspection-only safety
boundary above -- grounded in `stof/payloads/xss_knowledge_base.json`'s
`dom_based_xss` pattern (disclosed `location.hash`-into-jQuery-selector
reports, Uber/legacy-Twitter precedent). A DOM XSS sink
(`location.hash`/`location.search` fed into `innerHTML`/
`document.write`/a client-side router) may never even reach the
server -- a URL fragment is never sent in an HTTP request at all -- so
response-body inspection cannot detect this class structurally. This
technique instead navigates a REAL Playwright `Page` (obtained the same
way `crawler.py`'s own form-submission probing gets one: an
authenticated `BrowserContext.new_page()`, never `context.request.*`)
to a bounded set of discovered GET endpoint URLs, once with the marker
payload appended as `location.hash` and once as a `location.search`
value, with a `page.on('dialog')` listener registered BEFORE each
navigation -- the exact same auto-dismiss-and-record pattern
`crawler.py`'s own dialog handling already established for this
codebase, just repurposed here as a genuine-execution oracle instead of
a "was the page blocked" diagnostic. A FAIL is reported only when a
dialog actually fires AND its message contains this run's own unique
marker: real, unambiguous proof of script execution, not a signal
merely consistent with one. No `allow_state_changing_probes` gate is
needed -- navigation alone is read-only, same as TC-128.1-.3.

**TC-128.4 stored XSS**: a fourth, two-act plant/verify technique --
grounded in `stof/payloads/xss_knowledge_base.json`'s `stored_xss`
pattern (disclosed GitLab/Autodesk/X reports, and a 2025 disclosure
where an unfiltered stored payload escalated a low-priv account to
full Organization Admin takeover). A marker payload is planted into a
free-text-shaped POST field (comment/feedback/etc.) via a low-priv
authenticated context, then a SEPARATE, higher-privileged
authenticated context checks whether a DIFFERENT, likely-privileged
GET endpoint later reflects that same marker unencoded when it reads
the stored value back -- reusing `reflects_unencoded()` unchanged, the
exact same unencoded-reflection oracle TC-128.1-.3 already use, just
checked at a different endpoint/time/role than the plant. Same
plant/verify shape as `sqli_tests.py`'s TC-127.6 (whose
`_second_order_plant_candidates`/`_second_order_verify_candidates`
helpers -- promoted to `_injection_shared.py` for exactly this reuse
-- this technique calls directly), and the same
`allow_state_changing_probes` gate every other write-verb technique in
this codebase uses for its real POST. Detection stays response-
inspection only, matching this module's own safety boundary above: a
Finding here means "a marker planted at one endpoint reflected
unencoded at a different endpoint/role later," never a claim that
script execution was actually confirmed in a browser.
"""
from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from stof.core.logger import get_logger
from stof.findings.models import Finding
from stof.payloads.generators import StaticValueGenerator
from stof.payloads.models import ProbeContext
from stof.payloads.registry import PayloadRegistry

from ._injection_shared import (
    _second_order_plant_candidates,
    _second_order_verify_candidates,
    build_params,
    injectable_endpoints,
    send_probe,
)
from .base import VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from stof.crawler.endpoint_store import Endpoint
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.xss_tests")

_HTML_COMMENT_OPEN, _HTML_COMMENT_CLOSE = "<!--", "-->"

# TC-128.5 fallback query parameter name when a discovered endpoint has
# no known parameters to reuse -- one of the most commonly
# client-side-echoed parameter names in the real disclosed DOM XSS
# reports `xss_knowledge_base.json` cites (a "welcome, {name}"-shaped
# echo, or a search box that renders its own query client-side).
_DOM_XSS_DEFAULT_PARAM = "q"

# TC-128.8: installed via `page.add_init_script()` BEFORE navigation --
# wraps two real DOM/storage sinks to record every call made with a
# value containing this run's marker, without altering their actual
# behavior (each wrapper still calls the original function). Never
# calls a sink itself; only observes what the target's OWN client-side
# JS does with the marker once it's in location.hash/location.search.
_DOM_SINK_INSTRUMENT_SCRIPT = """
(() => {
  window.__stofDomSinks = [];
  const origSetItem = Storage.prototype.setItem;
  Storage.prototype.setItem = function (key, value) {
    window.__stofDomSinks.push({ sink: 'storage.setItem', value: String(value) });
    return origSetItem.apply(this, arguments);
  };
  const origSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    window.__stofDomSinks.push({ sink: 'setAttribute:' + name, value: String(value) });
    return origSetAttribute.apply(this, arguments);
  };
})();
"""


def _url_with_hash(url: str, payload: str) -> str:
    """`url` with `payload` set as its `location.hash` (replacing any
    existing fragment) -- never sent to the server at all, exactly the
    DOM XSS source this technique targets."""
    scheme, netloc, path, query, _fragment = urlsplit(url)
    return urlunsplit((scheme, netloc, path, query, payload))


def _url_with_search(url: str, param: str, payload: str) -> str:
    """`url` with `payload` set as the value of query parameter
    `param` (added, or replacing an existing same-named parameter),
    preserving every other existing query parameter and the fragment."""
    scheme, netloc, path, query, fragment = urlsplit(url)
    params = dict(parse_qsl(query, keep_blank_values=True))
    params[param] = payload
    return urlunsplit((scheme, netloc, path, urlencode(params), fragment))


def _is_hash_route_url(url: str) -> bool:
    """True when `url`'s fragment looks like a client-side route
    (`#/...`, or Angular's older `#!/...` hashbang form) rather than a
    plain in-page anchor -- same "#/"/"#!/" convention
    `stof.crawler.crawler` already established for exactly this signal,
    reimplemented locally rather than imported (`modules` doesn't
    import from `crawler`; see CLAUDE.md's layering rules)."""
    _, _, fragment = url.partition("#")
    return fragment.startswith(("/", "!/"))


def _url_with_hash_query(url: str, param: str, payload: str) -> str:
    """`url` with `payload` set as query parameter `param` INSIDE the
    hash fragment, route path left intact -- what a hash-routed SPA's
    own client-side router actually reads (Angular's classic
    `HashLocationStrategy`: `#/search?q=...`), which is neither of the
    other two DOM injection points: outright replacing the fragment
    (`_url_with_hash`) destroys the route path so the app never even
    renders the vulnerable view, and the real `location.search` (`_url_
    with_search`) is never populated by the browser during a pure
    hash-route navigation in the first place -- confirmed live against
    this project's own Juice Shop benchmark target, whose real,
    documented DOM XSS in its search view was completely unreachable by
    either of the other two variants."""
    scheme, netloc, path, query, fragment = urlsplit(url)
    frag_path, _, frag_query = fragment.partition("?")
    params = dict(parse_qsl(frag_query, keep_blank_values=True))
    params[param] = payload
    return urlunsplit((scheme, netloc, path, query, f"{frag_path}?{urlencode(params)}"))


def _dom_injection_points(endpoint: "Endpoint", param: str, payload: str) -> "list[tuple[str, str]]":
    """Every place a DOM-sink technique (TC-128.5/.6/.8) should try
    planting `payload` for this endpoint -- shared so the three
    techniques stay in sync on what "every reasonable DOM injection
    point" means, rather than drifting via three independently-edited
    copies of the same tuple list."""
    points = [
        ("location.hash", _url_with_hash(endpoint.url, payload)),
        ("location.search", _url_with_search(endpoint.url, param, payload)),
    ]
    if _is_hash_route_url(endpoint.url):
        points.append(("location.hash route query", _url_with_hash_query(endpoint.url, param, payload)))
    return points


def reflects_unencoded(body: str, payload: str) -> bool:
    """True if `payload` appears in `body` byte-for-byte.

    The special characters (`<`, `>`, `"`, `'`) every payload template
    in this module relies on to be executable are exactly the
    characters a correctly HTML-encoding application would replace
    (`&lt;`, `&gt;`, `&quot;`, `&#x27;`) before reflecting untrusted
    input -- a literal, unescaped match therefore already proves the
    app failed to encode this specific input, which is the real
    signal; a bare "does the marker substring appear anywhere" check
    would also fire on a *safely* HTML-entity-encoded reflection
    (`&lt;svg onload=...&gt;` still contains the marker text), which
    is exactly the false positive this project's own detection-quality
    rule (baseline/control diffing before reporting a hit) exists to
    avoid elsewhere. Also excludes a match sitting inside an HTML
    comment -- reflected verbatim but inert, the one common position a
    bare substring check would otherwise misreport as exploitable."""
    idx = body.find(payload)
    if idx == -1:
        return False
    before = body[:idx]
    return before.rfind(_HTML_COMMENT_OPEN) <= before.rfind(_HTML_COMMENT_CLOSE)


@dataclass
class XssTestConfig:
    low_priv_role: str = "normal"
    target_url: str | None = None
    # (endpoint, param) pairs probed per technique -- same reasoning
    # as `SqliTestConfig.max_probe_targets`: bounds total request
    # volume against a real target (O(endpoints x params)).
    max_probe_targets: int = 15
    # TC-128.4 -- bounded plant-phase and verify-phase candidate counts;
    # total probe volume is bounded at their product (see
    # `_technique_stored_xss`'s own docstring), same naming convention
    # and same default (3x3=9) as `SqliTestConfig`'s own TC-127.6 caps.
    max_second_order_plant_targets: int = 3
    max_second_order_verify_targets: int = 3
    # TC-128.5 -- bounded discovered-endpoint count for the DOM XSS
    # real-browser-navigation technique; each candidate is probed twice
    # (location.hash, then location.search), so total probe volume is
    # bounded at 2x this value (default 5 -> 10 max navigations), same
    # resilience-first capping convention as every other technique here.
    max_dom_xss_targets: int = 5
    # The verify phase reads back stored content through a SEPARATE,
    # higher-privileged authenticated context (the real "admin reviews
    # submitted content" shape from the disclosed reports in
    # `xss_knowledge_base.json`) -- defaults to "admin" the same way
    # `SqliTestConfig.high_priv_role` does.
    high_priv_role: str = "admin"
    # Gates TC-128.4's plant phase's real POST -- same convention every
    # other write-verb technique in this codebase already uses
    # (`SqliTestConfig`/`IdorTestConfig`/`CsrfTestConfig`). Wired from
    # `config.testing.allow_state_changing_probes` in `main.py`'s
    # `_build_module_builders()`.
    allow_state_changing_probes: bool = False


class XssTestsModule(VulnModule):
    module_id = "xss_tests"
    name = "Reflected Cross-Site Scripting Tests"
    phase = 1

    def __init__(self, config: XssTestConfig | None = None) -> None:
        self.config = config or XssTestConfig()
        # Unique per module instance (== per scan run, since the
        # registry constructs one fresh instance per `stof scan`) --
        # see module docstring for why this must never be a fixed
        # literal.
        self._marker = f"stofxss{secrets.token_hex(4)}"
        self.payload_registry = PayloadRegistry()
        self._register_payloads()

    def _payload_templates(self) -> dict[str, str]:
        marker = self._marker
        return {
            # Raw HTML body: a self-contained tag, no breakout needed --
            # fires immediately if reflected into an unescaped body position.
            "TC-128.1": f"<svg onload=confirm('{marker}')>",
            # HTML attribute breakout: closes the attacker-controlled
            # attribute's quote, then adds a fresh event-handler attribute.
            "TC-128.2": f'" onmouseover=confirm(\'{marker}\') data-stof="',
            # Inline-script/event-handler string breakout: closes a
            # single-quoted JS string literal, calls confirm(), then
            # comments out the rest of the original statement.
            "TC-128.3": f"');confirm('{marker}');//",
            # TC-128.4 stored -- a self-contained tag (no breakout
            # needed, same shape as TC-128.1), matching the "unfiltered
            # <img> payload" real pattern from `xss_knowledge_base.json`'s
            # 2025 disclosure. Planted once into a stored field rather
            # than reflected same-request.
            "TC-128.4": f"<img src=x onerror=confirm('{marker}')>",
            # TC-128.5 DOM XSS -- same self-contained <img onerror> shape
            # as the real 2025 disclosure pattern in
            # `xss_knowledge_base.json`, appended to `location.hash`/
            # `location.search` rather than sent as a request param;
            # fires on genuine in-browser execution, caught via
            # `page.on('dialog')`, not response inspection.
            "TC-128.5": f"<img src=x onerror=confirm('{marker}')>",
            # TC-128.7 CSS injection -- closes an attribute-context CSS
            # value and injects a fresh rule with a uniquely-tagged
            # exfiltration-shaped url() (a `.invalid` marker host, never
            # dispatched anywhere -- same "marker host, never a real
            # exploit" precedent as TC-137.7/TC-128.6's redirect
            # markers). Reuses the exact same byte-for-byte-unencoded-
            # reflection oracle as TC-128.2's attribute breakout: the
            # underlying gap (unencoded reflection allowing a context
            # breakout) is identical, only the injected content differs.
            "TC-128.7": f"';}}*{{background:url(https://stof-css-{marker}.invalid/)}}/*",
            # TC-128.9 HTML Injection -- deliberately no script/event-
            # handler content at all, unlike every other payload in this
            # module: a target that specifically strips `<script>` tags
            # and `on*=` attributes (a common, narrow WAF/filter
            # pattern) can still fail to HTML-encode output at all,
            # letting plain markup like this render -- content
            # spoofing/defacement/phishing via injected links or forms,
            # a real, separately-tracked finding class distinct from
            # script execution. Reuses the exact same byte-for-byte-
            # unencoded-reflection oracle as every other TC-128.x
            # technique; only the payload shape (and resulting
            # vuln_type) differs.
            "TC-128.9": f"<b>stof-html-injection-{marker}</b>",
        }

    def _register_payloads(self) -> None:
        for testcase_id, payload in self._payload_templates().items():
            self.payload_registry.register_all(list(
                StaticValueGenerator(testcase_id, "reflected_marker", (payload,), contexts=("query", "form")).generate()
            ))

    def _payload_for(self, testcase_id: str) -> str:
        context = ProbeContext(testcase_id=testcase_id, location="query")
        return str(self.payload_registry.for_context(context)[0].value)

    def _result(
        self, technique_id: str, technique: str, status: str, detail: str,
        role: "str | None" = None, endpoint=None, finding: "Finding | None" = None,
        vuln_type: str = "Reflected Cross-Site Scripting",
    ) -> TestCaseResult:
        return self._make_result(
            test_id="TC-128", technique_id=technique_id, technique=technique,
            vuln_type=vuln_type, status=status, detail=detail,
            role=role, endpoint=endpoint, finding=finding,
        )

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _param_candidates(self, endpoints: "list[Endpoint]") -> list[tuple["Endpoint", str, str]]:
        candidates: list[tuple[Endpoint, str, str]] = []
        for endpoint in injectable_endpoints(endpoints):
            for name in endpoint.parameters:
                candidates.append((endpoint, name, endpoint.location_for(name)))
        return candidates

    async def _technique_reflection(
        self, technique_id: str, technique_name: str, context_label: str,
        candidates: list[tuple["Endpoint", str, str]], context, evidence: "EvidenceCollector | None",
        vuln_type: str = "Reflected Cross-Site Scripting",
        severity: str = "High", cvss_score: float = 6.1,
        side_effect_note: str = (
            "and its only side effect is a harmless confirm() dialog tagged with this run's own random marker"
        ),
    ) -> TestCaseResult:
        """Shared body for all three context-variant techniques --
        each `_technique_*` wrapper below just supplies its own
        testcase id / human-readable name / context label and defers
        here, so the probe-sweep-and-check loop exists exactly once."""
        if not candidates:
            return self._result(technique_id, technique_name, SKIPPED, "no query/body parameter discovered to probe")

        payload = self._payload_for(technique_id)
        bounded = candidates[: self.config.max_probe_targets]
        for endpoint, param, location in bounded:
            probe = await send_probe(context, endpoint, build_params(endpoint, param, payload), location)
            if probe is None:
                continue
            status, body, _elapsed, _headers = probe
            if not reflects_unencoded(body, payload):
                continue
            description = (
                f"Injecting a uniquely-tagged marker payload into parameter '{param}' ({location}) "
                f"on {endpoint.method} {endpoint.url} reflected byte-for-byte unencoded in the "
                f"response (HTTP {status}), in a position consistent with {context_label} -- the "
                "application did not HTML-encode this input before reflecting it. This is a "
                "response-inspection signal only: the payload was never rendered in a real browser "
                f"to confirm actual script execution, {side_effect_note}."
            )
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity=severity, cvss_score=cvss_score,
                endpoint=endpoint, user_role=self.config.low_priv_role,
                request_raw=f"{endpoint.method} {endpoint.url}\n{param}={payload!r}",
                response_raw=body[:300],
                description=description,
                recommendation="HTML-encode all untrusted output at the point it's rendered (context-aware encoding for HTML body, attribute, and script/event-handler positions); do not rely on input validation alone.",
            )
            finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"xss-{technique_id}-{param}") if evidence else []
            return self._result(technique_id, technique_name, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding, vuln_type=vuln_type)
        return self._result(
            technique_id, technique_name, PASS,
            f"{len(bounded)} parameter(s) probed with a {context_label} marker payload, no unencoded reflection observed",
            role=self.config.low_priv_role,
        )

    async def _technique_stored_xss(
        self,
        endpoints: "list[Endpoint]",
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        """Two-act plant/verify technique (see the module docstring and
        `xss_knowledge_base.json`'s `stored_xss` pattern): plant a
        marker payload into a free-text field via a low-priv POST,
        then check whether a DIFFERENT, likely-privileged GET endpoint
        later reflects that same marker unencoded when read back
        through a SEPARATE, higher-privileged authenticated context.
        Exact template of `sqli_tests.py`'s `_technique_second_order`
        (TC-127.6): same promoted `_second_order_plant_candidates`/
        `_second_order_verify_candidates` helpers, same
        `max_second_order_plant_targets x max_second_order_verify_targets`
        bound (default 3x3=9), same `allow_state_changing_probes` gate
        on the plant phase's real POST -- only the verify-phase oracle
        differs: `reflects_unencoded()` (the same check TC-128.1-.3
        already use) instead of a SQL-error fingerprint."""
        tid, technique = "TC-128.4", "Stored Cross-Site Scripting (planted marker, cross-endpoint/role verification)"
        if not self.config.allow_state_changing_probes:
            return self._result(tid, technique, SKIPPED, "allow_state_changing_probes is disabled -- the plant phase requires a real POST", vuln_type="Stored Cross-Site Scripting")

        plant_candidates = _second_order_plant_candidates(endpoints, self.config.max_second_order_plant_targets)
        verify_candidates = _second_order_verify_candidates(endpoints, self.config.max_second_order_verify_targets)
        if not plant_candidates:
            return self._result(tid, technique, SKIPPED, "no discovered POST form has a free-text-shaped field (comment/message/feedback/subject/notes/name/body) to plant a payload into", vuln_type="Stored Cross-Site Scripting")
        if not verify_candidates:
            return self._result(tid, technique, SKIPPED, "no discovered endpoint looks like a privileged display/admin page to verify against", vuln_type="Stored Cross-Site Scripting")

        payload = self._payload_for(tid)
        try:
            _plant_session, plant_context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, plant_candidates[0][0].url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.low_priv_role}' not configured: {exc}", vuln_type="Stored Cross-Site Scripting")
        try:
            _verify_session, verify_context = await self._authenticated_context(session_manager, session_pool, self.config.high_priv_role, verify_candidates[0].url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.high_priv_role}' not configured: {exc}", vuln_type="Stored Cross-Site Scripting")

        for plant_endpoint, plant_field in plant_candidates:
            params = build_params(plant_endpoint, plant_field, payload)
            location = plant_endpoint.location_for(plant_field)
            plant_probe = await send_probe(plant_context, plant_endpoint, params, location)
            if plant_probe is None:
                continue
            for verify_endpoint in verify_candidates:
                verify_probe = await self._probe_get(verify_context, verify_endpoint.url)
                if verify_probe is None:
                    continue
                verify_status, verify_body = verify_probe
                if not reflects_unencoded(verify_body, payload):
                    continue
                description = (
                    f"Planted a uniquely-tagged marker payload into field '{plant_field}' via "
                    f"{plant_endpoint.method} {plant_endpoint.url} (as role '{self.config.low_priv_role}'); "
                    f"a SEPARATE, later GET request to {verify_endpoint.url} (as role "
                    f"'{self.config.high_priv_role}') reflected that same marker byte-for-byte "
                    f"unencoded in its response (HTTP {verify_status}) -- evidence the previously "
                    "planted value was stored and later rendered, unescaped, for a different "
                    "endpoint/role. This is a response-inspection signal only: the payload was "
                    "never rendered in a real browser to confirm actual script execution, and its "
                    "only side effect is a harmless confirm() dialog tagged with this run's own "
                    "random marker."
                )
                finding = Finding(
                    module_id=self.module_id, vuln_type="Stored Cross-Site Scripting", severity="Critical", cvss_score=8.8,
                    endpoint=verify_endpoint, user_role=self.config.high_priv_role,
                    request_raw=(
                        f"PLANT: {plant_endpoint.method} {plant_endpoint.url}\n{plant_field}={payload!r}\n"
                        f"VERIFY: GET {verify_endpoint.url}"
                    ),
                    response_raw=verify_body[:300],
                    description=description,
                    recommendation="HTML-encode all untrusted output at the point it's rendered, on every endpoint that displays stored content -- not just the endpoint it was submitted through; do not rely on input validation alone.",
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="xss-stored") if evidence else []
                return self._result(tid, technique, FAIL, description, role=self.config.high_priv_role, endpoint=verify_endpoint, finding=finding, vuln_type="Stored Cross-Site Scripting")
        return self._result(
            tid, technique, PASS,
            f"{len(plant_candidates)} free-text field(s) planted, {len(verify_candidates)} privileged "
            "endpoint(s) checked afterward, no unencoded reflection of the planted marker observed",
            role=self.config.high_priv_role, vuln_type="Stored Cross-Site Scripting",
        )

    def _dom_xss_candidates(self, endpoints: "list[Endpoint]") -> "list[Endpoint]":
        """Discovered GET page/form endpoints -- capped at
        `max_dom_xss_targets`, same discovery-order capping convention
        as `_param_candidates`/`_second_order_plant_candidates`. Unlike
        the reflected/stored techniques, a parameter isn't required
        here: `location.hash` needs none at all, and `location.search`
        falls back to `_DOM_XSS_DEFAULT_PARAM` when the endpoint has no
        discovered parameter of its own -- a DOM sink reading
        `location.search` client-side is very often on a page the
        crawler discovered with no server-side query parameter at
        all."""
        candidates = [e for e in endpoints if e.method.upper() == "GET"]
        return candidates[: self.config.max_dom_xss_targets]

    async def _navigate_and_check_dialog(self, page, url: str, timeout_ms: int = 10000) -> "str | None":
        """Navigates `page` to `url` with a `page.on('dialog')`
        listener registered BEFORE the navigation -- the standard
        Playwright pattern (same one `crawler.py`'s own form-submission
        probing already uses) for safely observing a triggered
        `confirm()`/`alert()`/`prompt()` without ever letting it block:
        the dialog is dismissed the instant it's seen, inside the
        listener itself, before `goto()` (or anything after it) can
        hang waiting on it. Returns the dialog's message, or `None` if
        no dialog fired. A short settle delay after `goto()` gives an
        `onload`/`hashchange`-driven DOM sink a chance to run its JS
        before the listener is torn down -- `goto()`'s own
        "load" wait covers `<img onerror>` firing during initial
        render, but a script that reacts to `location.hash` via a
        `hashchange` listener (a real pattern from the disclosed
        reports) can fire slightly after "load".

        `goto()`'s own `timeout_ms` isn't trusted as the only bound: a
        real hang was observed in this sandbox where `goto()` never
        returned or raised at all (a flaky-network `ERR_NETWORK_CHANGED`
        navigation landing right as a dialog was in flight left the CDP
        connection stuck, silently blocking the whole scan for hours --
        the same failure class `main.py`'s own `_with_retry` docstring
        already documents for this target, except that wrapper only
        covers whole-module runs, not a single probe inside this
        technique's per-endpoint loop). Wrapping the call in
        `asyncio.wait_for` with a hard external deadline guarantees this
        method always returns within a bounded time, whatever Playwright
        itself does internally."""
        captured: list[str] = []

        async def _on_dialog(dialog) -> None:
            captured.append(dialog.message)
            await dialog.dismiss()

        page.on("dialog", _on_dialog)
        try:
            try:
                await asyncio.wait_for(page.goto(url, timeout=timeout_ms), timeout=(timeout_ms / 1000) + 5)
            except Exception as exc:
                _log.warning(f"DOM XSS probe navigation failed for {url}: {exc}")
                return None
            await asyncio.sleep(0.3)
            return captured[0] if captured else None
        finally:
            page.remove_listener("dialog", _on_dialog)

    async def _technique_dom_xss(
        self,
        endpoints: "list[Endpoint]",
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        """TC-128.5 -- see the module docstring for why this is the one
        technique here that navigates a real browser `Page` instead of
        inspecting a raw HTTP response: a `location.hash` payload is
        never sent to the server at all, so response inspection cannot
        detect this class structurally. A FAIL requires an actually
        triggered dialog whose message contains this run's own unique
        marker -- proof of real script execution, not a signal merely
        consistent with one."""
        tid, technique = "TC-128.5", "DOM-based Cross-Site Scripting (real in-browser execution confirmation)"
        candidates = self._dom_xss_candidates(endpoints)
        if not candidates:
            return self._result(tid, technique, SKIPPED, "no GET page endpoint discovered to navigate to", vuln_type="DOM-based Cross-Site Scripting")

        payload = self._payload_for(tid)
        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, candidates[0].url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.low_priv_role}' not configured: {exc}", vuln_type="DOM-based Cross-Site Scripting")

        page = await context.new_page()
        probes_run = 0
        try:
            for endpoint in candidates:
                param = endpoint.parameters[0] if endpoint.parameters else _DOM_XSS_DEFAULT_PARAM
                for injection_point, probe_url in _dom_injection_points(endpoint, param, payload):
                    probes_run += 1
                    message = await self._navigate_and_check_dialog(page, probe_url)
                    if message is None or self._marker not in message:
                        continue
                    description = (
                        f"Navigating a real browser to {probe_url} with the marker payload placed in "
                        f"{injection_point} triggered a real confirm() dialog whose message "
                        f"({message!r}) contains this run's own unique marker -- genuine, confirmed "
                        "in-browser script execution, not a response-inspection signal. The dialog "
                        "was auto-dismissed immediately and had no other effect."
                    )
                    finding = Finding(
                        module_id=self.module_id, vuln_type="DOM-based Cross-Site Scripting", severity="High", cvss_score=6.1,
                        endpoint=endpoint, user_role=self.config.low_priv_role,
                        request_raw=f"GET {probe_url}",
                        response_raw=f"triggered dialog message: {message!r}",
                        description=description,
                        recommendation="Never pass location.hash/location.search (or any other client-controlled value) into innerHTML, document.write, eval, or a jQuery selector without HTML-encoding/sanitizing it first; prefer safe DOM APIs (textContent, createElement) for rendering untrusted client-side data.",
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"xss-dom-{injection_point}") if evidence else []
                    return self._result(tid, technique, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding, vuln_type="DOM-based Cross-Site Scripting")
        finally:
            await page.close()
        return self._result(
            tid, technique, PASS,
            f"{probes_run} navigation(s) across {len(candidates)} endpoint(s) (location.hash and location.search) "
            "with a real browser, no dialog fired containing this run's marker",
            role=self.config.low_priv_role, vuln_type="DOM-based Cross-Site Scripting",
        )

    async def _navigate_and_check_redirect(self, page, url: str, marker_host: str, timeout_ms: int = 10000) -> bool:
        """Same hang-safety discipline as `_navigate_and_check_dialog`
        (external `asyncio.wait_for` deadline, `goto()` failures logged
        and swallowed, never let a single probe block the whole scan) --
        but the signal here is where the browser ENDS UP after
        navigating, not a dialog. A DOM-based open redirect fires when
        client-side JS reads `location.hash`/`location.search` and
        assigns it straight into `location.href`/`.assign()`/`.replace()`
        with no validation -- there's no server round-trip to inspect at
        all, so (like TC-128.5's DOM XSS) the only way to detect this is
        to actually navigate a real browser and watch what it does."""
        try:
            await asyncio.wait_for(page.goto(url, timeout=timeout_ms), timeout=(timeout_ms / 1000) + 5)
        except Exception as exc:
            _log.warning(f"DOM open-redirect probe navigation failed for {url}: {exc}")
            return False
        await asyncio.sleep(0.3)
        return marker_host in urlsplit(page.url).netloc

    async def _technique_dom_open_redirect(
        self,
        endpoints: "list[Endpoint]",
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        """TC-128.6 -- DOM-based Open Redirect (CWE-601), added after
        cross-referencing a real Burp Active Scan run against this
        target and finding no STOF equivalent for Burp's own "Open
        redirection (DOM-based)" finding. Distinct from TC-137.7 in
        `ssrf_tests.py` (a SERVER-side redirect via the HTTP `Location`
        response header) -- this one has no server round-trip at all,
        reusing TC-128.5's exact "navigate a real browser, observe what
        actually happens" model since a client-side-only sink is
        structurally invisible to response inspection."""
        tid, technique = "TC-128.6", "DOM-based Open Redirect (real in-browser navigation confirmation)"
        vuln_type = "DOM-based Open Redirect"
        candidates = self._dom_xss_candidates(endpoints)
        if not candidates:
            return self._result(tid, technique, SKIPPED, "no GET page endpoint discovered to navigate to", vuln_type=vuln_type)

        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, candidates[0].url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.low_priv_role}' not configured: {exc}", vuln_type=vuln_type)

        page = await context.new_page()
        probes_run = 0
        try:
            for endpoint in candidates:
                marker_host = f"stof-dom-redirect-{secrets.token_hex(5)}.invalid"
                marker_url = f"https://{marker_host}/"
                param = endpoint.parameters[0] if endpoint.parameters else _DOM_XSS_DEFAULT_PARAM
                for injection_point, probe_url in _dom_injection_points(endpoint, param, marker_url):
                    probes_run += 1
                    if await self._navigate_and_check_redirect(page, probe_url, marker_host):
                        description = (
                            f"Navigating a real browser to {probe_url} with an external marker URL placed in "
                            f"{injection_point} caused the browser to actually navigate to that external host "
                            f"({marker_host}) -- confirmed client-side redirect with no server round-trip "
                            "involved at all."
                        )
                        finding = Finding(
                            module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=6.1,
                            endpoint=endpoint, user_role=self.config.low_priv_role,
                            request_raw=f"GET {probe_url}", response_raw=f"browser navigated to: https://{marker_host}/",
                            description=description,
                            recommendation="Never assign location.hash/location.search (or any client-controlled value) directly into location.href/.assign()/.replace(); validate against an explicit allowlist of same-origin/known-partner destinations first.",
                        )
                        finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=f"dom-open-redirect-{injection_point}") if evidence else []
                        return self._result(tid, technique, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding, vuln_type=vuln_type)
        finally:
            await page.close()
        return self._result(
            tid, technique, PASS,
            f"{probes_run} navigation(s) across {len(candidates)} endpoint(s) (location.hash and location.search) "
            "with a real browser, none redirected to the injected external marker host",
            role=self.config.low_priv_role, vuln_type=vuln_type,
        )

    async def _technique_dom_data_manipulation(
        self,
        endpoints: "list[Endpoint]",
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None",
    ) -> TestCaseResult:
        """TC-128.8 -- DOM Data Manipulation (CWE-79/CWE-915 family):
        the last of the "DOM-sink" categories cross-referenced against a
        real Burp Active Scan run (see TC-128.6's own note) with no STOF
        equivalent -- client-controlled data (location.hash/search)
        flowing into a sensitive DOM/storage sink WITHOUT necessarily
        executing script (TC-128.5's job) or causing navigation
        (TC-128.6's job). Detected the same "navigate a real browser,
        observe what actually happens" way those two already use, since
        this is equally invisible to response inspection -- but the
        observation itself is different: an `add_init_script()`
        installed BEFORE navigation wraps `Storage.prototype.setItem`
        and `Element.prototype.setAttribute` to record every call whose
        value contains this run's marker, then the sweep checks whether
        any were recorded. This never itself calls a dangerous API --
        it only observes calls the PAGE's own JS already makes."""
        tid, technique = "TC-128.8", "DOM Data Manipulation (client-controlled value reaches a storage/attribute sink)"
        vuln_type = "DOM Data Manipulation"
        candidates = self._dom_xss_candidates(endpoints)
        if not candidates:
            return self._result(tid, technique, SKIPPED, "no GET page endpoint discovered to navigate to", vuln_type=vuln_type)

        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, candidates[0].url)
        except KeyError as exc:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.low_priv_role}' not configured: {exc}", vuln_type=vuln_type)

        page = await context.new_page()
        await page.add_init_script(_DOM_SINK_INSTRUMENT_SCRIPT)
        probes_run = 0
        try:
            for endpoint in candidates:
                marker = f"stof-dom-sink-{secrets.token_hex(5)}"
                param = endpoint.parameters[0] if endpoint.parameters else _DOM_XSS_DEFAULT_PARAM
                for injection_point, probe_url in _dom_injection_points(endpoint, param, marker):
                    probes_run += 1
                    try:
                        await asyncio.wait_for(page.goto(probe_url, timeout=10000), timeout=15)
                    except Exception as exc:
                        _log.warning(f"DOM data-manipulation probe navigation failed for {probe_url}: {exc}")
                        continue
                    await asyncio.sleep(0.3)
                    sinks = await page.evaluate(
                        "(marker) => (window.__stofDomSinks || []).filter((s) => s.value && s.value.includes(marker))", marker,
                    )
                    if not sinks:
                        continue
                    hit = sinks[0]
                    description = (
                        f"Navigating a real browser to {probe_url} with a unique marker placed in {injection_point} "
                        f"caused the page's own client-side JS to write that marker into a '{hit['sink']}' sink "
                        f"(observed value: {hit['value']!r}) -- client-controlled data reaching a storage/DOM-"
                        "attribute sink without validation, confirmed by real in-browser observation."
                    )
                    finding = Finding(
                        module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.4,
                        endpoint=endpoint, user_role=self.config.low_priv_role,
                        request_raw=f"GET {probe_url}", response_raw=f"sink: {hit['sink']}, value: {hit['value']!r}",
                        description=description,
                        recommendation="Never write location.hash/location.search (or any client-controlled value) directly into localStorage/sessionStorage or a DOM element's attribute without validating/sanitizing it first -- treat it exactly as untrusted as any server-side input.",
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="dom-data-manipulation") if evidence else []
                    return self._result(tid, technique, FAIL, description, role=self.config.low_priv_role, endpoint=endpoint, finding=finding, vuln_type=vuln_type)
        finally:
            await page.close()
        return self._result(
            tid, technique, PASS,
            f"{probes_run} navigation(s) across {len(candidates)} endpoint(s) (location.hash and location.search) "
            "with a real browser, no marker value observed reaching a storage/setAttribute sink",
            role=self.config.low_priv_role, vuln_type=vuln_type,
        )

    async def run_techniques(
        self,
        endpoints: "list[Endpoint]",
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        technique_defs = (
            ("TC-128.1", "Reflected XSS in raw HTML body context", "an unescaped HTML body position"),
            ("TC-128.2", "Reflected XSS via HTML attribute breakout", "an HTML attribute breakout"),
            ("TC-128.3", "Reflected XSS via inline script/event-handler breakout", "an inline script/event-handler breakout"),
            ("TC-128.7", "CSS Injection via attribute-context breakout", "a CSS injection / attribute-context breakout"),
            ("TC-128.9", "HTML Injection via unencoded markup reflection", "an unescaped HTML body position (no script/event-handler content)"),
        )
        candidates = self._param_candidates(endpoints)
        stored_tid, stored_technique = "TC-128.4", "Stored Cross-Site Scripting (planted marker, cross-endpoint/role verification)"

        if not candidates:
            results = [self._result(tid, name, SKIPPED, "no query/body parameter discovered to probe") for tid, name, _label in technique_defs]
        else:
            target_url = self.config.target_url or candidates[0][0].url
            try:
                _session, context = await self._authenticated_context(session_manager, session_pool, self.config.low_priv_role, target_url)
            except KeyError as exc:
                reason = f"role '{self.config.low_priv_role}' not configured: {exc}"
                results = [self._result(tid, name, SKIPPED, reason) for tid, name, _label in technique_defs]
            else:
                results = []
                for tid, name, label in technique_defs:
                    extra_kwargs = {}
                    if tid == "TC-128.7":
                        vt = "CSS Injection"
                    elif tid == "TC-128.9":
                        # Medium, not the High every script-executing
                        # technique in this module uses: content
                        # spoofing/defacement via injected markup is a
                        # real but categorically lower-impact finding
                        # than confirmed script execution, and there's
                        # no confirm() dialog to mention since this
                        # payload deliberately carries none.
                        vt = "HTML Injection"
                        extra_kwargs = {
                            "severity": "Medium", "cvss_score": 4.1,
                            "side_effect_note": "this payload deliberately carries no script or event-handler content at all",
                        }
                    else:
                        vt = "Reflected Cross-Site Scripting"
                    results.append(await self._safe_result(
                        self._technique_reflection(tid, name, label, candidates, context, evidence, vuln_type=vt, **extra_kwargs),
                        "TC-128", tid, name, vt, role=self.config.low_priv_role,
                    ))

        # TC-128.4 runs independently of the same-request `candidates`
        # sweep above -- it needs a discovered POST form and a
        # discovered privileged GET endpoint, not a "query/body
        # parameter", and it manages its own (low-priv plant / high-priv
        # verify) authenticated contexts, same as `sqli_tests.py`'s
        # `_technique_second_order`.
        results.append(await self._safe_result(
            self._technique_stored_xss(endpoints, session_manager, session_pool, evidence),
            "TC-128", stored_tid, stored_technique, "Stored Cross-Site Scripting", role=self.config.low_priv_role,
        ))

        # TC-128.5 likewise runs independently -- it needs a discovered
        # GET page endpoint to navigate a real browser to, not a
        # "query/body parameter", and manages its own authenticated
        # context/page (see `_technique_dom_xss`'s own docstring for
        # why this is the one technique in this module that navigates
        # a real `Page` rather than inspecting a raw HTTP response).
        dom_tid, dom_technique = "TC-128.5", "DOM-based Cross-Site Scripting (real in-browser execution confirmation)"
        results.append(await self._safe_result(
            self._technique_dom_xss(endpoints, session_manager, session_pool, evidence),
            "TC-128", dom_tid, dom_technique, "DOM-based Cross-Site Scripting", role=self.config.low_priv_role,
        ))

        dom_redirect_tid, dom_redirect_technique = "TC-128.6", "DOM-based Open Redirect (real in-browser navigation confirmation)"
        results.append(await self._safe_result(
            self._technique_dom_open_redirect(endpoints, session_manager, session_pool, evidence),
            "TC-128", dom_redirect_tid, dom_redirect_technique, "DOM-based Open Redirect", role=self.config.low_priv_role,
        ))

        dom_data_tid, dom_data_technique = "TC-128.8", "DOM Data Manipulation (client-controlled value reaches a storage/attribute sink)"
        results.append(await self._safe_result(
            self._technique_dom_data_manipulation(endpoints, session_manager, session_pool, evidence),
            "TC-128", dom_data_tid, dom_data_technique, "DOM Data Manipulation", role=self.config.low_priv_role,
        ))
        return results
