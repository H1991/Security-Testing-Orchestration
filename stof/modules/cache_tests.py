"""Layer 9 -- stof/modules/cache_tests.py: Web Cache Poisoning & Web
Cache Deception (TC-136).

Methodology grounded in PortSwigger's own research -- the source that
essentially defined the modern testing approach for both classes -- and
OWASP's WSTG-CACH test cases, per this project's own house convention
of citing the disclosed-methodology source in the module docstring
(see configuration_tests.py's CORS technique, csrf_tests.py's
token-not-bound-to-session technique).

TC-136.1 -- Web Cache Poisoning (PortSwigger "Practical Web Cache
Poisoning" / "Web Cache Poisoning" Web Security Academy topic): identify
a response that shows cache-indicating headers (Cache-Control,
X-Cache, Age, ETag), send a request carrying an "unkeyed" header
PortSwigger's research documents as commonly reflected-into-the-response
but NOT part of the cache key (X-Forwarded-Host, X-Forwarded-Scheme,
X-Forwarded-Proto) set to a harmless, unique STOF marker, check
whether that marker is reflected into the response body, and -- ONLY
then -- send a SECOND, separate, unmodified request and check whether
THAT response also carries the marker. Reflection in the first response
alone is necessary but not sufficient evidence (a target can reflect an
unkeyed header into a response no cache ever stores) -- only the second
request's own, independent observation of the marker is genuine
confirmation that a poisoned response was actually cached and served
back out.

TC-136.2 -- Web Cache Deception (PortSwigger "Web cache deception attack
research" / Web Security Academy "Web cache deception" topic): request a
discovered AUTHENTICATED, sensitive page with a static-resource-shaped
path suffix appended (/account.jsp/nonexistent.css) and check whether
the server ignores the suffix and returns the real authenticated content
AND whether that response looks cacheable -- the precondition PortSwigger's
research documents (a cache mistaking a dynamic, authenticated response
for a static asset because of its URL shape). Full confirmation -- the
same suffixed URL requested a SECOND time, anonymously, and found to
carry the first, authenticated request's content -- is the actual,
unambiguous evidence bar: an anonymous caller receiving another user's
authenticated content.

Both techniques send a request whose response a real shared cache in
front of the target could actually store and serve to a genuine,
unrelated visitor until that cache entry naturally expires -- a bigger,
more literal blast radius than any other state-changing technique built
so far in this project (which write to the tester's OWN account/session,
never something a stranger's browser could receive). Both are therefore
gated, uniformly and in their entirety (including the read-only
cache-header reconnaissance step), behind CacheTestConfig.
allow_state_changing_probes -- off by default, same convention as
CsrfTestConfig's (see that file's own docstring: "CSRF probing as a
whole is being treated as one engagement decision here, not something
to half-run"). The marker value used is a synthetic, .invalid-TLD
STOF-branded string (RFC 2606) that can never be mistaken for real
content and never carries anything beyond its own presence/absence.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding

from .base import VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.cache_tests")

# PortSwigger's own canonical "commonly reflected, rarely cache-keyed"
# header set (Practical Web Cache Poisoning research) -- small and
# high-signal, same "known-patterns" philosophy as this project's other
# curated lists (configuration_tests._ADMIN_PANEL_PATHS etc).
_UNKEYED_HEADERS: tuple[str, ...] = ("X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto")

# Cache-indicating response headers (OWASP WSTG-CACH-01's own check
# list) -- presence of ANY of these is the signal a cache sits in front
# of (or the origin itself caches) this response at all.
_CACHE_INDICATOR_HEADERS: tuple[str, ...] = ("cache-control", "x-cache", "age", "etag")

# Endpoint-path keywords marking an authenticated, sensitive page --
# narrow and reused only as a candidate filter, same shape as
# configuration_tests._SENSITIVE_PATH_KEYWORDS.
_SENSITIVE_PAGE_KEYWORDS: tuple[str, ...] = ("account", "profile", "dashboard", "settings", "billing")

# Static-resource-shaped suffixes -- exactly PortSwigger's own web cache
# deception PoC shape, a path segment a cache's own extension-based
# heuristic could plausibly mistake for a real static asset.
_DECEPTION_SUFFIXES: tuple[str, ...] = ("/nonexistent.css", "/nonexistent.js")


def _marker_value() -> str:
    """A synthetic, .invalid-TLD (RFC 2606 -- guaranteed never to
    resolve to anything real) STOF-branded marker, unique per probe --
    inert by construction, distinguishable from any real content, and
    never mistakeable for a genuine header/URL value."""
    return f"stof-cache-probe-{secrets.token_hex(6)}.invalid"


def _cache_indicator(headers: dict[str, str]) -> str | None:
    """Pure, directly-unit-testable evidence check: which (if any)
    cache-indicating header this response carries. Returns the header
    name on a hit, None if the response shows no cache signal at all
    -- the honest "no cache detected" case this whole module is built
    to SKIP cleanly on."""
    for name in _CACHE_INDICATOR_HEADERS:
        if headers.get(name):
            return name
    return None


def _body_fingerprint(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8", errors="ignore")).hexdigest()


def _find_cacheable_get_endpoint_urls(endpoints: list["Endpoint"], limit: int = 5) -> list[str]:
    urls = [e.url for e in endpoints if e.method.upper() == "GET"]
    return urls[:limit]


def _find_sensitive_authenticated_endpoint(endpoints: list["Endpoint"]) -> "Endpoint | None":
    """First discovered GET endpoint whose path looks like an
    authenticated account/profile-shaped page -- the narrow "sensitive
    page" candidate TC-136.2 needs. auth_required isn't relied upon
    alone (the crawler doesn't always observe it reliably), the path
    keyword is the real signal, same as configuration_tests._is_
    sensitive_path."""
    for endpoint in endpoints:
        if endpoint.method.upper() != "GET":
            continue
        lowered = endpoint.url.lower()
        if any(keyword in lowered for keyword in _SENSITIVE_PAGE_KEYWORDS):
            return endpoint
    return None


def _synthetic_endpoint(url: str) -> Endpoint:
    return Endpoint(url=url, method="GET", endpoint_type="api", auth_required=False)


@dataclass
class CacheTestConfig:
    base_url: str = ""
    test_role: str = "normal"
    # Off by default: both techniques send a request whose response a
    # real shared cache could store and serve to a genuine, unrelated
    # visitor -- a bigger blast radius than any other gated technique
    # in this project. See module docstring.
    allow_state_changing_probes: bool = False


class CacheTestsModule(VulnModule):
    module_id = "cache_tests"
    name = "Web Cache Poisoning & Web Cache Deception Tests"
    phase = 1

    def __init__(self, config: CacheTestConfig | None = None) -> None:
        self.config = config or CacheTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, technique_id: str, technique: str, status: str, detail: str,
                endpoint=None, finding: Finding | None = None) -> TestCaseResult:
        return self._make_result(
            test_id="TC-136", technique_id=technique_id, technique=technique,
            vuln_type="Web Cache Poisoning / Deception", status=status, detail=detail,
            role="unauthenticated", endpoint=endpoint, finding=finding,
        )

    def _target_url(self, endpoints: list["Endpoint"]) -> str:
        return self.config.base_url or (endpoints[0].url if endpoints else "")

    async def _find_cacheable_candidate(self, context, endpoints: list["Endpoint"], target_url: str) -> "tuple[str, str] | None":
        """Probes a small, bounded set of discovered GET endpoints (plus
        the bare target URL as a fallback) and returns the first
        (url, cache_header_name) pair that shows a cache-indicating
        response header. None means no cache signal was found
        anywhere probed -- the honest "likely no cache in front of this
        target" outcome, not a shortfall."""
        candidates = _find_cacheable_get_endpoint_urls(endpoints) or ([target_url] if target_url else [])
        for url in candidates:
            try:
                resp = await context.request.get(url, max_redirects=0)
            except Exception as exc:
                _log.warning(f"cache-header probe failed for {url}: {exc}")
                continue
            headers = {k.lower(): v for k, v in resp.headers.items()}
            indicator = _cache_indicator(headers)
            if indicator is not None:
                return url, indicator
        return None

    async def _technique_cache_poisoning(self, endpoints, session_pool, evidence) -> TestCaseResult:
        tid, technique = "TC-136.1", "Web cache poisoning via unkeyed header injection"
        vuln_type = "Web Cache Poisoning"
        if not self.config.allow_state_changing_probes:
            return self._result(
                tid, technique, SKIPPED,
                "cache poisoning probes could plant a response a real shared cache serves to an unrelated "
                "visitor and is disabled by default -- set CacheTestConfig.allow_state_changing_probes=True "
                "for an authorized engagement window",
            )

        target_url = self._target_url(endpoints)
        context = await session_pool.new_anonymous_context()
        try:
            candidate = await self._find_cacheable_candidate(context, endpoints, target_url)
            if candidate is None:
                return self._result(
                    tid, technique, SKIPPED,
                    f"none of {len(_find_cacheable_get_endpoint_urls(endpoints)) or 1} probed GET response(s) "
                    "carried a Cache-Control/X-Cache/Age/ETag header -- no evidence of a cache in front of this "
                    "target to test against",
                )
            url, indicator = candidate

            for header_name in _UNKEYED_HEADERS:
                marker = _marker_value()
                try:
                    poisoned_resp = await context.request.get(url, max_redirects=0, headers={header_name: marker})
                    poisoned_body = await poisoned_resp.text()
                except Exception as exc:
                    _log.warning(f"poisoning probe failed for {url} ({header_name}): {exc}")
                    continue

                if marker not in poisoned_body:
                    continue  # not reflected via this header -- try the next candidate header

                # Reflection alone is necessary but NOT sufficient
                # evidence (see module docstring) -- only a SEPARATE,
                # unmodified follow-up request observing the same
                # marker proves the poisoned response was actually
                # cached and served back out.
                try:
                    clean_resp = await context.request.get(url, max_redirects=0)
                    clean_body = await clean_resp.text()
                except Exception as exc:
                    _log.warning(f"cache-confirmation probe failed for {url}: {exc}")
                    continue

                if marker in clean_body:
                    finding = Finding(
                        module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=8.6,
                        endpoint=_synthetic_endpoint(url), user_role="unauthenticated",
                        request_raw=f"GET {url}\n{header_name}: {marker}",
                        response_raw=f"(cached, {indicator} present) second unmodified GET {url} -> body contains {marker!r}",
                        description=(
                            f"'{url}' (cache-indicating header: {indicator}) reflects an attacker-supplied "
                            f"'{header_name}' header into its response body, and that reflected value is still "
                            "present in a SEPARATE, completely unmodified follow-up request -- proving the "
                            "poisoned response was cached and served to a different, clean request."
                        ),
                        recommendation=(
                            "Exclude X-Forwarded-Host/X-Forwarded-Scheme/X-Forwarded-Proto (and any other "
                            "client-controllable header the origin reflects) from what the origin trusts when "
                            "generating response content, or include them in the cache key so a poisoned "
                            "variant can never be served to a request that didn't send them."
                        ),
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="cache-poisoning-confirmed") if evidence else []
                    return self._result(tid, technique, FAIL, finding.description, endpoint=_synthetic_endpoint(url), finding=finding)

            return self._result(
                tid, technique, PASS,
                f"'{url}' ({indicator} present) checked against {len(_UNKEYED_HEADERS)} commonly-unkeyed header(s); "
                "any reflection observed did not reappear in a separate, unmodified follow-up request",
            )
        finally:
            await context.close()

    async def _technique_cache_deception(self, endpoints, session_pool, evidence, session_manager=None) -> TestCaseResult:
        tid, technique = "TC-136.2", "Web cache deception via static-resource-shaped path suffix"
        vuln_type = "Web Cache Deception"
        if not self.config.allow_state_changing_probes:
            return self._result(
                tid, technique, SKIPPED,
                "cache deception probes could get a real shared cache to store and serve another user's "
                "authenticated content and is disabled by default -- set CacheTestConfig."
                "allow_state_changing_probes=True for an authorized engagement window",
            )

        sensitive_endpoint = _find_sensitive_authenticated_endpoint(endpoints)
        if sensitive_endpoint is None:
            return self._result(
                tid, technique, SKIPPED,
                "no discovered GET endpoint looked like an authenticated account/profile/dashboard-shaped page",
            )

        target_url = self._target_url(endpoints)
        try:
            _session, auth_context = await self._authenticated_context(
                session_manager, session_pool, self.config.test_role, target_url,
            )
        except KeyError:
            return self._result(tid, technique, SKIPPED, f"role '{self.config.test_role}' is not configured")
        except Exception as exc:
            return self._result(tid, technique, "ERROR", f"could not authenticate as '{self.config.test_role}': {exc}")

        real_probe = await self._probe_get(auth_context, sensitive_endpoint.url)
        if real_probe is None:
            return self._result(tid, technique, "ERROR", f"probe of '{sensitive_endpoint.url}' failed")
        real_status, real_body = real_probe
        if real_status != 200 or not real_body.strip():
            return self._result(tid, technique, PASS, f"'{sensitive_endpoint.url}' did not return authenticated content to check a suffixed variant against")
        real_fingerprint = _body_fingerprint(real_body)

        for suffix in _DECEPTION_SUFFIXES:
            suffixed_url = sensitive_endpoint.url + suffix
            suffixed_probe = await self._probe_get(auth_context, suffixed_url)
            if suffixed_probe is None:
                continue
            suffixed_status, suffixed_body = suffixed_probe
            if suffixed_status != 200 or _body_fingerprint(suffixed_body) != real_fingerprint:
                continue  # server didn't ignore the suffix -- not a deception precondition for this suffix

            try:
                headers_resp = await auth_context.request.get(suffixed_url, max_redirects=0)
            except Exception as exc:
                _log.warning(f"cache-header probe failed for {suffixed_url}: {exc}")
                continue
            headers = {k.lower(): v for k, v in headers_resp.headers.items()}
            indicator = _cache_indicator(headers)
            if indicator is None:
                continue  # precondition (ignored suffix) held, but no cache signal -- not exploitable evidence

            # Full confirmation: the SAME suffixed URL, requested a
            # SECOND time as a completely anonymous/unauthenticated
            # caller -- does IT receive the first, authenticated
            # request's real content?
            anon_context = await session_pool.new_anonymous_context()
            try:
                anon_probe = await self._probe_get(anon_context, suffixed_url)
            finally:
                await anon_context.close()

            if anon_probe is not None and anon_probe[0] == 200 and _body_fingerprint(anon_probe[1]) == real_fingerprint:
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                    endpoint=sensitive_endpoint, user_role=self.config.test_role,
                    request_raw=f"GET {suffixed_url} (authenticated as '{self.config.test_role}'), then a SEPARATE anonymous GET {suffixed_url}",
                    response_raw=f"({indicator} present) anonymous request received the same content as the authenticated request (body fingerprint {real_fingerprint[:12]}...)",
                    description=(
                        f"'{sensitive_endpoint.url}' ignores a static-resource-shaped path suffix ('{suffix}') and "
                        f"returns the real authenticated page ({indicator} present, cache-indicating). A completely "
                        "anonymous, separate request to that same suffixed URL received the same authenticated "
                        "content -- a real shared cache in front of this target would serve one user's "
                        "authenticated page to any other visitor."
                    ),
                    recommendation=(
                        "Configure the cache to key on the full, exact path (or only cache an explicit, "
                        "known static-asset allowlist) so a trailing path segment can never change what a "
                        "dynamic, authenticated response is stored/served under; ensure the origin itself "
                        "returns 404 for any unmatched sub-path instead of falling through to the real page."
                    ),
                )
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="cache-deception-confirmed") if evidence else []
                return self._result(tid, technique, FAIL, finding.description, endpoint=sensitive_endpoint, finding=finding)

            return self._result(
                tid, technique, PASS,
                f"'{sensitive_endpoint.url}{suffix}' ignores the suffix and looks cacheable ({indicator} present), "
                "but a separate anonymous request to the same URL did not receive the authenticated content",
            )

        return self._result(
            tid, technique, PASS,
            f"'{sensitive_endpoint.url}' checked against {len(_DECEPTION_SUFFIXES)} static-resource-shaped "
            "suffix(es); none both ignored the suffix and looked cacheable",
        )

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        results: list[TestCaseResult] = []
        results.append(await self._safe_result(
            self._technique_cache_poisoning(endpoints, session_pool, evidence),
            "TC-136", "TC-136.1", "Web cache poisoning via unkeyed header injection", "Web Cache Poisoning / Deception",
            role="unauthenticated",
        ))
        results.append(await self._safe_result(
            self._technique_cache_deception(endpoints, session_pool, evidence, session_manager=session_manager),
            "TC-136", "TC-136.2", "Web cache deception via static-resource-shaped path suffix", "Web Cache Poisoning / Deception",
            role=self.config.test_role,
        ))
        return results
