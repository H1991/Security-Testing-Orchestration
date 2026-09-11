"""Layer 9 — `stof/modules/vulnerable_components_tests.py`: Known-
Vulnerable and Outdated Components (TC-149), OWASP A06:2021 -- a real,
currently-uncovered OWASP Top 10 category. Every other module in this
codebase tests how the target's OWN code behaves; this one instead
checks WHICH third-party front-end libraries it ships and whether any
of them are versions with a publicly-known CVE, the same question
`retire.js` (RetireJS/retire.js, MIT license, the de-facto standard
tool for this: https://github.com/RetireJS/retire.js) exists to answer.

**Scope, stated honestly**: this is a small, curated, hand-verified set
of well-known client-side JS libraries and their known-bad version
ranges (jQuery, jQuery UI, Bootstrap, Lodash, Moment.js, Handlebars,
Underscore.js, and AngularJS's own end-of-life status) -- not a port of
retire.js's full multi-hundred-entry regex database. Matches this
project's own established convention (`configuration_tests.py`'s
SecLists-derived path lists, `tls_tests.py`'s sslyze-backed checks):
a small, cited, verifiable list beats an unmaintainable copy of
someone else's much larger one. Detection works two ways, cheapest
first: (1) the library's version is usually embedded directly in a
CDN-hosted `<script src>` URL (e.g.
`cdnjs.cloudflare.com/.../jquery/1.7.2/jquery.min.js`) -- zero extra
requests, just a regex over the page's own HTML; (2) for a
self-hosted/bundled file with no version in its URL, fetch the script
body (capped at a small number of extra fetches per scan --
`VulnerableComponentsConfig.max_content_fetches`) and look for the
version banner comment nearly every one of these libraries writes at
the top of its own minified/unminified build (e.g. `/*! jQuery v1.7.2
| ... */`).

**Candidate-detect, not auto-exploit** (this project's own established
line): a FAIL here means "this specific library version has a public,
named CVE" -- it does not attempt to actually trigger that CVE against
the target. That confirmation step (e.g. actually proving the jQuery
XSS fires) belongs to `xss_tests.py`'s own techniques, not this one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding

from .base import VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

_log = get_logger("modules.vulnerable_components_tests")

_TEST_ID = "TC-149"
_VULN_TYPE = "Known-Vulnerable and Outdated Component"

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


@dataclass
class LibrarySignature:
    name: str
    # Matches a version number directly out of a script URL/filename --
    # the common CDN-hosted case, no extra request needed.
    filename_re: "re.Pattern[str]"
    # Matches a version out of the script's own content (a version-
    # banner comment nearly every one of these libraries writes at the
    # top of its build) -- only tried when the filename itself carried
    # no version, and only within max_content_fetches' budget.
    banner_re: "re.Pattern[str] | None"
    # Versions >= this tuple are safe. `None` means the library itself
    # is flagged regardless of version (AngularJS: end-of-life, no
    # further patches will ever ship for ANY 1.x version).
    max_safe_version: tuple[int, ...] | None
    cves: tuple[str, ...]
    detail: str
    severity: str
    cvss: float


def _v(version_str: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version_str.split(".") if p.isdigit())


# Curated, hand-verified set -- see module docstring for why this isn't
# a larger, unmaintainable copy of retire.js's own database.
LIBRARY_SIGNATURES: tuple[LibrarySignature, ...] = (
    LibrarySignature(
        name="jQuery",
        # `/` matches a CDN's own version-as-path-segment convention
        # (cdnjs: `.../jquery/1.7.2/jquery.min.js`); `.`/`-` matches a
        # version embedded directly in the filename instead (jsDelivr/
        # Google Hosted Libraries: `jquery-1.7.2.min.js`). Only ever
        # `.search()`ed against the FULL url, not just the trailing
        # filename, so either convention is found.
        filename_re=re.compile(r"jquery[./-](\d+\.\d+\.\d+)", re.IGNORECASE),
        banner_re=re.compile(r"jQuery\s+v?(\d+\.\d+\.\d+)"),
        max_safe_version=_v("3.5.0"),
        cves=("CVE-2020-11022", "CVE-2020-11023"),
        detail="jQuery versions before 3.5.0 pass untrusted HTML strings from `.html()`/`.append()`/etc. through `.htmlPrefilter()` without sanitizing `<script>` tags first, enabling XSS if any of that HTML can be influenced by an attacker.",
        severity="Medium", cvss=6.1,
    ),
    LibrarySignature(
        name="jQuery UI",
        filename_re=re.compile(r"jquery-?ui[./-](\d+\.\d+\.\d+)", re.IGNORECASE),
        banner_re=re.compile(r"jQuery UI\s*-\s*v?(\d+\.\d+\.\d+)"),
        max_safe_version=_v("1.13.0"),
        cves=("CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184"),
        detail="jQuery UI versions before 1.13.0 are vulnerable to XSS via the `altField` option of the Datepicker widget and via certain `.position()`/`checkboxradio` values containing HTML.",
        severity="Medium", cvss=6.1,
    ),
    LibrarySignature(
        name="Bootstrap",
        filename_re=re.compile(r"bootstrap[./-](\d+\.\d+\.\d+)", re.IGNORECASE),
        banner_re=re.compile(r"Bootstrap\s+v?(\d+\.\d+\.\d+)"),
        max_safe_version=_v("4.1.2"),
        cves=("CVE-2018-14040", "CVE-2018-14041", "CVE-2018-14042"),
        detail="Bootstrap versions before 4.1.2 (and 3.x before 3.4.0) are vulnerable to XSS via the `data-target`/`data-container`/`collapse` attributes and the tooltip/popover `title`/`content` options when populated with untrusted input.",
        severity="Medium", cvss=6.1,
    ),
    LibrarySignature(
        name="AngularJS",
        filename_re=re.compile(r"(?:^|/)angular[./-](\d+\.\d+\.\d+)", re.IGNORECASE),
        banner_re=None,
        max_safe_version=None,  # EOL project -- every version is flagged, not a version-range check
        cves=(),
        detail="AngularJS (1.x) reached end-of-life in January 2022 -- Google will never release another security patch for it, at any version, including this one. Any vulnerability discovered in it from this point forward stays unpatched permanently.",
        severity="Medium", cvss=5.3,
    ),
    LibrarySignature(
        name="Lodash",
        filename_re=re.compile(r"lodash[./@-](\d+\.\d+\.\d+)", re.IGNORECASE),
        banner_re=re.compile(r"lodash\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE),
        max_safe_version=_v("4.17.21"),
        cves=("CVE-2021-23337", "CVE-2020-8203"),
        detail="Lodash versions before 4.17.21 are vulnerable to command injection via the `template` function and prototype pollution via `zipObjectDeep`/similar deep-merge functions, when given attacker-influenced input.",
        severity="High", cvss=7.2,
    ),
    LibrarySignature(
        name="Moment.js",
        filename_re=re.compile(r"moment[./@-](\d+\.\d+\.\d+)", re.IGNORECASE),
        banner_re=re.compile(r"moment\.js\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE),
        max_safe_version=_v("2.29.4"),
        cves=("CVE-2022-31129",),
        detail="Moment.js versions before 2.29.4 are vulnerable to Regular Expression Denial of Service (ReDoS) when parsing a long, attacker-controlled date string.",
        severity="Medium", cvss=5.3,
    ),
    LibrarySignature(
        name="Handlebars",
        filename_re=re.compile(r"handlebars[./@-](\d+\.\d+\.\d+)", re.IGNORECASE),
        banner_re=re.compile(r"handlebars\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE),
        max_safe_version=_v("4.7.7"),
        cves=("CVE-2021-23369", "CVE-2021-23383"),
        detail="Handlebars versions before 4.7.7 are vulnerable to remote code execution via crafted templates that escape the sandboxed template-compilation environment.",
        severity="Critical", cvss=9.1,
    ),
    LibrarySignature(
        name="Underscore.js",
        filename_re=re.compile(r"underscore[./@-](\d+\.\d+\.\d+)", re.IGNORECASE),
        banner_re=re.compile(r"Underscore\.js\s+(\d+\.\d+\.\d+)", re.IGNORECASE),
        max_safe_version=_v("1.12.1"),
        cves=("CVE-2021-23358",),
        detail="Underscore.js versions before 1.12.1 are vulnerable to remote code execution via the `template` function when the template source is influenced by attacker input.",
        severity="Critical", cvss=9.1,
    ),
)


@dataclass
class VulnerableComponentsConfig:
    base_url: str = ""
    library_signatures: tuple[LibrarySignature, ...] = field(default_factory=lambda: LIBRARY_SIGNATURES)
    # Bounds this technique's own request budget -- most real targets'
    # library versions are readable straight from the CDN URL with zero
    # extra requests; this cap only matters for self-hosted/bundled
    # scripts with no version in their filename, and keeps a page with
    # many such scripts from turning into an unbounded fetch spree.
    max_content_fetches: int = 8


def _synthetic_endpoint(url: str) -> Endpoint:
    return Endpoint(url=url, method="GET", endpoint_type="page", auth_required=False)


def _match_from_filename(url: str, sig: LibrarySignature) -> tuple[int, ...] | None:
    match = sig.filename_re.search(url)
    return _v(match.group(1)) if match else None


def _bare_name(name: str) -> str:
    """`"jQuery UI"` -> `"jqueryui"`, `"Moment.js"` -> `"moment"`,
    `"AngularJS"` -> `"angular"` (real angular.js filenames never carry
    the trailing "JS") -- a filename-shaped token for
    `_match_signature_for_url`'s own substring check, derived from the
    display name instead of a second hand-maintained name per
    signature."""
    token = name.lower().replace(" ", "").replace(".js", "")
    return token.removesuffix("js")


class VulnerableComponentsModule(VulnModule):
    module_id = "vulnerable_components_tests"
    name = "Known-Vulnerable Component Tests"
    phase = 1

    def __init__(self, config: VulnerableComponentsConfig | None = None) -> None:
        self.config = config or VulnerableComponentsConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, status: str, detail: str, finding: Finding | None = None) -> TestCaseResult:
        return self._make_result(
            test_id=_TEST_ID, technique_id=_TEST_ID, technique="Known-vulnerable JavaScript library in use",
            vuln_type=_VULN_TYPE, status=status, detail=detail, role="unauthenticated", finding=finding,
        )

    def _target_url(self, endpoints: list[Endpoint]) -> str:
        return self.config.base_url or (endpoints[0].url if endpoints else "")

    def _extract_script_urls(self, page_url: str, html: str) -> list[str]:
        return [urljoin(page_url, src) for src in _SCRIPT_SRC_RE.findall(html)]

    def _match_signature_for_url(self, script_url: str) -> tuple[LibrarySignature, str] | None:
        """Which known library a script URL's filename names, regardless
        of whether a version was embedded in it -- a URL like
        `.../jquery.min.js` (no version in the path at all) still
        identifies the library by name, it just needs the content-banner
        fallback for the version itself."""
        filename = urlsplit(script_url).path.rsplit("/", 1)[-1]
        filename_lower = filename.lower()
        # Sorted longest-bare-name-first so "jqueryui" is checked (and
        # can win) before the more generic "jquery" -- otherwise every
        # jQuery UI URL would misclassify as plain jQuery, since
        # "jquery" is a substring of "jquery-ui.min.js" too.
        candidates = sorted(self.config.library_signatures, key=lambda s: -len(_bare_name(s.name)))
        for sig in candidates:
            if _bare_name(sig.name) in filename_lower:
                return sig, filename
        return None

    async def _fetch_banner_version(self, context, script_url: str, sig: LibrarySignature) -> tuple[int, ...] | None:
        if sig.banner_re is None:
            return None
        try:
            resp = await context.request.get(script_url, max_redirects=2, timeout=8000)
            if resp.status != 200:
                return None
            body = await resp.text()
        except Exception as exc:
            _log.debug(f"could not fetch '{script_url}' for version banner: {exc}")
            return None
        match = sig.banner_re.search(body[:2000])  # the banner is always near the top of the file
        return _v(match.group(1)) if match else None

    def _build_finding(self, script_url: str, sig: LibrarySignature, detected_version: tuple[int, ...] | None) -> Finding:
        version_str = ".".join(str(p) for p in detected_version) if detected_version else "unknown version"
        description = (
            f"'{script_url}' loads {sig.name} {version_str}. {sig.detail}"
            + (f" Known CVE(s): {', '.join(sig.cves)}." if sig.cves else "")
        )
        return Finding(
            module_id=self.module_id, vuln_type=_VULN_TYPE, severity=sig.severity, cvss_score=sig.cvss,
            endpoint=_synthetic_endpoint(script_url), user_role="unauthenticated",
            request_raw=f"GET {script_url}", response_raw=f"{sig.name} {version_str} identified via {'filename' if detected_version else 'content banner'}",
            description=description,
            recommendation=f"Upgrade {sig.name} to {'.'.join(str(p) for p in sig.max_safe_version) if sig.max_safe_version else 'a currently-maintained alternative'} or later.",
        )

    async def _evaluate_script(self, context, script_url: str, content_fetches_used: int) -> tuple[Finding | None, str | None, int]:
        """One script URL's own verdict: `(finding-or-None,
        checked-library-name-or-None, updated content_fetches_used)`.
        Split out of `run_techniques` purely to keep that method's own
        cyclomatic complexity below this project's B-rank gate -- no
        behavior change from the inline version."""
        matched = self._match_signature_for_url(script_url)
        if matched is None:
            return None, None, content_fetches_used
        sig, _filename = matched
        version = _match_from_filename(script_url, sig)
        if version is None and content_fetches_used < self.config.max_content_fetches:
            version = await self._fetch_banner_version(context, script_url, sig)
            content_fetches_used += 1

        is_vulnerable = sig.max_safe_version is None or (version is not None and version < sig.max_safe_version)
        if is_vulnerable:
            # EOL library (max_safe_version is None) is flagged regardless
            # of version, as long as filename matching confirmed it's THIS
            # library at all.
            return self._build_finding(script_url, sig, version), sig.name, content_fetches_used
        if version is not None:
            return None, sig.name, content_fetches_used  # a safe version was positively identified -- still "checked"
        return None, None, content_fetches_used

    async def _scan_script_urls(self, context, script_urls: list[str]) -> tuple[list[Finding], set[str]]:
        findings: list[Finding] = []
        checked_libraries: set[str] = set()
        content_fetches_used = 0
        for script_url in script_urls:
            finding, checked_name, content_fetches_used = await self._evaluate_script(context, script_url, content_fetches_used)
            if finding is not None:
                findings.append(finding)
            if checked_name is not None:
                checked_libraries.add(checked_name)
        return findings, checked_libraries

    async def run_techniques(self, endpoints, session_manager, session_pool, evidence=None) -> list[TestCaseResult]:
        url = self._target_url(endpoints)
        if not url:
            return [self._result(SKIPPED, "no target URL to fetch")]

        context = await session_pool.new_anonymous_context()
        try:
            try:
                resp = await context.request.get(url, max_redirects=2, timeout=10000)
                html = await resp.text()
            except Exception as exc:
                return [self._result("ERROR", f"could not fetch '{url}': {exc}")]

            script_urls = self._extract_script_urls(url, html)
            findings, checked_libraries = await self._scan_script_urls(context, script_urls)

            if not findings:
                note = f" ({', '.join(sorted(checked_libraries))} all on safe versions)" if checked_libraries else ""
                return [self._result(PASS, f"'{url}': no known-vulnerable JavaScript library version detected among {len(script_urls)} script(s) loaded{note}")]

            results = []
            for finding in findings:
                finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label="vulnerable-component") if evidence else []
                results.append(self._result(FAIL, finding.description, finding=finding))
            return results
        finally:
            await context.close()
