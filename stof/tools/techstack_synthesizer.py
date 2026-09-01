"""stof/tools — synthesizes the curated tech-stack summary from
httpx + nuclei output.

Produces exactly the requested shape (frontend/backend/server/language/
database/cdn/authentication/apis) plus fields needed to make "recon
category" complete: `waf`, `cms`, `javascript_libraries` (framework
fingerprinting conventionally separates "what serves the app" from
"what libraries the page loads"), and `confidence_notes` (fingerprinting
is inherently probabilistic -- database and CDN in particular are
usually inferred indirectly, not directly observed, and every field
here defaults to null/empty rather than guessing).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .httpx_runner import HttpxResult
    from .nuclei_runner import NucleiFinding

# tech string (lowercase substring match) -> (category, canonical display name).
# One table, one classification pass -- easier to extend/test than a
# separate dict per category.
_TECH_CLASSIFICATION: dict[str, tuple[str, str]] = {
    # frontend frameworks
    "react": ("frontend", "React"),
    "angular": ("frontend", "Angular"),
    "vue.js": ("frontend", "Vue.js"),
    "next.js": ("frontend", "Next.js"),
    "nuxt.js": ("frontend", "Nuxt.js"),
    "svelte": ("frontend", "Svelte"),
    # backend frameworks
    "spring boot": ("backend", "Spring Boot"),
    "spring": ("backend", "Spring"),
    "django": ("backend", "Django"),
    "flask": ("backend", "Flask"),
    "express": ("backend", "Express"),
    "laravel": ("backend", "Laravel"),
    "ruby on rails": ("backend", "Ruby on Rails"),
    "fastapi": ("backend", "FastAPI"),
    # web/app servers
    "nginx": ("server", "Nginx"),
    "apache tomcat": ("server", "Apache Tomcat"),
    "apache-coyote": ("server", "Apache Tomcat"),
    "apache": ("server", "Apache HTTP Server"),
    "microsoft-iis": ("server", "Microsoft IIS"),
    "iis": ("server", "Microsoft IIS"),
    "caddy": ("server", "Caddy"),
    "litespeed": ("server", "LiteSpeed"),
    "openresty": ("server", "OpenResty"),
    # languages/runtimes
    "java": ("language", "Java"),
    "php": ("language", "PHP"),
    "python": ("language", "Python"),
    "node.js": ("language", "Node.js"),
    "ruby": ("language", "Ruby"),
    "asp.net": ("language", ".NET"),
    "golang": ("language", "Go"),
    # CDN
    "cloudflare": ("cdn", "Cloudflare"),
    "akamai": ("cdn", "Akamai"),
    "fastly": ("cdn", "Fastly"),
    "amazon cloudfront": ("cdn", "Amazon CloudFront"),
    "azure cdn": ("cdn", "Azure CDN"),
    # WAF
    "waf detect": ("waf", "Generic/unidentified WAF"),
    "waf-detect": ("waf", "Generic/unidentified WAF"),
    "cloudflare waf": ("waf", "Cloudflare WAF"),
    "aws waf": ("waf", "AWS WAF"),
    "mod_security": ("waf", "ModSecurity"),
    # database (usually only surfaces via an error-message leak, not a header)
    "postgresql": ("database", "PostgreSQL"),
    "mysql": ("database", "MySQL"),
    "microsoft sql server": ("database", "Microsoft SQL Server"),
    "mongodb": ("database", "MongoDB"),
    "oracle": ("database", "Oracle DB"),
    "redis": ("database", "Redis"),
    # CMS
    "wordpress": ("cms", "WordPress"),
    "drupal": ("cms", "Drupal"),
    "joomla": ("cms", "Joomla"),
    # auth
    "jwt": ("authentication", "JWT"),
    "oauth2": ("authentication", "OAuth2"),
    "oauth": ("authentication", "OAuth2"),
    "saml": ("authentication", "SAML"),
    "openid": ("authentication", "OIDC"),
    "basic-auth": ("authentication", "Basic Auth"),
    # APIs
    "graphql": ("apis", "GraphQL"),
    "swagger": ("apis", "REST (OpenAPI/Swagger)"),
    "openapi": ("apis", "REST (OpenAPI/Swagger)"),
    "soap": ("apis", "SOAP"),
    "grpc": ("apis", "gRPC"),
    # JS libraries (client-side, separate from the serving framework)
    "jquery": ("javascript_library", "jQuery"),
    "bootstrap": ("javascript_library", "Bootstrap"),
}

_SINGLE_VALUE_CATEGORIES = ("frontend", "backend", "server", "language", "database", "cdn", "waf", "cms")
_LIST_CATEGORIES = ("authentication", "apis", "javascript_library")


@dataclass
class TechStackSummary:
    target: str
    scanned_at: str
    frontend: dict = field(default_factory=dict)  # {"framework": ..., "version": ...}
    backend: dict = field(default_factory=dict)  # {"framework": ..., "version": ...}
    server: str | None = None
    language: str | None = None
    database: str | None = None
    cdn: str | None = None
    waf: str | None = None
    cms: str | None = None
    authentication: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)
    javascript_libraries: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)  # which tool(s) actually contributed data
    confidence_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


_SORTED_CLASSIFICATION_KEYS = sorted(_TECH_CLASSIFICATION.keys(), key=len, reverse=True)


def classify_tech_items(tech_items: list[str]) -> dict[str, set[str]]:
    """Pure classification pass: every tech string -> its category
    bucket. Testable independent of any subprocess call.

    Keys are checked longest-first and stop at the first match per
    item: several signature keys are substrings of each other (e.g.
    "spring" is a substring of "spring boot"; "apache" is a substring
    of "apache-coyote", the real server string this project's own demo
    target reports), and without this, a single tech string could land
    in two conflicting buckets ("Spring" AND "Spring Boot")."""
    buckets: dict[str, set[str]] = {}
    for item in tech_items:
        lowered = item.lower()
        for key in _SORTED_CLASSIFICATION_KEYS:
            if key in lowered:
                category, label = _TECH_CLASSIFICATION[key]
                buckets.setdefault(category, set()).add(label)
                break
    return buckets


def synthesize_techstack(
    target: str,
    httpx_results: list["HttpxResult"] | None = None,
    nuclei_findings: list["NucleiFinding"] | None = None,
) -> TechStackSummary:
    httpx_results = httpx_results or []
    nuclei_findings = nuclei_findings or []

    tech_items: list[str] = []
    for r in httpx_results:
        tech_items.extend(r.tech)
        if r.webserver:
            tech_items.append(r.webserver)
    for f in nuclei_findings:
        # Prefer the specific matched value (e.g. "Apache-Coyote/1.1")
        # over the generic template name ("Apache Detection") -- see
        # NucleiFinding.extracted_results docstring for why. Only fall
        # back to `name` when the template didn't extract anything
        # (e.g. a WAF-detect match, which is inherently a yes/no signal).
        if f.extracted_results:
            tech_items.extend(f.extracted_results)
        else:
            tech_items.append(f.name)
        # Deliberately NOT tech_items.extend(f.tags): tags are broad
        # category labels ("apache", "tech", "discovery"), not specific
        # product identifiers -- a generic "apache" tag caused the same
        # dilution bug as the generic name did (see the test this
        # comment sits next to), just through a second path. `name`/
        # `extracted_results` already carry the real signal.

    buckets = classify_tech_items(tech_items)

    summary = TechStackSummary(target=target, scanned_at=datetime.now(timezone.utc).isoformat())
    summary.sources = [name for name, used in (("httpx", bool(httpx_results)), ("nuclei", bool(nuclei_findings))) if used]

    if "frontend" in buckets:
        summary.frontend = {"framework": sorted(buckets["frontend"])[0], "version": None}
    if "backend" in buckets:
        summary.backend = {"framework": sorted(buckets["backend"])[0], "version": None}
    summary.server = sorted(buckets["server"])[0] if "server" in buckets else None
    summary.language = sorted(buckets["language"])[0] if "language" in buckets else None
    summary.database = sorted(buckets["database"])[0] if "database" in buckets else None
    summary.cdn = sorted(buckets["cdn"])[0] if "cdn" in buckets else None
    summary.waf = sorted(buckets["waf"])[0] if "waf" in buckets else None
    summary.cms = sorted(buckets["cms"])[0] if "cms" in buckets else None
    summary.authentication = sorted(buckets.get("authentication", set()))
    summary.apis = sorted(buckets.get("apis", set()))
    summary.javascript_libraries = sorted(buckets.get("javascript_library", set()))

    if not summary.database:
        summary.confidence_notes.append(
            "database: not detected -- black-box DB fingerprinting normally needs an "
            "error-based leak (see stof.recon.misconfig_scanner) or a DB-specific probe, "
            "neither of which httpx/these nuclei tags attempt"
        )
    if not summary.cdn:
        summary.confidence_notes.append("cdn: not detected -- no CDN-identifying header/tech signature matched")
    if not summary.frontend:
        summary.confidence_notes.append("frontend: not detected -- page may be server-rendered with no JS framework, or the framework isn't in the signature table yet")
    if not summary.authentication:
        summary.confidence_notes.append("authentication: not detected from tech signatures -- cross-check stof.recon output or manual review of login flow")

    return summary
