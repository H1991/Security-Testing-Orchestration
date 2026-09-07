"""Layer 9 — `stof/modules/file_upload_tests.py`: File Upload
(TC-099 "Malicious File Upload" / TC-100 "Unrestricted File Upload"),
grounded in OWASP WSTG-BUSL-08/-09.

Both techniques were an explicit, honest GAP in `config/testcases.json`
until now: they needed the crawler to actually detect
`<input type=file>` fields, which it never surfaced -- a form's file
input was just another named parameter, indistinguishable from a text
field. `stof/crawler/form_detector.py`'s `_input_locations()` closes
that gap by tagging a file input's `param_locations` entry as `"file"`
(extending the same free-string vocabulary `param_locations` already
uses for "query"/"body"/"header"/"cookie" -- additive-only, no schema
change), which is this module's only discovery mechanism.

Both techniques upload a REAL file to a discovered form -- a genuine
write action against the live target -- so, matching
`business_logic_tests.py`'s own convention for anything that isn't a
pure read, both are gated behind `allow_state_changing_probes`.

Deliberately bounded, matching this project's "candidate-detect, never
auto-exploit" line already drawn for RCE/DoS gadget chains
(`business_logic_tests.py`'s own module docstring): a FAIL here means
"the upload was accepted with no extension/type rejection signal," NOT
"STOF confirmed remote code execution." STOF never retrieves or
requests the uploaded file afterward to try to trigger it -- that would
be an actual exploitation step, not a detection one, and this project's
Phase 1 scope stays on the detection side of that line.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding

from ._idor_shared import _method_request_fn
from .base import VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from stof.engine.multi_session import SessionPool
    from stof.evidence.collector import EvidenceCollector
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.file_upload_tests")


def _find_file_upload_endpoint(endpoints: list[Endpoint]) -> "tuple[Endpoint, str] | None":
    """The crawler's own file-input tagging (`form_detector.py`'s
    `_input_locations()`) is the only signal this needs: the first
    discovered endpoint with at least one `param_locations` entry
    marked `"file"`, paired with that field's name. `None` if the
    crawler found no upload-capable form at all."""
    for endpoint in endpoints:
        for name, location in endpoint.param_locations.items():
            if location == "file":
                return endpoint, name
    return None


# TC-099.1: dangerous server-executable extensions disguised with a
# benign-looking Content-Type -- the exact bypass class WSTG-BUSL-08
# documents (a server that trusts client-supplied Content-Type/
# extension alone, never inspecting real content). Payload content is
# a harmless marker string, not a functional web shell -- STOF never
# attempts to retrieve/execute the uploaded file (see module docstring).
_DANGEROUS_EXTENSION_PAYLOADS: tuple[tuple[str, str, bytes], ...] = (
    ("stof-probe.php", "image/jpeg", b"stof-file-upload-probe"),
    ("stof-probe.phtml", "image/jpeg", b"stof-file-upload-probe"),
    ("stof-probe.jsp", "image/jpeg", b"stof-file-upload-probe"),
    ("stof-probe.asp", "image/jpeg", b"stof-file-upload-probe"),
)

# TC-100.1: double-extension bypass -- a filter inspecting only the
# LAST extension (or only the first) is unaware common web-server
# extension-matching configs will still execute the other one.
_DOUBLE_EXTENSION_PAYLOADS: tuple[tuple[str, str, bytes], ...] = (
    ("stof-probe.php.jpg", "image/jpeg", b"stof-file-upload-probe"),
    ("stof-probe.jpg.php", "image/jpeg", b"stof-file-upload-probe"),
)

_REJECTION_SIGNATURES: tuple[str, ...] = (
    "not allowed", "invalid file", "invalid extension", "not permitted",
    "file type", "unsupported", "rejected", "disallowed", "forbidden",
)


def _looks_accepted(status: int, body: str) -> bool:
    """Pure helper: an HTTP error status is an unambiguous rejection;
    a 200-shaped response containing a rejection-shaped word (an app
    that renders its own validation error on a 200 page, same
    convention `business_logic_tests.py`'s `_SIGNUP_REJECTION_SIGNATURES`
    already established) is also not a real acceptance."""
    if status >= 400:
        return False
    lowered = (body or "").lower()
    return not any(sig in lowered for sig in _REJECTION_SIGNATURES)


@dataclass
class FileUploadTestConfig:
    allow_state_changing_probes: bool = False


class FileUploadTestsModule(VulnModule):
    module_id = "file_upload_tests"
    name = "File Upload Tests"
    phase = 1

    def __init__(self, config: FileUploadTestConfig | None = None) -> None:
        self.config = config or FileUploadTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, technique_id: str, technique: str, status: str, detail: str,
                endpoint=None, finding: "Finding | None" = None) -> TestCaseResult:
        return self._make_result(
            test_id="TC-099", technique_id=technique_id, technique=technique,
            vuln_type="File Upload", status=status, detail=detail,
            role="unauthenticated", endpoint=endpoint, finding=finding,
        )

    def _gated_skip(self, technique_id: str, technique: str, reason: str) -> TestCaseResult:
        return self._result(technique_id, technique, SKIPPED,
                             f"{reason} -- set FileUploadTestConfig.allow_state_changing_probes=True for an authorized engagement window")

    async def _probe_upload(
        self, endpoints, session_pool, evidence, tid: str, technique: str, vuln_type: str,
        payloads: tuple[tuple[str, str, bytes], ...], severity: str, cvss: float, label: str,
    ) -> TestCaseResult:
        target = _find_file_upload_endpoint(endpoints)
        if target is None:
            return self._result(tid, technique, SKIPPED, "no <input type=file> form discovered by the crawler")
        endpoint, file_param = target
        if not self.config.allow_state_changing_probes:
            return self._gated_skip(tid, technique, "uploads a real file to a discovered form and is disabled by default")

        method = endpoint.method.upper() if endpoint.method.upper() in ("POST", "PUT") else "POST"
        context = await session_pool.new_anonymous_context()
        try:
            method_fn = _method_request_fn(context, method)
            for filename, mime, content in payloads:
                multipart = {p: "stof-file-upload-probe" for p in endpoint.parameters if p != file_param}
                multipart[file_param] = {"name": filename, "mimeType": mime, "buffer": content}
                try:
                    resp = await method_fn(endpoint.url, multipart=multipart, max_redirects=0)
                    body = await resp.text()
                except Exception as exc:
                    _log.warning(f"file upload probe failed for {filename} against {endpoint.url}: {exc}")
                    continue
                if _looks_accepted(resp.status, body):
                    finding = Finding(
                        module_id=self.module_id, vuln_type=vuln_type, severity=severity, cvss_score=cvss,
                        endpoint=endpoint, user_role="unauthenticated",
                        request_raw=f"{method} {endpoint.url} multipart file={filename} (Content-Type: {mime})",
                        response_raw=f"HTTP {resp.status}, no rejection signal",
                        description=(
                            f"Uploading '{filename}' (Content-Type: {mime}) to '{endpoint.url}' was accepted "
                            f"(HTTP {resp.status}) with no extension/type rejection signal. STOF did not attempt "
                            "to retrieve or execute the uploaded file to confirm actual code execution -- this "
                            "needs manual verification, but acceptance alone indicates missing server-side file "
                            "type validation."
                        ),
                        recommendation="Validate uploaded file content server-side (not just extension/declared Content-Type), store uploads outside the webroot or with execution disabled, and reject any filename whose extension (including a non-final one) matches an executable server-side handler.",
                        # The description above says so explicitly:
                        # "STOF did not attempt to retrieve or execute
                        # the uploaded file to confirm actual code
                        # execution -- this needs manual verification."
                        # Acceptance alone is a real, actionable signal
                        # (missing validation) but not a confirmed RCE.
                        confidence="likely",
                    )
                    finding.evidence_refs = await evidence.capture_raw(finding.request_raw, finding.response_raw, label=label) if evidence else []
                    return self._result(tid, technique, FAIL, finding.description, endpoint=endpoint, finding=finding)
            return self._result(tid, technique, PASS, f"{len(payloads)} upload probe(s) against '{endpoint.url}' all rejected or errored")
        finally:
            await context.close()

    async def _technique_dangerous_extension(self, endpoints, session_pool, evidence) -> TestCaseResult:
        return await self._probe_upload(
            endpoints, session_pool, evidence,
            "TC-099.1", "Malicious file upload accepted despite server-executable extension (WSTG-BUSL-08)",
            "File Upload -- Dangerous Extension Accepted", _DANGEROUS_EXTENSION_PAYLOADS, "High", 7.5,
            "file-upload-dangerous-extension",
        )

    async def _technique_double_extension(self, endpoints, session_pool, evidence) -> TestCaseResult:
        return await self._probe_upload(
            endpoints, session_pool, evidence,
            "TC-100.1", "Unrestricted file upload accepted via double-extension bypass (WSTG-BUSL-09)",
            "File Upload -- Double Extension Bypass Accepted", _DOUBLE_EXTENSION_PAYLOADS, "High", 7.5,
            "file-upload-double-extension",
        )

    async def run_techniques(
        self,
        endpoints: list["Endpoint"],
        session_manager: "SessionManager",
        session_pool: "SessionPool",
        evidence: "EvidenceCollector | None" = None,
    ) -> list[TestCaseResult]:
        results: list[TestCaseResult] = []
        for tid, technique, coro in (
            ("TC-099.1", "Malicious file upload accepted despite server-executable extension (WSTG-BUSL-08)", self._technique_dangerous_extension(endpoints, session_pool, evidence)),
            ("TC-100.1", "Unrestricted file upload accepted via double-extension bypass (WSTG-BUSL-09)", self._technique_double_extension(endpoints, session_pool, evidence)),
        ):
            results.append(await self._safe_result(coro, "TC-099", tid, technique, "File Upload", role="unauthenticated"))
        return results
