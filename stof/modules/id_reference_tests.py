"""TC-053.6 / TC-054.4 -- object-id classification and nested-reference
techniques, split out of `idor_tests.py` (grown back to 1,214 lines
after its earlier BFLA/Role/MassAssignment/Tenant splits, with three
methods sitting above the project's own C-rank complexity signal --
see `stof-enterprise-dev`'s "current complexity/duplication baseline"
rule: treat a method newly landing above C-rank ~15, or a file's MI
dropping below ~30, as the signal to extract before piling on more).

`IdReferenceTechniquesMixin` is composed into `IdorTestsModule` via
multiple inheritance, the same shape as `BFLATechniquesMixin`/
`RoleTechniquesMixin`/`MassAssignmentTechniquesMixin`/
`TenantTechniquesMixin` -- it has no `module_id`/`config`/
`authorization_matrix` of its own and isn't usable standalone. Both
techniques here only ever need the cross-cutting plumbing already on
`self` (`_result`, `_authenticated_context`, `_probe_candidates`,
`_object_ref_finding`, `_capture_evidence`, `self.config`,
`self.high_priv_role`), same as every other mixin in this family, so a
real module boundary (CLAUDE.md's no-cross-sibling-import rule) would
mean threading that plumbing through function parameters for no
benefit -- a mixin keeps the *file* split without adding a second
module identity.
"""
from __future__ import annotations

import asyncio

from stof.core.logger import get_logger
from stof.findings.models import Finding

from ._idor_shared import (
    _MIN_ID_PREDICTABILITY_SAMPLE,
    _collect_observed_ids,
    _content_fingerprint,
    _endpoint_candidate_ids,
    _extract_leaked_ids,
    _id_shape,
    _numeric_path_segment_indexes,
    _observed_path_segment_value,
    _set_path_segment,
)
from .results import FAIL, PASS, SKIPPED, TestCaseResult

_log = get_logger("modules.id_reference_tests")


class IdReferenceTechniquesMixin:
    def _technique_id_predictability_analysis(self, endpoints, base_findings: list[Finding] | None = None) -> list[TestCaseResult]:
        """TC-053.6 -- purely ANALYTICAL, zero new network requests,
        distinct from every ID-SUBSTITUTION technique in `idor_tests.py`
        (TC-053.1/.2/.4/.5 actually probe a candidate id and check
        access; this one only classifies the SHAPE of ids this scan
        already observed). Real-world grounding: this project's own
        knowledge base (`stof/payloads/idor_knowledge_base.json`,
        `direct_object_reference` family) already records that 60.8% of
        confirmed real-world direct-object-reference BOLA cases used
        plain sequential-integer identifiers -- the same pattern that
        makes ID-substitution IDOR attacks trivial to automate/enumerate
        at scale, independent of whether any single substitution attempt
        this scan made actually succeeded. OWASP's API3:2023 (Broken
        Object Level Authorization) names this same auto-increment-
        primary-key-as-external-id pattern as a contributing risk factor
        for exactly this reason. Reported as a contributing-risk FAIL,
        not a confirmed IDOR -- it never claims unauthorized access was
        observed, only that the id space is easy to enumerate.

        Two id sources, both already-observed data from this scan pass,
        neither costing a new request: (1) id-shaped path segments/
        query-param values already sitting in the discovered `endpoints`
        list, and (2) ids surfaced in `base_findings`' own request/
        response text -- e.g. TC-053.2's query-substitution finding
        names every distinct account id it confirmed, even though the
        crawler itself only discovered the bare `/bank/showAccount` URL
        with no query string at all. Source (2) matters in practice:
        without it, a target whose object ids only ever appear via
        substitution (never as a literal query value the crawler
        happened to see) would always SKIP here for lack of sample,
        despite the substitution techniques right above having just
        demonstrated the id space is a plain sequential range."""
        test_id, tid, technique = "TC-053", "TC-053.6", "Object-id predictability analysis (sequential/enumerable id scheme)"
        vuln_type = "Predictable/Sequential Object Identifiers"
        observed_ids = _collect_observed_ids(endpoints)
        finding_texts = [f"{f.request_raw}\n{f.response_raw}" for f in (base_findings or [])]
        for extra_id in _extract_leaked_ids(finding_texts, known=set(observed_ids), limit=50):
            observed_ids.append(extra_id)
        if len(observed_ids) < _MIN_ID_PREDICTABILITY_SAMPLE:
            return [self._result(
                test_id, tid, technique, vuln_type, SKIPPED,
                f"only {len(observed_ids)} id-shaped value(s) discovered on this target -- too few to draw a "
                f"conclusion about the id scheme (minimum sample size: {_MIN_ID_PREDICTABILITY_SAMPLE})",
            )]

        shapes = [_id_shape(i) for i in observed_ids]
        total = len(shapes)
        sequential = sum(1 for s in shapes if s == "sequential_int")
        random_shaped = sum(1 for s in shapes if s in ("uuid", "long_random_token"))
        sample = observed_ids[:5]
        if sequential / total > 0.5:
            description = (
                f"{sequential}/{total} object id(s) discovered on this target (sample: {sample}) are short, "
                "plain sequential/incrementing integers -- consistent with database auto-increment primary "
                "keys used directly as externally-visible identifiers. This does not by itself confirm an "
                "IDOR, but it dramatically lowers the bar for one: sequential ids are trivial to enumerate/"
                "automate at scale, the same real-world pattern behind 60.8% of confirmed direct-object-"
                "reference BOLA cases per this project's own knowledge base. Flag as a contributing risk "
                "factor even independent of any single confirmed IDOR finding on this scan."
            )
            # No new network request is made by this technique -- it is
            # purely re-classifying ids already discovered elsewhere in
            # the scan -- so there is no single "the" vulnerable
            # endpoint; `endpoints[0]` is attached only so the Finding
            # (which requires one) is anchored to this target/run.
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Info", cvss_score=0.0,
                endpoint=endpoints[0], user_role=self.high_priv_role,
                request_raw="(analytical -- no request sent)",
                response_raw=f"observed id sample: {sample} (id-shape classification only, {total} id(s) total)",
                description=description,
                recommendation=(
                    "Use non-sequential, unguessable identifiers (UUIDv4, cryptographically random tokens) "
                    "for any externally-visible object reference, in addition to (not instead of) enforcing "
                    "server-side object-level authorization."
                ),
                confidence="likely",  # contributing-risk signal, never claims unauthorized access was observed -- see this technique's own docstring
            )
            return [self._result(test_id, tid, technique, vuln_type, FAIL, description, role=self.high_priv_role, finding=finding)]
        if random_shaped / total > 0.5:
            return [self._result(
                test_id, tid, technique, vuln_type, PASS,
                f"{random_shaped}/{total} object id(s) discovered on this target (sample: {sample}) look like "
                "UUIDs or long random tokens rather than sequential integers -- not easily enumerable",
            )]
        return [self._result(
            test_id, tid, technique, vuln_type, PASS,
            f"object id(s) discovered on this target ({total} sampled: {sample}) are not predominantly "
            "sequential integers -- no clear enumerable id pattern",
        )]

    async def _technique_nested_object_reference(self, endpoints, session_manager, session_pool, target_url, evidence) -> list[TestCaseResult]:
        test_id, tid, technique = "TC-054", "TC-054.4", "Nested object reference inside a related sub-resource"
        vuln_type = "Missing Object-Level Authorization (BOLA) via nested reference"
        candidates = [(e, _numeric_path_segment_indexes(e.url)) for e in endpoints if e.method.upper() == "GET"]
        candidates = [(e, idxs) for e, idxs in candidates if len(idxs) >= 2]
        if not candidates:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, "no GET endpoint with 2+ numeric/UUID path segments discovered")]
        try:
            session, context = await self._authenticated_context(session_manager, session_pool, self.high_priv_role, target_url)
        except KeyError as exc:
            return [self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")]

        return list(await asyncio.gather(*(
            self._check_nested_object_reference_candidate(context, session, evidence, endpoint, idxs, test_id, tid, technique, vuln_type)
            for endpoint, idxs in candidates
        )))

    async def _check_nested_object_reference_candidate(
        self, context, session, evidence, endpoint, idxs, test_id: str, tid: str, technique: str, vuln_type: str,
    ) -> TestCaseResult:
        """Per-endpoint probe-and-check body of
        `_technique_nested_object_reference`'s loop, extracted so
        different endpoints can run concurrently."""
        outer_index = idxs[0]  # vary the outermost id, keep the inner (last) one fixed
        url_for = lambda cid, e=endpoint, i=outer_index: _set_path_segment(e.url, i, cid)
        observed = _observed_path_segment_value(endpoint.url, outer_index)
        endpoint_candidates = _endpoint_candidate_ids(observed, self.config.candidate_ids)
        responses, statuses, _control_fp = await self._probe_candidates(context, endpoint_candidates, url_for)
        distinct = {_content_fingerprint(b) for b in responses.values()}
        if len(responses) >= 2 and len(distinct) >= 2:
            finding = self._object_ref_finding(
                endpoint, self.high_priv_role, "outer path segment", url_for, statuses, responses, vuln_type, 8.1,
                description=(
                    f"'{endpoint.url}' has a nested object reference (2+ id-shaped path segments); varying the outer "
                    f"segment across {list(responses.keys())[:3]} while keeping the inner one fixed still returned "
                    f"{len(responses)} distinct objects, for role '{self.high_priv_role}'."
                ),
                recommendation="Verify ownership of the OUTER object in a nested resource path too, not only the innermost one.",
            )
            sample_id = next(iter(responses.keys()))
            finding.evidence_refs = await self._capture_evidence(evidence, context, session, url_for(sample_id), label=f"idor-nested-{sample_id}", finding=finding)
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, role=self.high_priv_role, endpoint=endpoint, finding=finding)
        return self._result(test_id, tid, technique, vuln_type, PASS, f"'{endpoint.url}': varying the outer path segment returned no distinct objects", role=self.high_priv_role, endpoint=endpoint)
