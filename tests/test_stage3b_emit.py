"""Tests for `fw_audit.stage3b_claims.emit` — the deterministic
ClaimExtraction -> AnalysisReport expansion. This is the load-bearing test
file for Stage 3b: every emitted report MUST round-trip through
`AnalysisReport.model_validate_json` and MUST recover its `bin_id` via
`chunk_id.rpartition("#")`, exactly as Stage 4/5's discovery logic does."""

from __future__ import annotations

from fw_audit.common.claims import ClaimExtraction
from fw_audit.common.findings import AnalysisReport, Confidence, Decision
from fw_audit.stage3b_claims.emit import to_analysis_report, to_emitted_claim
from fw_audit.stage3b_claims.models import BinaryResolution, FunctionResolution

_RESOLVED_BINARY = BinaryResolution(bin_id="usr_sbin_httpd__a1b2c3", matched_on="basename")
_UNRESOLVED_BINARY = BinaryResolution(bin_id=None)
_RESOLVED_FUNCTION = FunctionResolution(function_name="formSetWanNonLogin", matched_on="exact")
_UNRESOLVED_FUNCTION = FunctionResolution(function_name=None)


def _claim(**overrides) -> ClaimExtraction:
    defaults = dict(
        claim_id="claim_001",
        title="Stack overflow in formSetWanNonLogin",
        category="memory_safety",
        cwe=["CWE-121"],
        cve_ids=["CVE-2024-99999"],
        binary_hint="httpd",
        function_hint="formSetWanNonLogin",
        security_condition="unchecked strcpy from POST body",
        claimed_severity="Critical",
        claimed_impact="Remote code execution",
        evidence_quote="strcpy(buf, request->body);",
        page_numbers=[7, 8],
    )
    defaults.update(overrides)
    return ClaimExtraction(**defaults)


def test_emitted_report_round_trips_through_analysis_report():
    report = to_analysis_report(
        _claim(),
        doc_stem="acme_report",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    raw = report.model_dump_json()
    back = AnalysisReport.model_validate_json(raw)
    assert back.chunk_id == report.chunk_id
    assert back.findings[0].finding_id == "claim_001"


def test_bin_id_recoverable_via_rpartition():
    report = to_analysis_report(
        _claim(),
        doc_stem="acme_report",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    recovered_bin_id = report.chunk_id.rpartition("#")[0]
    assert recovered_bin_id == "usr_sbin_httpd__a1b2c3"
    assert "#" in report.chunk_id


def test_decision_escalate_only_when_both_resolved():
    report = to_analysis_report(
        _claim(),
        doc_stem="doc",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    assert report.findings[0].decision == Decision.ESCALATE


def test_decision_context_required_when_binary_unresolved():
    report = to_analysis_report(
        _claim(),
        doc_stem="doc",
        ordinal=0,
        binary_resolution=_UNRESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    assert report.findings[0].decision == Decision.CONTEXT_REQUIRED


def test_decision_context_required_when_function_unresolved():
    report = to_analysis_report(
        _claim(),
        doc_stem="doc",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_UNRESOLVED_FUNCTION,
    )
    assert report.findings[0].decision == Decision.CONTEXT_REQUIRED


def test_decision_context_required_when_both_unresolved():
    report = to_analysis_report(
        _claim(),
        doc_stem="doc",
        ordinal=0,
        binary_resolution=_UNRESOLVED_BINARY,
        function_resolution=_UNRESOLVED_FUNCTION,
    )
    assert report.findings[0].decision == Decision.CONTEXT_REQUIRED


def test_confidence_is_never_confirmed_or_high():
    for br, fr in (
        (_RESOLVED_BINARY, _RESOLVED_FUNCTION),
        (_UNRESOLVED_BINARY, _UNRESOLVED_FUNCTION),
    ):
        report = to_analysis_report(
            _claim(), doc_stem="doc", ordinal=0, binary_resolution=br, function_resolution=fr
        )
        assert report.findings[0].confidence == Confidence.MEDIUM
        assert report.findings[0].confidence != Confidence.CONFIRMED
        assert report.findings[0].confidence != Confidence.HIGH


def test_unresolved_binary_gets_synthetic_bin_id_with_hash():
    report = to_analysis_report(
        _claim(binary_hint="mystery_daemon"),
        doc_stem="doc",
        ordinal=0,
        binary_resolution=_UNRESOLVED_BINARY,
        function_resolution=_UNRESOLVED_FUNCTION,
    )
    bin_id = report.chunk_id.rpartition("#")[0]
    assert bin_id.startswith("unresolved_")
    assert "mystery_daemon" in bin_id


def test_unresolved_binary_with_no_hint_still_produces_valid_chunk_id():
    report = to_analysis_report(
        _claim(binary_hint=""),
        doc_stem="doc",
        ordinal=0,
        binary_resolution=_UNRESOLVED_BINARY,
        function_resolution=_UNRESOLVED_FUNCTION,
    )
    assert "#" in report.chunk_id
    AnalysisReport.model_validate_json(report.model_dump_json())  # must not raise


def test_ordinal_changes_chunk_id_and_avoids_collision():
    r0 = to_analysis_report(
        _claim(claim_id="c0"),
        doc_stem="doc",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    r1 = to_analysis_report(
        _claim(claim_id="c1"),
        doc_stem="doc",
        ordinal=1,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    assert r0.chunk_id != r1.chunk_id


def test_chunk_id_ordinal_band_cannot_collide_with_stage3():
    # Stage 3's own ordinals are small (chunk.strategy.chunk_source starts
    # at 0 and a real run rarely exceeds a few hundred per binary) — the
    # 9000+ band must stay clear of that range.
    report = to_analysis_report(
        _claim(),
        doc_stem="doc",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    ordinal_str = report.chunk_id.rpartition("#")[-1]
    assert int(ordinal_str) >= 9000


def test_missing_context_notes_unresolved_binary():
    report = to_analysis_report(
        _claim(binary_hint="httpd"),
        doc_stem="doc",
        ordinal=0,
        binary_resolution=_UNRESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    assert any("httpd" in m for m in report.findings[0].missing_context)


def test_missing_context_notes_no_evidence():
    report = to_analysis_report(
        _claim(evidence_quote=""),
        doc_stem="doc",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    assert any("no code" in m.lower() for m in report.findings[0].missing_context)


def test_evidence_code_falls_back_to_placeholder_when_no_quote():
    report = to_analysis_report(
        _claim(evidence_quote=""),
        doc_stem="acme",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    code = report.findings[0].evidence_span.code
    assert "acme" in code
    assert "no code evidence" in code.lower()


def test_evidence_code_uses_verbatim_quote_when_present():
    report = to_analysis_report(
        _claim(evidence_quote="strcpy(buf, x);"),
        doc_stem="acme",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    assert report.findings[0].evidence_span.code == "strcpy(buf, x);"


def test_tags_include_provenance_and_cve():
    report = to_analysis_report(
        _claim(cve_ids=["CVE-2024-99999"]),
        doc_stem="acme",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    tags = report.findings[0].tags
    assert "external_claim" in tags
    assert "doc:acme" in tags
    assert "CVE-2024-99999" in tags
    assert "page:7" in tags


def test_why_not_false_positive_names_report_as_unverified():
    report = to_analysis_report(
        _claim(),
        doc_stem="acme",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    text = report.findings[0].why_not_false_positive.lower()
    assert "unverified" in text
    assert "acme" in text.lower()


def test_severity_impact_maps_from_claimed_severity_keyword():
    critical = to_analysis_report(
        _claim(claimed_severity="Critical"),
        doc_stem="d",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    low = to_analysis_report(
        _claim(claimed_severity="Low"),
        doc_stem="d",
        ordinal=1,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    assert critical.findings[0].severity.impact == 5
    assert low.findings[0].severity.impact == 2


def test_severity_impact_defaults_to_midpoint_for_unstated_severity():
    report = to_analysis_report(
        _claim(claimed_severity=""),
        doc_stem="d",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    assert report.findings[0].severity.impact == 3


def test_to_emitted_claim_wraps_report_correctly():
    report = to_analysis_report(
        _claim(),
        doc_stem="acme",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    global_id = f"{report.chunk_id}::{report.findings[0].finding_id}"
    emitted = to_emitted_claim(
        report, global_id=global_id, bin_id="usr_sbin_httpd__a1b2c3", binary_resolved=True
    )
    assert emitted.global_id == global_id
    assert emitted.chunk_id == report.chunk_id
    assert emitted.decision == "ESCALATE"
    assert emitted.binary_resolved is True
    # report_json must itself be a valid AnalysisReport.
    AnalysisReport.model_validate_json(emitted.report_json)


def test_one_finding_per_report():
    report = to_analysis_report(
        _claim(),
        doc_stem="d",
        ordinal=0,
        binary_resolution=_RESOLVED_BINARY,
        function_resolution=_RESOLVED_FUNCTION,
    )
    assert len(report.findings) == 1
