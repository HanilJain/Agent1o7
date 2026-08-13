"""Tests for fw_audit.common.findings — Stage 3 Component 2's structured
vulnerability-finding schema.

The primary acceptance test here is `test_analysis_report_validates_the_spec_example`:
it round-trips the EXACT example JSON from the Component 2 task specification
through `AnalysisReport`. If that test passes, the schema faithfully
represents the required wire shape.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from fw_audit.common.findings import (
    AnalysisReport,
    CheckedCategory,
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)

# The exact example JSON from the Component 2 task specification.
_SPEC_EXAMPLE = {
    "chunk_id": "chunk_00421",
    "function_id": "FUN_00446000",
    "findings": [
        {
            "finding_id": "candidate_001",
            "title": "Potential stack buffer overflow through attacker-influenced copy length",
            "category": "memory_safety",
            "cwe": ["CWE-121", "CWE-787"],
            "severity": {"impact": 4, "exploitability": 3, "reachability": 3},
            "confidence": "HIGH",
            "decision": "ESCALATE",
            "tags": ["UNSAFE_OPERATION", "MEMORY_SAFETY", "BOUNDS_CHECK", "DATA_FLOW"],
            "evidence_span": {
                "function_id": "FUN_00446000",
                "line_start": 18,
                "line_end": 21,
                "code": (
                    "[L018] char local_40[32];\n[L019] len = get_length(param_1);\n"
                    "[L020] if (len > 0)\n[L021] memcpy(local_40, param_1, len);"
                ),
            },
            "source": {
                "expression": "param_1",
                "type": "FUNCTION_PARAMETER",
                "attacker_control": "UNKNOWN",
            },
            "sink": {"expression": "memcpy(local_40, param_1, len)", "type": "MEMORY_WRITE"},
            "data_flow": [
                "param_1 reaches get_length(param_1)",
                "returned length is assigned to len",
                "len controls memcpy write size",
                "memcpy writes into fixed 32-byte local_40",
            ],
            "security_condition": (
                "The destination is fixed at 32 bytes while the copy length is not "
                "visibly bounded by the destination size."
            ),
            "exploitability": (
                "The supplied chunk does not establish attacker control of param_1 or "
                "the maximum value returned by get_length(). CPG/caller analysis should "
                "determine both."
            ),
            "impact": (
                "If len can exceed 32, the operation may corrupt stack memory and "
                "potentially affect control data."
            ),
            "why_vulnerable": (
                "A variable-length memory write targets a fixed-size stack buffer "
                "without a visible destination-size constraint."
            ),
            "why_not_false_positive": (
                "The candidate is based on the concrete fixed destination size and "
                "absence of an in-chunk upper bound, rather than merely the presence "
                "of memcpy()."
            ),
            "missing_context": [
                "Semantics of get_length()",
                "Callers controlling param_1",
                "Potential compiler/decompiler type information affecting len",
            ],
            "recommended_next_analysis": [
                "Inspect get_length() in the CPG.",
                "Trace callers of FUN_00446000.",
                "Determine the maximum possible value of len.",
                "Verify whether any caller-side invariant constrains len <= 32.",
            ],
        }
    ],
    "checked_categories": [
        {
            "category": "command_execution",
            "status": "NOT_CONFIRMED",
            "reason": (
                "No execution sink receiving a suspicious value was identified "
                "in the supplied chunk."
            ),
        },
        {
            "category": "hardcoded_secret",
            "status": "NOT_CONFIRMED",
            "reason": (
                "No constant was identified with sufficient evidence of "
                "credential or cryptographic use."
            ),
        },
    ],
    "analysis_limitations": [
        "Caller and callee implementations were not available in this chunk."
    ],
}


def test_analysis_report_validates_the_spec_example():
    report = AnalysisReport.model_validate(_SPEC_EXAMPLE)

    assert report.chunk_id == "chunk_00421"
    assert report.function_id == "FUN_00446000"
    assert len(report.findings) == 1
    assert len(report.checked_categories) == 2
    assert len(report.analysis_limitations) == 1

    finding = report.findings[0]
    assert finding.finding_id == "candidate_001"
    assert finding.cwe == ["CWE-121", "CWE-787"]
    assert finding.severity == Severity(impact=4, exploitability=3, reachability=3)
    assert finding.confidence == Confidence.HIGH
    assert finding.decision == Decision.ESCALATE
    assert finding.evidence_span.line_start == 18
    assert finding.evidence_span.line_end == 21
    assert finding.source.attacker_control == "UNKNOWN"
    assert finding.sink.type == "MEMORY_WRITE"
    assert len(finding.data_flow) == 4

    assert report.checked_categories[0].category == "command_execution"
    assert report.checked_categories[0].status == "NOT_CONFIRMED"


def test_analysis_report_round_trips_through_json():
    report = AnalysisReport.model_validate(_SPEC_EXAMPLE)
    dumped = json.loads(report.model_dump_json())
    reparsed = AnalysisReport.model_validate(dumped)
    assert reparsed.findings[0].severity.impact == 4
    assert reparsed.findings[0].decision == Decision.ESCALATE


def test_severity_rejects_out_of_range_values():
    with pytest.raises(ValidationError):
        Severity(impact=0, exploitability=3, reachability=3)
    with pytest.raises(ValidationError):
        Severity(impact=6, exploitability=3, reachability=3)


def test_confidence_and_decision_reject_unknown_values():
    with pytest.raises(ValidationError):
        Finding.model_validate(
            {
                **_SPEC_EXAMPLE["findings"][0],
                "confidence": "SUPER_HIGH",
            }
        )
    with pytest.raises(ValidationError):
        Finding.model_validate(
            {
                **_SPEC_EXAMPLE["findings"][0],
                "decision": "MAYBE",
            }
        )


def test_analysis_report_validates_with_no_findings():
    # A sparse-but-valid response: an analyst that found nothing worth
    # escalating should still validate cleanly (default_factory=list).
    sparse = {
        "chunk_id": "chunk_00001",
        "checked_categories": [
            {
                "category": "command_execution",
                "status": "NOT_CONFIRMED",
                "reason": "Nothing suspicious found.",
            }
        ],
    }
    report = AnalysisReport.model_validate(sparse)
    assert report.findings == []
    assert report.function_id == ""
    assert report.analysis_limitations == []


def test_finding_category_and_tags_accept_free_form_values():
    # category/tags are deliberately free-form — the worker prompt says
    # "Do not limit analysis to predefined vulnerability classes".
    payload = {
        **_SPEC_EXAMPLE["findings"][0],
        "category": "firmware_update_logic_tampering",
        "tags": ["SOMETHING_NEW", "NOT_IN_ANY_ENUM"],
    }
    finding = Finding.model_validate(payload)
    assert finding.category == "firmware_update_logic_tampering"
    assert "SOMETHING_NEW" in finding.tags


def test_checked_category_minimal_shape():
    cc = CheckedCategory(category="ipc", status="NOT_APPLICABLE", reason="No IPC in this chunk.")
    assert cc.category == "ipc"


def test_evidence_span_and_source_sink_construct_directly():
    span = EvidenceSpan(function_id="FUN_1", line_start=1, line_end=2, code="int x;")
    source = FindingSource(expression="x", type="LOCAL", attacker_control="NO")
    sink = FindingSink(expression="free(x)", type="MEMORY_FREE")
    assert span.line_end == 2
    assert source.attacker_control == "NO"
    assert sink.type == "MEMORY_FREE"
