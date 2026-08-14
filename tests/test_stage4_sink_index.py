"""Tests for `fw_audit.stage4_rag.sink_index` — summary-free Stage 3 finding
resolution."""

from __future__ import annotations

from pathlib import Path

from fw_audit.common.findings import (
    AnalysisReport,
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.stage4_rag.sink_index import DEFAULT_DECISIONS, discover_sink_candidates


def _finding(finding_id: str, decision: Decision) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="t",
        category="command_execution",
        severity=Severity(impact=3, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=decision,
        evidence_span=EvidenceSpan(function_id="f", line_start=1, line_end=2, code="x"),
        source=FindingSource(expression="s", type="NVRAM", attacker_control="UNKNOWN"),
        sink=FindingSink(expression="system(s)", type="COMMAND_EXECUTION"),
        security_condition="c",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )


def _write_report(findings_dir: Path, chunk_id: str, findings: list[Finding]) -> None:
    findings_dir.mkdir(parents=True, exist_ok=True)
    report = AnalysisReport(chunk_id=chunk_id, findings=findings, checked_categories=[])
    filename = f"{chunk_id.replace('#', '__')}.json"
    (findings_dir / filename).write_text(report.model_dump_json(indent=2), encoding="utf-8")


def test_discover_sink_candidates_filters_by_default_decisions(tmp_path):
    stage3_dir = tmp_path / "stage3"
    _write_report(
        stage3_dir / "findings",
        "sbin_httpd__abc#0000",
        [
            _finding("c1", Decision.ESCALATE),
            _finding("c2", Decision.CONTEXT_REQUIRED),
            _finding("c3", Decision.DISCARD),
            _finding("c4", Decision.MERGE),
        ],
    )

    candidates = discover_sink_candidates(stage3_dir)

    assert {c.finding.finding_id for c in candidates} == {"c1", "c2"}


def test_discover_sink_candidates_builds_global_id_and_bin_id(tmp_path):
    stage3_dir = tmp_path / "stage3"
    _write_report(
        stage3_dir / "findings",
        "sbin_httpd__abc123#0007",
        [_finding("candidate_001", Decision.ESCALATE)],
    )

    candidates = discover_sink_candidates(stage3_dir)

    assert len(candidates) == 1
    c = candidates[0]
    assert c.chunk_id == "sbin_httpd__abc123#0007"
    assert c.bin_id == "sbin_httpd__abc123"
    assert c.global_id == "sbin_httpd__abc123#0007::candidate_001"


def test_discover_sink_candidates_missing_dir_yields_nothing(tmp_path):
    assert discover_sink_candidates(tmp_path / "does_not_exist") == []


def test_discover_sink_candidates_skips_malformed_file(tmp_path, caplog):
    findings_dir = tmp_path / "stage3" / "findings"
    findings_dir.mkdir(parents=True)
    (findings_dir / "broken.json").write_text("{not valid json", encoding="utf-8")
    _write_report(findings_dir, "good_bin#0000", [_finding("c1", Decision.ESCALATE)])

    with caplog.at_level("WARNING", logger="fw_audit.stage4_rag.sink_index"):
        candidates = discover_sink_candidates(tmp_path / "stage3")

    assert len(candidates) == 1
    assert candidates[0].chunk_id == "good_bin#0000"


def test_discover_sink_candidates_custom_decisions(tmp_path):
    stage3_dir = tmp_path / "stage3"
    _write_report(
        stage3_dir / "findings",
        "bin#0000",
        [_finding("c1", Decision.DISCARD), _finding("c2", Decision.ESCALATE)],
    )

    candidates = discover_sink_candidates(stage3_dir, decisions=frozenset({Decision.DISCARD}))

    assert {c.finding.finding_id for c in candidates} == {"c1"}


def test_default_decisions_are_escalate_and_context_required():
    assert frozenset({Decision.ESCALATE, Decision.CONTEXT_REQUIRED}) == DEFAULT_DECISIONS
