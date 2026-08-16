"""Tests for `fw_audit.stage5_verification.candidate_index` — Stage 3
finding resolution + normalized-Joern-C path resolution via
`stage2_summary.json`. Mirrors `tests/test_stage4_sink_index.py`'s shape,
plus the Stage-2-summary resolution `SinkCandidate` never needed."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

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
from fw_audit.common.schemas import (
    DecompilationArtifacts,
    DecompilationStatus,
    DecompiledBinary,
    ExtractionStatus,
    Stage2Summary,
)
from fw_audit.stage5_verification.candidate_index import (
    DEFAULT_DECISIONS,
    discover_candidates,
)
from fw_audit.stage5_verification.errors import Stage5InputError


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


def _write_stage2_summary(
    db_subfolder: Path, *, bin_id: str, normalized_joern_c_relpath: str | None
) -> None:
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True, exist_ok=True)
    binary = DecompiledBinary(
        bin_id=bin_id,
        rootfs_path="sbin/httpd",
        requested_path="/sbin/httpd",
        sha256="a" * 64,
        size_bytes=100,
        status=DecompilationStatus.SUCCEEDED,
        artifacts=DecompilationArtifacts(normalized_joern_c=normalized_joern_c_relpath),
    )
    summary = Stage2Summary(
        run_id="r1",
        status=ExtractionStatus.COMPLETED,
        db_subfolder=str(db_subfolder),
        rootfs_dir="rootfs",
        stage2_dir=str(stage2_dir),
        ghidra_image="fw-audit-ghidra:latest",
        binaries=[binary],
        started_at=datetime.now(UTC),
    )
    (stage2_dir / "stage2_summary.json").write_text(
        summary.model_dump_json(indent=2), encoding="utf-8"
    )


def _write_joern_c(db_subfolder: Path, relpath: str) -> None:
    path = db_subfolder / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("int main() { return 0; }\n", encoding="utf-8")


def test_default_decisions_is_escalate_only():
    assert frozenset({Decision.ESCALATE}) == DEFAULT_DECISIONS


def test_missing_findings_dir_yields_nothing(tmp_path):
    assert discover_candidates(tmp_path) == []


def test_missing_stage2_summary_raises(tmp_path):
    _write_report(tmp_path / "stage3" / "findings", "bin#0000", [_finding("c1", Decision.ESCALATE)])
    with pytest.raises(Stage5InputError, match="Stage 2 summary not found"):
        discover_candidates(tmp_path)


def test_discover_candidates_filters_by_default_decisions_and_resolves_source(tmp_path):
    bin_id = "sbin_httpd__abc123"
    relpath = f"stage2/binaries/{bin_id}/normalized/joern/whole.c"
    _write_report(
        tmp_path / "stage3" / "findings",
        f"{bin_id}#0000",
        [
            _finding("c1", Decision.ESCALATE),
            _finding("c2", Decision.CONTEXT_REQUIRED),
            _finding("c3", Decision.DISCARD),
        ],
    )
    _write_stage2_summary(tmp_path, bin_id=bin_id, normalized_joern_c_relpath=relpath)
    _write_joern_c(tmp_path, relpath)

    candidates = discover_candidates(tmp_path)

    assert len(candidates) == 1
    c = candidates[0]
    assert c.finding.finding_id == "c1"
    assert c.bin_id == bin_id
    assert c.global_id == f"{bin_id}#0000::c1"
    assert c.source_path == (tmp_path / relpath).resolve()


def test_discover_candidates_custom_decisions(tmp_path):
    bin_id = "bin"
    relpath = f"stage2/binaries/{bin_id}/normalized/joern/whole.c"
    _write_report(
        tmp_path / "stage3" / "findings",
        f"{bin_id}#0000",
        [_finding("c1", Decision.DISCARD), _finding("c2", Decision.ESCALATE)],
    )
    _write_stage2_summary(tmp_path, bin_id=bin_id, normalized_joern_c_relpath=relpath)
    _write_joern_c(tmp_path, relpath)

    candidates = discover_candidates(tmp_path, decisions=frozenset({Decision.DISCARD}))

    assert {c.finding.finding_id for c in candidates} == {"c1"}


def test_unresolved_bin_id_yields_none_source_path(tmp_path):
    bin_id = "unknown_bin"
    _write_report(
        tmp_path / "stage3" / "findings",
        f"{bin_id}#0000",
        [_finding("c1", Decision.ESCALATE)],
    )
    # stage2 summary exists but has no binary matching bin_id at all.
    _write_stage2_summary(tmp_path, bin_id="some_other_bin", normalized_joern_c_relpath=None)

    candidates = discover_candidates(tmp_path)

    assert len(candidates) == 1
    assert candidates[0].source_path is None


def test_missing_normalized_joern_c_on_disk_yields_none_source_path(tmp_path):
    bin_id = "bin"
    relpath = f"stage2/binaries/{bin_id}/normalized/joern/whole.c"
    _write_report(
        tmp_path / "stage3" / "findings",
        f"{bin_id}#0000",
        [_finding("c1", Decision.ESCALATE)],
    )
    # Summary records the path, but the file itself was never written.
    _write_stage2_summary(tmp_path, bin_id=bin_id, normalized_joern_c_relpath=relpath)

    candidates = discover_candidates(tmp_path)

    assert candidates[0].source_path is None


def test_skips_malformed_findings_file(tmp_path, caplog):
    bin_id = "good_bin"
    relpath = f"stage2/binaries/{bin_id}/normalized/joern/whole.c"
    findings_dir = tmp_path / "stage3" / "findings"
    findings_dir.mkdir(parents=True)
    (findings_dir / "broken.json").write_text("{not valid json", encoding="utf-8")
    _write_report(findings_dir, f"{bin_id}#0000", [_finding("c1", Decision.ESCALATE)])
    _write_stage2_summary(tmp_path, bin_id=bin_id, normalized_joern_c_relpath=relpath)
    _write_joern_c(tmp_path, relpath)

    with caplog.at_level("WARNING", logger="fw_audit.stage5_verification.candidate_index"):
        candidates = discover_candidates(tmp_path)

    assert len(candidates) == 1
    assert candidates[0].chunk_id == f"{bin_id}#0000"


def test_malformed_stage2_summary_raises(tmp_path):
    _write_report(
        tmp_path / "stage3" / "findings", "bin#0000", [_finding("c1", Decision.ESCALATE)]
    )
    stage2_dir = tmp_path / "stage2"
    stage2_dir.mkdir(parents=True)
    (stage2_dir / "stage2_summary.json").write_text(
        json.dumps({"not": "a valid summary"}), encoding="utf-8"
    )

    with pytest.raises(Stage5InputError, match="does not match the Stage2Summary contract"):
        discover_candidates(tmp_path)
