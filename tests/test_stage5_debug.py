"""Tests for `fw_audit.stage5_verification.debug` — dry-run component
inspection. Mirrors `tests/test_stage4_debug.py`'s discipline: never writes
into the pipeline's own persisted output (`verifications/`/`reports/`)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from fw_audit.common.schemas import (
    DecompilationArtifacts,
    DecompilationStatus,
    DecompiledBinary,
    ExtractionStatus,
    Stage2Summary,
)
from fw_audit.executors.base import ExecutionResult
from fw_audit.stage5_verification import debug as debug_mod
from fw_audit.stage5_verification import layout
from fw_audit.stage5_verification.errors import Stage5InputError
from fw_audit.stage5_verification.tools import joern_tool as jt


def _write_stage2_summary(db_subfolder, bin_id: str) -> str:
    relpath = f"stage2/binaries/{bin_id}/normalized/joern/whole.c"
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True, exist_ok=True)
    binary = DecompiledBinary(
        bin_id=bin_id,
        rootfs_path="sbin/httpd",
        requested_path="/sbin/httpd",
        sha256="a" * 64,
        size_bytes=100,
        status=DecompilationStatus.SUCCEEDED,
        artifacts=DecompilationArtifacts(normalized_joern_c=relpath),
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
    source_path = db_subfolder / relpath
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text("int main(){return 0;}\n", encoding="utf-8")
    return relpath


async def test_debug_build_cpg_stages_source_and_builds(tmp_path, monkeypatch):
    _write_stage2_summary(tmp_path, "bin")

    def on_run(command, files):
        if command.startswith("joern-parse"):
            (files / jt.CPG_FILENAME).write_bytes(b"cpg")
        return ExecutionResult(command=command, returncode=0, stdout="", stderr="", timed_out=False)

    from tests.conftest import FakeExecutor

    fake = FakeExecutor(on_run)
    monkeypatch.setattr(debug_mod, "joern_executor", lambda settings: fake)

    result = await debug_mod.debug_build_cpg(tmp_path, "bin")

    assert result.record.ok
    assert (result.workspace_dir / jt.SOURCE_FILENAME).is_file()
    assert result.workspace_dir == layout.debug_dir(layout.stage5_dir(tmp_path)) / "bin"


async def test_debug_build_cpg_unresolved_bin_id_raises(tmp_path):
    _write_stage2_summary(tmp_path, "some_bin")
    with pytest.raises(Stage5InputError, match="No normalized Joern C resolved"):
        await debug_mod.debug_build_cpg(tmp_path, "unknown_bin")


async def test_debug_run_script_requires_existing_cpg(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(Stage5InputError, match="No cpg.bin"):
        await debug_mod.debug_run_script(workspace, "cpg.method.l")


async def test_debug_run_script_runs_against_existing_cpg(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / jt.CPG_FILENAME).write_bytes(b"cpg")

    def on_run(command, files):
        return ExecutionResult(
            command=command, returncode=0, stdout="result", stderr="", timed_out=False
        )

    from tests.conftest import FakeExecutor

    fake = FakeExecutor(on_run)
    monkeypatch.setattr(debug_mod, "joern_executor", lambda settings: fake)

    attempt = await debug_mod.debug_run_script(workspace, "cpg.method.l")

    assert attempt.ok
    assert attempt.stdout == "result"


async def test_debug_verify_never_persists(tmp_path, monkeypatch):
    """A dry run must not write into verifications/ or reports/."""
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
    from fw_audit.common.verification import CpgBuildRecord, VerificationReport, VerificationVerdict

    finding = Finding(
        finding_id="c1",
        title="t",
        category="command_execution",
        severity=Severity(impact=3, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=Decision.ESCALATE,
        evidence_span=EvidenceSpan(function_id="f", line_start=1, line_end=2, code="x"),
        source=FindingSource(expression="s", type="NVRAM", attacker_control="UNKNOWN"),
        sink=FindingSink(expression="system(s)", type="COMMAND_EXECUTION"),
        security_condition="c",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )
    findings_dir = tmp_path / "stage3" / "findings"
    findings_dir.mkdir(parents=True)
    report = AnalysisReport(chunk_id="bin#0000", findings=[finding], checked_categories=[])
    (findings_dir / "bin__0000.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    _write_stage2_summary(tmp_path, "bin")

    async def fake_verify_candidate(
        candidate, *, db_subfolder, settings, system_prompt=None, on_step=None
    ):
        return VerificationReport(
            global_id=candidate.global_id,
            bin_id=candidate.bin_id,
            verdict=VerificationVerdict.CONFIRMED,
            cpg_build=CpgBuildRecord(ok=True),
            started_at=datetime.now(UTC),
        )

    monkeypatch.setattr(debug_mod, "verify_candidate", fake_verify_candidate)

    result = await debug_mod.debug_verify(tmp_path, "bin#0000::c1")

    assert result.verdict.value == "CONFIRMED"
    stage5_dir_ = layout.stage5_dir(tmp_path)
    assert not layout.verifications_dir(stage5_dir_).exists()
    assert not layout.reports_dir(stage5_dir_).exists()
