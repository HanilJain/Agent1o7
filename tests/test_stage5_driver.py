"""Tests for `fw_audit.stage5_verification.driver` — the worker-pool loop.
Mocks `agent.verifier.verify_candidate` so this never needs a real LLM or
Docker/Joern — same discipline as `tests/test_stage4_driver.py`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fw_audit.common.findings import (
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
from fw_audit.common.verification import CpgBuildRecord, VerificationReport, VerificationVerdict
from fw_audit.config.settings import Settings
from fw_audit.stage5_verification import driver, layout
from fw_audit.stage5_verification.errors import SandboxUnavailableError, Stage5InputError


def _finding(finding_id: str) -> Finding:
    return Finding(
        finding_id=finding_id,
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


def _write_findings(db_subfolder: Path, bin_id: str, finding_ids: list[str]) -> None:
    from fw_audit.common.findings import AnalysisReport

    findings_dir = db_subfolder / "stage3" / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    chunk_id = f"{bin_id}#0000"
    report = AnalysisReport(
        chunk_id=chunk_id, findings=[_finding(fid) for fid in finding_ids], checked_categories=[]
    )
    filename = f"{chunk_id.replace('#', '__')}.json"
    (findings_dir / filename).write_text(report.model_dump_json(indent=2), encoding="utf-8")


def _write_stage2_summary(db_subfolder: Path, bin_id: str) -> None:
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


def _fake_report(global_id: str, bin_id: str, verdict: VerificationVerdict) -> VerificationReport:
    return VerificationReport(
        global_id=global_id,
        bin_id=bin_id,
        model="anthropic:claude-sonnet-4-5",
        cpg_build=CpgBuildRecord(command="joern-parse", ok=True, duration_seconds=1.0),
        attempts=[],
        verdict=verdict,
        confidence="HIGH",
        summary="s",
        evidence="e",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )


def _patch_verify(monkeypatch, *, side_effect=None, verdict=VerificationVerdict.CONFIRMED):
    async def fake_verify_candidate(candidate, *, db_subfolder, settings, system_prompt=None):
        if side_effect is not None:
            result = side_effect(candidate)
            if isinstance(result, Exception):
                raise result
        return _fake_report(candidate.global_id, candidate.bin_id, verdict)

    monkeypatch.setattr(driver, "verify_candidate", fake_verify_candidate)


async def test_run_queue_no_findings_dir_raises_input_error(tmp_path):
    with pytest.raises(Stage5InputError):
        await driver.run_queue(
            db_subfolder=tmp_path / "db" / "fw", settings=Settings(_env_file=None)
        )


async def test_run_queue_no_candidates_yields_no_targets(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    (db_subfolder / "stage3" / "findings").mkdir(parents=True)
    _patch_verify(monkeypatch)

    summary = await driver.run_queue(db_subfolder=db_subfolder, settings=Settings(_env_file=None))

    assert summary.status == "no_targets"
    assert summary.total_candidates == 0


async def test_run_queue_end_to_end_persists_json_and_markdown(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder, "bin", ["c1", "c2"])
    _write_stage2_summary(db_subfolder, "bin")
    _patch_verify(monkeypatch)

    summary = await driver.run_queue(
        db_subfolder=db_subfolder, settings=Settings(_env_file=None, stage5_workers=2)
    )

    assert summary.status == "completed"
    assert summary.total_candidates == 2
    assert summary.total_verified == 2
    assert summary.total_failed == 0
    assert summary.verdicts_by_type == {"CONFIRMED": 2}

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    for gid in ("bin#0000::c1", "bin#0000::c2"):
        assert (
            layout.verifications_dir(stage5_dir_) / layout.verification_filename(gid)
        ).is_file()
        assert (layout.reports_dir(stage5_dir_) / layout.report_filename(gid)).is_file()

    summary_path = layout.stage5_summary_path(stage5_dir_)
    assert summary_path.is_file()
    written = json.loads(summary_path.read_text(encoding="utf-8"))
    assert written["total_verified"] == 2


async def test_run_queue_only_filters_to_selected_global_ids(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder, "bin", ["c1", "c2"])
    _write_stage2_summary(db_subfolder, "bin")
    _patch_verify(monkeypatch)

    summary = await driver.run_queue(
        db_subfolder=db_subfolder,
        settings=Settings(_env_file=None),
        only_global_ids=frozenset({"bin#0000::c1"}),
    )

    assert summary.total_candidates == 1
    assert summary.candidates[0].global_id == "bin#0000::c1"


async def test_run_queue_permanent_failure_recorded_not_verified(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder, "bin", ["c1"])
    _write_stage2_summary(db_subfolder, "bin")
    _patch_verify(
        monkeypatch, side_effect=lambda candidate: SandboxUnavailableError("no docker")
    )

    summary = await driver.run_queue(
        db_subfolder=db_subfolder,
        settings=Settings(_env_file=None, stage5_queue_max_attempts=1, stage5_workers=1),
    )

    assert summary.total_verified == 0
    assert summary.total_failed == 1
    assert summary.candidates[0].status == "failed"
    assert summary.candidates[0].error is not None


async def test_workspace_cleaned_up_unless_keep_workspace(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder, "bin", ["c1"])
    _write_stage2_summary(db_subfolder, "bin")
    _patch_verify(monkeypatch)

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    workspace = layout.workspace_dir(stage5_dir_, "bin#0000::c1")
    workspace.mkdir(parents=True)
    (workspace / "cpg.bin").write_bytes(b"x")

    await driver.run_queue(db_subfolder=db_subfolder, settings=Settings(_env_file=None))

    assert not workspace.exists()


async def test_workspace_kept_when_keep_workspace_true(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder, "bin", ["c1"])
    _write_stage2_summary(db_subfolder, "bin")
    _patch_verify(monkeypatch)

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    workspace = layout.workspace_dir(stage5_dir_, "bin#0000::c1")
    workspace.mkdir(parents=True)
    (workspace / "cpg.bin").write_bytes(b"x")

    await driver.run_queue(
        db_subfolder=db_subfolder, settings=Settings(_env_file=None, stage5_keep_workspace=True)
    )

    assert workspace.exists()
