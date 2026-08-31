"""Tests for `stage5_verification.fvvw.driver` — the fork-join's own
worker-pool loop. Mocks `fvvw.graph.run_fvvw`/`fvvw.report.write_report`
so this never needs a real LLM/Docker/QEMU/GDB — same discipline as
`tests/test_stage5_driver.py` for the static-only driver."""

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
from fw_audit.common.verification import (
    Agreement,
    MechanismConfidence,
    ReachabilityConfidence,
    TrackResult,
    VerificationVerdict,
)
from fw_audit.config.settings import Settings
from fw_audit.stage5_verification import layout
from fw_audit.stage5_verification.cmdlog import CommandLog
from fw_audit.stage5_verification.errors import SandboxUnavailableError, Stage5InputError
from fw_audit.stage5_verification.fvvw import driver as fvvw_driver


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


class _FakeDeps:
    def __init__(self, tmp_path: Path) -> None:
        self.report_llm = object()
        self.static_workspace_dir = tmp_path / "static_ws"
        self.dynamic_workspace_dir = tmp_path / "dynamic_ws"
        self.static_workspace_dir.mkdir(parents=True, exist_ok=True)
        self.dynamic_workspace_dir.mkdir(parents=True, exist_ok=True)
        self.static_command_log = CommandLog.disabled()
        self.dynamic_command_log = CommandLog.disabled()


def _fake_outcome(tmp_path: Path, *, agreement=Agreement.CONCORDANT_CONFIRM) -> dict:
    return {
        "target": None,
        "plan": None,
        "static_result": TrackResult(verdict=VerificationVerdict.CONFIRMED, proved_hypothesis="A"),
        "dynamic_result": TrackResult(verdict=VerificationVerdict.CONFIRMED, proved_hypothesis="A"),
        "agreement": agreement,
        "mechanism_confidence": MechanismConfidence.CONFIRMED_STRONG,
        "reachability_confidence": ReachabilityConfidence.CONFIRMED,
        "residual_unknowns": [],
        "guard_logs": [],
        "dynamic_gdb_transcript": "",
        "crosscheck_evidence": {},
        "deps": _FakeDeps(tmp_path),
    }


def _patch_fvvw(
    monkeypatch, tmp_path: Path, *, side_effect=None, agreement=Agreement.CONCORDANT_CONFIRM
):
    async def fake_run_fvvw(candidate, *, db_subfolder, settings):
        if side_effect is not None:
            result = side_effect(candidate)
            if isinstance(result, Exception):
                raise result
        return _fake_outcome(tmp_path, agreement=agreement)

    async def fake_write_report(**kwargs):
        return "# Disclosure report\n\nfake"

    monkeypatch.setattr(fvvw_driver, "run_fvvw", fake_run_fvvw)
    monkeypatch.setattr(fvvw_driver, "write_report", fake_write_report)


async def test_run_fvvw_queue_no_findings_dir_raises_input_error(tmp_path):
    with pytest.raises(Stage5InputError):
        await fvvw_driver.run_fvvw_queue(
            db_subfolder=tmp_path / "db" / "fw", settings=Settings(_env_file=None)
        )


async def test_run_fvvw_queue_no_candidates_yields_no_targets(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    (db_subfolder / "stage3" / "findings").mkdir(parents=True)
    _patch_fvvw(monkeypatch, tmp_path)

    summary = await fvvw_driver.run_fvvw_queue(
        db_subfolder=db_subfolder, settings=Settings(_env_file=None)
    )

    assert summary.status == "no_targets"
    assert summary.total_candidates == 0


async def test_run_fvvw_queue_end_to_end_persists_json_and_markdown(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder, "bin", ["c1", "c2"])
    _write_stage2_summary(db_subfolder, "bin")
    _patch_fvvw(monkeypatch, tmp_path)

    summary = await fvvw_driver.run_fvvw_queue(
        db_subfolder=db_subfolder, settings=Settings(_env_file=None, stage5_workers=2)
    )

    assert summary.status == "completed"
    assert summary.total_candidates == 2
    assert summary.total_verified == 2
    assert summary.total_failed == 0
    assert summary.verdicts_by_type == {"confirmed_strong": 2}

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    fvvw_dir_ = layout.fvvw_dir(stage5_dir_)
    reports_dir_ = layout.fvvw_reports_dir(fvvw_dir_)
    for gid in ("bin#0000::c1", "bin#0000::c2"):
        json_path = reports_dir_ / layout.fvvw_report_json_filename(gid)
        md_path = reports_dir_ / layout.fvvw_report_markdown_filename(gid)
        assert json_path.is_file()
        assert md_path.is_file()
        assert "Disclosure report" in md_path.read_text(encoding="utf-8")

        # Previously-computed-then-dropped fields must now be persisted.
        report_data = json.loads(json_path.read_text(encoding="utf-8"))
        assert "guard_logs" in report_data
        assert "dynamic_gdb_transcript" in report_data
        assert "crosscheck_evidence" in report_data
        # started_at must be captured BEFORE the work runs, not backfilled
        # after — a regression here would make started_at ~= finished_at.
        started_at = datetime.fromisoformat(report_data["started_at"])
        finished_at = datetime.fromisoformat(report_data["finished_at"])
        assert started_at <= finished_at

    summary_path = layout.fvvw_summary_path(stage5_dir_)
    assert summary_path.is_file()
    written = json.loads(summary_path.read_text(encoding="utf-8"))
    assert written["total_verified"] == 2

    # Must NOT touch the static-only path's own summary file.
    assert not layout.stage5_summary_path(stage5_dir_).is_file()


async def test_run_fvvw_queue_persists_command_log_paths_when_enabled(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder, "bin", ["c1"])
    _write_stage2_summary(db_subfolder, "bin")

    async def fake_run_fvvw(candidate, *, db_subfolder, settings):
        outcome = _fake_outcome(tmp_path)
        deps = outcome["deps"]
        deps.static_command_log = CommandLog(tmp_path / "c1.static.jsonl", track="static")
        deps.dynamic_command_log = CommandLog(tmp_path / "c1.dynamic.jsonl", track="dynamic")
        deps.static_command_log.record(node="build_cpg", kind="joern_parse", command="joern-parse")
        deps.dynamic_command_log.record(node="reach_target", kind="gdb_batch", command="gdb ...")
        return outcome

    async def fake_write_report(**kwargs):
        return "# Disclosure report\n\nfake"

    monkeypatch.setattr(fvvw_driver, "run_fvvw", fake_run_fvvw)
    monkeypatch.setattr(fvvw_driver, "write_report", fake_write_report)

    summary = await fvvw_driver.run_fvvw_queue(
        db_subfolder=db_subfolder, settings=Settings(_env_file=None)
    )
    assert summary.total_verified == 1

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    fvvw_dir_ = layout.fvvw_dir(stage5_dir_)
    reports_dir_ = layout.fvvw_reports_dir(fvvw_dir_)
    json_path = reports_dir_ / layout.fvvw_report_json_filename("bin#0000::c1")
    report_data = json.loads(json_path.read_text(encoding="utf-8"))
    assert report_data["command_log_paths"]["static"] == str(tmp_path / "c1.static.jsonl")
    assert report_data["command_log_paths"]["dynamic"] == str(tmp_path / "c1.dynamic.jsonl")


async def test_run_fvvw_queue_only_filters_to_selected_global_ids(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder, "bin", ["c1", "c2"])
    _write_stage2_summary(db_subfolder, "bin")
    _patch_fvvw(monkeypatch, tmp_path)

    summary = await fvvw_driver.run_fvvw_queue(
        db_subfolder=db_subfolder,
        settings=Settings(_env_file=None),
        only_global_ids=frozenset({"bin#0000::c1"}),
    )

    assert summary.total_candidates == 1
    assert summary.candidates[0].global_id == "bin#0000::c1"


async def test_run_fvvw_queue_permanent_failure_recorded_not_verified(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder, "bin", ["c1"])
    _write_stage2_summary(db_subfolder, "bin")
    _patch_fvvw(
        monkeypatch, tmp_path, side_effect=lambda candidate: SandboxUnavailableError("no docker")
    )

    summary = await fvvw_driver.run_fvvw_queue(
        db_subfolder=db_subfolder,
        settings=Settings(_env_file=None, stage5_queue_max_attempts=1, stage5_workers=1),
    )

    assert summary.total_verified == 0
    assert summary.total_failed == 1
    assert summary.candidates[0].status == "failed"
    assert summary.candidates[0].error is not None


async def test_run_fvvw_queue_discordant_still_persists_and_verifies(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder, "bin", ["c1"])
    _write_stage2_summary(db_subfolder, "bin")
    _patch_fvvw(monkeypatch, tmp_path, agreement=Agreement.DISCORDANT)

    summary = await fvvw_driver.run_fvvw_queue(
        db_subfolder=db_subfolder, settings=Settings(_env_file=None)
    )

    # A discordant verdict is still a SUCCESSFUL run of the workflow (the
    # workflow's job is to surface the disagreement, not to fail on it).
    assert summary.total_verified == 1
    assert summary.total_failed == 0
