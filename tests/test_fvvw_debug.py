"""Tests for `stage5_verification.fvvw.debug` — the per-track debug entry
points (`debug_strategy`, `debug_dynamic`, `debug_fvvw`), added per the
user's explicit request that the Joern track and the QEMU track each be
runnable individually. Never persists into `stage5/fvvw/reports/` — same
discipline as `stage5_verification.debug`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

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
    ELFArch,
    ELFInfo,
    ExtractionStatus,
    Stage2Summary,
)
from fw_audit.common.verification import StrategyPlan
from fw_audit.config.settings import Settings
from fw_audit.executors.base import ExecutionResult, SessionHandle
from fw_audit.stage5_verification.errors import Stage5InputError
from fw_audit.stage5_verification.fvvw import debug as fvvw_debug


class _ScriptedLLM:
    def __init__(self, responses: list) -> None:
        self._responses = list(responses)
        self.calls: list = []

    async def ainvoke(self, messages, config=None):
        self.calls.append(messages)
        return AIMessage(content=self._responses.pop(0))


class _FakeSessionExecutor:
    async def start(self, *, image=None, files=None, network=None):
        return SessionHandle(container_name="fake-session", workspace_dir=files)

    async def exec_in_session(self, handle, command, *, timeout=None):
        return ExecutionResult(command=command, returncode=0, stdout="", stderr="", timed_out=False)

    async def stop(self, handle):
        pass


def _finding() -> Finding:
    return Finding(
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


def _write_findings(db_subfolder: Path, bin_id: str) -> None:
    findings_dir = db_subfolder / "stage3" / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    chunk_id = f"{bin_id}#0000"
    report = AnalysisReport(chunk_id=chunk_id, findings=[_finding()])
    (findings_dir / f"{bin_id}__0000.json").write_text(
        report.model_dump_json(indent=2), encoding="utf-8"
    )


def _write_stage2_summary(db_subfolder: Path, bin_id: str, *, rootfs: Path) -> None:
    relpath = f"stage2/binaries/{bin_id}/normalized/joern/whole.c"
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True, exist_ok=True)
    elf = ELFInfo(
        path="bin/vulnbin",
        absolute_path=str(rootfs / "bin" / "vulnbin"),
        size_bytes=100,
        arch=ELFArch.ARM,
        is_64bit=False,
        is_little_endian=True,
        is_stripped=True,
        interpreter=None,
    )
    binary = DecompiledBinary(
        bin_id=bin_id,
        rootfs_path="bin/vulnbin",
        requested_path="/bin/vulnbin",
        sha256="a" * 64,
        size_bytes=100,
        elf=elf,
        status=DecompilationStatus.SUCCEEDED,
        artifacts=DecompilationArtifacts(normalized_joern_c=relpath),
    )
    summary = Stage2Summary(
        run_id="r1",
        status=ExtractionStatus.COMPLETED,
        db_subfolder=str(db_subfolder),
        rootfs_dir=str(rootfs),
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


def _strategy_plan_json(observable: str = "obs") -> str:
    return json.dumps(
        {
            "threat_model": {},
            "hypotheses": {"a": "A", "b": "B", "decisive_observable": observable},
            "static_plan": {
                "target_function": "FUN_1",
                "expected_intermediate_calls": [],
                "sanitizer_patterns": [],
                "crosscheck_required": True,
                "decisive_observable": observable,
            },
            "dynamic_plan": {
                "reach_strategy": "inferior_call",
                "entry_addr": "0x1000",
                "target_addr": "0x1000",
                "sink_addr": "0x2000",
                "guards": [],
                "argv_template": [],
                "payload_marker": ";touch /tmp/claim_001_proof;",
                "required_signals": ["a", "b", "c"],
                "decisive_observable": observable,
            },
            "static_runnable": True,
            "dynamic_runnable": True,
        }
    )


def _setup(tmp_path: Path) -> tuple[Path, Path]:
    db_subfolder = tmp_path / "db"
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "vulnbin").write_bytes(b"\x7fELF")
    _write_findings(db_subfolder, "vulnbin")
    _write_stage2_summary(db_subfolder, "vulnbin", rootfs=rootfs)
    return db_subfolder, rootfs


async def test_debug_strategy_returns_plan_without_running_either_track(
    monkeypatch, tmp_path: Path
):
    db_subfolder, _rootfs = _setup(tmp_path)
    strategy_llm = _ScriptedLLM([_strategy_plan_json()])
    monkeypatch.setattr(
        fvvw_debug, "get_llm_for_agent", lambda role, *, settings=None: strategy_llm
    )

    result = await fvvw_debug.debug_strategy(
        db_subfolder, "vulnbin#0000::c1", settings=Settings(_env_file=None)
    )

    assert isinstance(result.plan, StrategyPlan)
    assert result.target.arch == "arm"
    assert result.plan.static_plan.target_function == "FUN_1"


async def test_debug_strategy_raises_on_missing_global_id(tmp_path: Path):
    db_subfolder, _rootfs = _setup(tmp_path)
    with pytest.raises(ValueError, match="No finding"):
        await fvvw_debug.debug_strategy(
            db_subfolder, "vulnbin#0000::nonexistent", settings=Settings(_env_file=None)
        )


async def test_debug_dynamic_runs_only_dynamic_track(monkeypatch, tmp_path: Path):
    db_subfolder, _rootfs = _setup(tmp_path)
    strategy_llm = _ScriptedLLM([_strategy_plan_json()])

    def fake_get_llm_for_agent(role, *, settings=None):
        return strategy_llm

    monkeypatch.setattr(
        "fw_audit.stage5_verification.fvvw.graph.get_llm_for_agent", fake_get_llm_for_agent
    )
    monkeypatch.setattr(
        "fw_audit.stage5_verification.fvvw.graph.joern_executor", lambda settings: None
    )
    monkeypatch.setattr(
        "fw_audit.stage5_verification.fvvw.graph.verification_executor", lambda settings: None
    )
    monkeypatch.setattr(
        "fw_audit.stage5_verification.fvvw.graph.verification_session_executor",
        lambda settings: _FakeSessionExecutor(),
    )

    result = await fvvw_debug.debug_dynamic(
        db_subfolder,
        "vulnbin#0000::c1",
        settings=Settings(_env_file=None, FWA_STAGE5_DYNAMIC_MAX_ITERATIONS=1),
    )

    assert result.result is not None
    # The strategy LLM was called (needed for DynamicPlan), but no
    # generator/evaluator role for the static track was ever resolved via
    # this path — only strategy + report/dynamic-relevant roles.
    assert len(strategy_llm.calls) == 1


async def test_debug_fvvw_raises_without_source_path(tmp_path: Path):
    db_subfolder = tmp_path / "db"
    (db_subfolder / "stage3" / "findings").mkdir(parents=True)
    findings_dir = db_subfolder / "stage3" / "findings"
    report = AnalysisReport(chunk_id="vulnbin#0000", findings=[_finding()])
    (findings_dir / "vulnbin__0000.json").write_text(
        report.model_dump_json(indent=2), encoding="utf-8"
    )
    # No stage2_summary.json at all -> source_path never resolves.
    with pytest.raises(Stage5InputError):
        await fvvw_debug.debug_fvvw(
            db_subfolder, "vulnbin#0000::c1", settings=Settings(_env_file=None)
        )
