"""Tests for `stage5_verification.fvvw.graph` — Stage 5 FVVW v3 Phase 5.

`resolve_checkpointer` is tested directly (memory vs sqlite vs unknown).
`run_fvvw` is exercised end-to-end with every external dependency
(LLMs, executors, session executor) faked/monkeypatched — no real Docker,
QEMU, GDB, or LLM provider involved — proving the fork-join topology
(strategy -> fork(static, dynamic) -> join -> joint_evaluate) actually
produces a coherent result for both a concordant-confirm and a
discordant scenario.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

from fw_audit.common.findings import (
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.common.schemas import ELFArch, ELFInfo
from fw_audit.common.verification import Agreement, MechanismConfidence, VerificationVerdict
from fw_audit.config.settings import Settings
from fw_audit.executors.base import ExecutionResult, SessionHandle
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.fvvw.graph import resolve_checkpointer, run_fvvw


class _ScriptedLLM:
    def __init__(self, responses: list) -> None:
        self._responses = list(responses)
        self.calls: list = []

    async def ainvoke(self, messages, config=None):
        self.calls.append(messages)
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return AIMessage(content=item)


class _FakeSessionExecutor:
    def __init__(self, on_exec=None) -> None:
        self.exec_calls: list[str] = []
        self.stopped = False

    async def start(self, *, image=None, files=None, network=None):
        return SessionHandle(container_name="fake-session", workspace_dir=files)

    async def exec_in_session(self, handle, command, *, timeout=None):
        self.exec_calls.append(command)
        if "gdb-multiarch" in command and "recipe_reach" in command:
            return ExecutionResult(
                command=command,
                returncode=0,
                stdout="Breakpoint 1, 0x1000 in main ()\n",
                stderr="",
                timed_out=False,
            )
        if "gdb-multiarch" in command and "recipe_guards" in command:
            return ExecutionResult(
                command=command, returncode=0, stdout="", stderr="", timed_out=False
            )
        if "gdb-multiarch" in command and "recipe_trigger" in command:
            return ExecutionResult(
                command=command,
                returncode=0,
                stdout="TRIGGER:sink_arg:;touch /tmp/claim_001_proof;\n",
                stderr="",
                timed_out=False,
            )
        if command.startswith("test -e"):
            return ExecutionResult(
                command=command, returncode=0, stdout="FOUND\n", stderr="", timed_out=False
            )
        # collect_signals reads the QEMU log path (`.fvvw_qemu.log`), not
        # the never-written `target_stdout.log` — see dynamic_track.py's
        # `_QEMU_LOG_PATH` and the fix in collect_signals.
        if ".fvvw_qemu.log" in command and command.startswith("cat"):
            return ExecutionResult(
                command=command,
                returncode=0,
                stdout="wrote /tmp/claim_001_proof\n",
                stderr="",
                timed_out=False,
            )
        return ExecutionResult(command=command, returncode=0, stdout="", stderr="", timed_out=False)

    async def stop(self, handle):
        self.stopped = True


def _finding() -> Finding:
    return Finding(
        finding_id="candidate_001",
        title="t",
        category="command_execution",
        severity=Severity(impact=3, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=Decision.ESCALATE,
        evidence_span=EvidenceSpan(function_id="f", line_start=1, line_end=2, code="x"),
        source=FindingSource(
            expression="argv[1]", type="FUNCTION_PARAMETER", attacker_control="YES"
        ),
        sink=FindingSink(expression="system(cmd)", type="COMMAND_EXECUTION"),
        security_condition="c",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )


def _candidate(
    *,
    source_path: Path | None,
    binary_path: Path | None,
    rootfs_dir: Path | None,
    with_elf: bool = False,
):
    elf = None
    if with_elf:
        elf = ELFInfo(
            path="bin/vulnbin",
            absolute_path=str(binary_path),
            size_bytes=100,
            arch=ELFArch.ARM,
            is_64bit=False,
            is_little_endian=True,
            is_stripped=True,
            interpreter=None,
        )
    return VerificationCandidate(
        global_id="vulnbin#0000::candidate_001",
        chunk_id="vulnbin#0000",
        bin_id="vulnbin",
        finding=_finding(),
        source_path=source_path,
        binary_path=binary_path,
        rootfs_dir=rootfs_dir,
        elf=elf,
    )


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


def _verdict_json(verdict: str) -> str:
    return json.dumps(
        {"verdict": verdict, "confidence": "HIGH", "reasoning": "r", "feedback_for_retry": ""}
    )


def _patch_llm_roles(
    monkeypatch, *, strategy_response: str, generator_response, evaluator_response
):
    from fw_audit.config.llm_config import AgentRole

    roles = {
        AgentRole.STAGE5_STRATEGY_AGENT: _ScriptedLLM([strategy_response]),
        AgentRole.STAGE5_SCRIPT_GENERATOR: _ScriptedLLM([generator_response]),
        AgentRole.STAGE5_RESULT_EVALUATOR: _ScriptedLLM([evaluator_response]),
        AgentRole.STAGE5_REPORT_WRITER: _ScriptedLLM(["# report"]),
    }

    def fake_get_llm_for_agent(role, *, settings=None):
        return roles[role]

    monkeypatch.setattr(
        "fw_audit.stage5_verification.fvvw.graph.get_llm_for_agent", fake_get_llm_for_agent
    )
    return roles


def _patch_executors(monkeypatch, fake_executor_cls, *, script_outputs: list[str]):
    outputs = list(script_outputs)

    def on_run(command, files):
        if command.startswith("joern-parse"):
            (files / "cpg.bin").write_bytes(b"cpg")
            return ExecutionResult(
                command=command, returncode=0, stdout="", stderr="", timed_out=False
            )
        if command.startswith("objdump"):
            return ExecutionResult(
                command=command, returncode=0, stdout="disasm\n", stderr="", timed_out=False
            )
        stdout = outputs.pop(0) if outputs else ""
        return ExecutionResult(
            command=command, returncode=0, stdout=stdout, stderr="", timed_out=False
        )

    joern_exec = fake_executor_cls(on_run)
    crosscheck_exec = fake_executor_cls(on_run)
    session_exec = _FakeSessionExecutor()

    monkeypatch.setattr(
        "fw_audit.stage5_verification.fvvw.graph.joern_executor", lambda settings: joern_exec
    )
    monkeypatch.setattr(
        "fw_audit.stage5_verification.fvvw.graph.verification_executor",
        lambda settings: crosscheck_exec,
    )
    monkeypatch.setattr(
        "fw_audit.stage5_verification.fvvw.graph.verification_session_executor",
        lambda settings: session_exec,
    )
    return joern_exec, crosscheck_exec, session_exec


# ---------------------------------------------------------------------- #
# resolve_checkpointer
# ---------------------------------------------------------------------- #


def test_resolve_checkpointer_memory_backend():
    from langgraph.checkpoint.memory import MemorySaver

    settings = Settings(_env_file=None, FWA_STAGE5_CHECKPOINT_BACKEND="memory")
    checkpointer = resolve_checkpointer(settings)
    assert isinstance(checkpointer, MemorySaver)


def test_resolve_checkpointer_unknown_backend_raises():
    settings = Settings(_env_file=None, FWA_STAGE5_CHECKPOINT_BACKEND="redis")
    with pytest.raises(ValueError, match="Unknown stage5_checkpoint_backend"):
        resolve_checkpointer(settings)


def test_resolve_checkpointer_sqlite_without_package_raises_import_error():
    settings = Settings(_env_file=None, FWA_STAGE5_CHECKPOINT_BACKEND="sqlite")
    try:
        import langgraph.checkpoint.sqlite  # noqa: F401

        pytest.skip("langgraph-checkpoint-sqlite is installed; can't test the missing-dep path")
    except ImportError:
        pass
    with pytest.raises(ImportError, match="stage5-fvvw"):
        resolve_checkpointer(settings)


# ---------------------------------------------------------------------- #
# run_fvvw — end-to-end with everything faked
# ---------------------------------------------------------------------- #


async def test_run_fvvw_concordant_confirm(monkeypatch, fake_executor, tmp_path: Path):
    db_subfolder = tmp_path / "db"
    source_path = tmp_path / "whole.c"
    source_path.write_text("int main() { return 0; }\n", encoding="utf-8")
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    binary_path = rootfs / "bin" / "vulnbin"
    binary_path.write_bytes(b"\x7fELF")

    candidate = _candidate(
        source_path=source_path, binary_path=binary_path, rootfs_dir=rootfs, with_elf=True
    )

    _patch_llm_roles(
        monkeypatch,
        strategy_response=_strategy_plan_json(),
        generator_response='println("RESULT: FLOW_FOUND (1 path(s))")',
        evaluator_response=_verdict_json("PASS"),
    )
    _patch_executors(
        monkeypatch, fake_executor, script_outputs=["RESULT: FLOW_FOUND (1 path(s))"]
    )

    settings = Settings(_env_file=None, FWA_STAGE5_DYNAMIC_MAX_ITERATIONS=2)
    result = await run_fvvw(candidate, db_subfolder=db_subfolder, settings=settings)

    assert result["static_result"].verdict == VerificationVerdict.CONFIRMED
    assert result["dynamic_result"].verdict == VerificationVerdict.CONFIRMED
    assert result["agreement"] == Agreement.CONCORDANT_CONFIRM
    assert result["mechanism_confidence"] == MechanismConfidence.CONFIRMED_STRONG
    assert result["plan"].static_plan.target_function == "FUN_1"
    assert result["target"].arch == "arm"

    # cmdlog: both tracks' JSONL command logs land on disk under
    # stage5/fvvw/logs/, with real command/result content — not just the
    # LangSmith span (which is a no-op without --trace).
    deps = result["deps"]
    dynamic_records = deps.dynamic_command_log.read_all()
    static_records = deps.static_command_log.read_all()
    assert dynamic_records, "dynamic track issued no commands to the log"
    assert static_records, "static track issued no commands to the log"
    assert any(r["kind"] == "exec_in_session" for r in dynamic_records)
    assert any("gdb-multiarch" in r["command"] for r in dynamic_records)
    assert deps.dynamic_command_log.path.exists()
    assert deps.static_command_log.path.exists()
    assert deps.dynamic_command_log.path != deps.static_command_log.path


async def test_run_fvvw_static_confirmed_dynamic_unsupported_arch_is_one_sided(
    monkeypatch, fake_executor, tmp_path: Path
):
    """No ELF info at all -> characterize_target reports arch='unknown' ->
    plan_emulation reports mode='unsupported' -> dynamic track terminates
    ERROR without ever touching the session executor -> one_sided
    agreement, never a hard crash."""
    db_subfolder = tmp_path / "db"
    source_path = tmp_path / "whole.c"
    source_path.write_text("int main() { return 0; }\n", encoding="utf-8")

    candidate = _candidate(source_path=source_path, binary_path=None, rootfs_dir=None)

    _patch_llm_roles(
        monkeypatch,
        strategy_response=_strategy_plan_json(),
        generator_response='println("RESULT: FLOW_FOUND (1 path(s))")',
        evaluator_response=_verdict_json("PASS"),
    )
    joern_exec, crosscheck_exec, session_exec = _patch_executors(
        monkeypatch, fake_executor, script_outputs=["RESULT: FLOW_FOUND (1 path(s))"]
    )

    settings = Settings(_env_file=None)
    result = await run_fvvw(candidate, db_subfolder=db_subfolder, settings=settings)

    assert result["static_result"].verdict == VerificationVerdict.CONFIRMED
    assert result["dynamic_result"].verdict == VerificationVerdict.ERROR
    assert result["agreement"] == Agreement.ONE_SIDED
    # The session executor must never have been touched — bringup never runs
    # for an unsupported arch.
    assert session_exec.exec_calls == []


async def test_run_fvvw_discordant_holds(monkeypatch, fake_executor, tmp_path: Path):
    db_subfolder = tmp_path / "db"
    source_path = tmp_path / "whole.c"
    source_path.write_text("int main() { return 0; }\n", encoding="utf-8")
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    binary_path = rootfs / "bin" / "vulnbin"
    binary_path.write_bytes(b"\x7fELF")

    candidate = _candidate(
        source_path=source_path, binary_path=binary_path, rootfs_dir=rootfs, with_elf=True
    )

    _patch_llm_roles(
        monkeypatch,
        strategy_response=_strategy_plan_json(),
        generator_response='println("RESULT: FLOW_NOT_FOUND")',
        evaluator_response=_verdict_json("PASS"),
    )
    _patch_executors(monkeypatch, fake_executor, script_outputs=["RESULT: FLOW_NOT_FOUND"])

    settings = Settings(_env_file=None, FWA_STAGE5_DYNAMIC_MAX_ITERATIONS=2)
    result = await run_fvvw(candidate, db_subfolder=db_subfolder, settings=settings)

    # static track: FLOW_NOT_FOUND -> REFUTED. dynamic track: our fake
    # session always reports the marker present -> CONFIRMED. That's a
    # genuine discordant disagreement between the two independent witnesses.
    assert result["static_result"].verdict == VerificationVerdict.REFUTED
    assert result["dynamic_result"].verdict == VerificationVerdict.CONFIRMED
    assert result["agreement"] == Agreement.DISCORDANT
    assert result["mechanism_confidence"] == MechanismConfidence.DISCORDANT_HOLD


async def test_run_fvvw_raises_stage5_input_error_without_source_path(tmp_path: Path):
    from fw_audit.stage5_verification.errors import Stage5InputError

    candidate = _candidate(source_path=None, binary_path=None, rootfs_dir=None)
    with pytest.raises(Stage5InputError):
        await run_fvvw(candidate, db_subfolder=tmp_path, settings=Settings(_env_file=None))


async def test_run_fvvw_recovers_from_dynamic_fault_raised_by_bringup_itself(
    monkeypatch, fake_executor, tmp_path: Path
):
    """Regression (Bug C): a DynamicFault raised by bringup_stabilize
    ITSELF (staging failure, readiness-probe timeout) used to escape
    run_dynamic_track_only uncaught — it was raised from inside the
    `except DynamicFault:` handler in the main reach/guards/trigger loop,
    which does not re-catch its own body's exceptions. That propagated all
    the way out of run_fvvw as an unhandled DynamicFault instead of being
    retried like every other dynamic-track fault. Model a session executor
    whose FIRST exec_in_session call (the QEMU-staging copy inside
    bringup_stabilize) fails, forcing a DynamicFault mid-loop, and assert
    run_fvvw completes normally instead of raising."""
    db_subfolder = tmp_path / "db"
    source_path = tmp_path / "whole.c"
    source_path.write_text("int main() { return 0; }\n", encoding="utf-8")
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    binary_path = rootfs / "bin" / "vulnbin"
    binary_path.write_bytes(b"\x7fELF")

    candidate = _candidate(
        source_path=source_path, binary_path=binary_path, rootfs_dir=rootfs, with_elf=True
    )

    _patch_llm_roles(
        monkeypatch,
        strategy_response=_strategy_plan_json(),
        generator_response='println("RESULT: FLOW_FOUND (1 path(s))")',
        evaluator_response=_verdict_json("PASS"),
    )

    class _FlakyThenOkSessionExecutor(_FakeSessionExecutor):
        """Fails the QEMU-staging `cp` exactly once (triggering
        DynamicFault from inside bringup_stabilize's in-loop repair call),
        then behaves normally on every retry."""

        def __init__(self):
            super().__init__()
            self._stage_attempts = 0

        async def exec_in_session(self, handle, command, *, timeout=None):
            if command.startswith("cp ") and "$(command -v" in command:
                self._stage_attempts += 1
                if self._stage_attempts == 1:
                    return ExecutionResult(
                        command=command,
                        returncode=1,
                        stdout="",
                        stderr="cp: cannot stat: No such file or directory",
                        timed_out=False,
                    )
            return await super().exec_in_session(handle, command, timeout=timeout)

    def on_run(command, files):
        if command.startswith("joern-parse"):
            (files / "cpg.bin").write_bytes(b"cpg")
            return ExecutionResult(
                command=command, returncode=0, stdout="", stderr="", timed_out=False
            )
        if command.startswith("objdump"):
            return ExecutionResult(
                command=command, returncode=0, stdout="disasm\n", stderr="", timed_out=False
            )
        return ExecutionResult(
            command=command,
            returncode=0,
            stdout="RESULT: FLOW_FOUND (1 path(s))",
            stderr="",
            timed_out=False,
        )

    joern_exec = fake_executor(on_run)
    crosscheck_exec = fake_executor(on_run)
    flaky_session = _FlakyThenOkSessionExecutor()

    monkeypatch.setattr(
        "fw_audit.stage5_verification.fvvw.graph.joern_executor", lambda settings: joern_exec
    )
    monkeypatch.setattr(
        "fw_audit.stage5_verification.fvvw.graph.verification_executor",
        lambda settings: crosscheck_exec,
    )
    monkeypatch.setattr(
        "fw_audit.stage5_verification.fvvw.graph.verification_session_executor",
        lambda settings: flaky_session,
    )

    settings = Settings(
        _env_file=None, FWA_STAGE5_DYNAMIC_MAX_ITERATIONS=2, FWA_STAGE5_BRINGUP_MAX_REPAIRS=5
    )
    # Must complete without raising DynamicFault.
    result = await run_fvvw(candidate, db_subfolder=db_subfolder, settings=settings)
    assert result["dynamic_result"] is not None
    assert flaky_session._stage_attempts >= 2  # failed once, then retried successfully
