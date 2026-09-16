"""Tests for `stage5_verification.fvvw.dynamic_agents` — Stage 5 FVVW v3's
Node 6 trigger/PoC loop. This module previously had no dedicated test
file; these tests were added alongside the trigger-shape enforcement fix
(see `dynamic_agents.ALLOWED_DELIVERY_TOOLS_BY_SHAPE`/
`allowed_delivery_tools_for_shape`) for the `sbin_hostapd` production
failure where `deliver_via_network` fired repeatedly with no receiving
listener while `deliver_via_direct_call` — the shape the plan actually
specified — was never dispatched even once, because the dispatcher ran
whatever `deliver_via_*` tool the LLM named with no gate against
`DynamicPlan.trigger_shape` at all.

Follows `tests/test_fvvw_strategy.py`'s `_ScriptedLLM` pattern for a
duck-typed `llm.ainvoke(messages, config=...)` double, and
`tests/test_fvvw_dynamic_track.py`'s `_FakeSessionExecutor`/`_ctx`-style
fixtures for the session layer `instrument_trigger`/`collect_observation`
(both real, unmocked) need underneath `trigger_agent`.
"""

from __future__ import annotations

import json
from pathlib import Path

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
from fw_audit.common.verification import DynamicPlan, TargetMeta
from fw_audit.config.settings import Settings
from fw_audit.executors.base import ExecutionResult, SessionHandle
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.fvvw.dynamic_agents import (
    ALLOWED_DELIVERY_TOOLS_BY_SHAPE,
    allowed_delivery_tools_for_shape,
    trigger_agent,
)
from fw_audit.stage5_verification.fvvw.dynamic_prompts import render_trigger_brief
from fw_audit.stage5_verification.fvvw.dynamic_track import BringupContext

# ---------------------------------------------------------------------- #
# allowed_delivery_tools_for_shape — pure mapping, no fixtures needed
# ---------------------------------------------------------------------- #


def test_direct_call_shape_allows_only_direct_call():
    assert allowed_delivery_tools_for_shape("direct_call") == frozenset(
        {"deliver_via_direct_call"}
    )


def test_network_http_shape_allows_only_network():
    assert allowed_delivery_tools_for_shape("network_http") == frozenset(
        {"deliver_via_network"}
    )


def test_cli_argv_shape_allows_only_argv():
    assert allowed_delivery_tools_for_shape("cli_argv") == frozenset({"deliver_via_argv"})


def test_unrecognized_shape_falls_back_to_permitting_all_known_tools():
    """An unrecognized/empty shape is a plan-authoring gap, not evidence
    that delivery should be blocked entirely."""
    assert allowed_delivery_tools_for_shape("") == frozenset(
        {"deliver_via_direct_call", "deliver_via_network", "deliver_via_argv"}
    )
    assert allowed_delivery_tools_for_shape("some_future_shape") == frozenset(
        {"deliver_via_direct_call", "deliver_via_network", "deliver_via_argv"}
    )


def test_every_table_entry_maps_to_a_real_deliver_tool_name():
    known_tools = {"deliver_via_direct_call", "deliver_via_network", "deliver_via_argv"}
    for shape, tools in ALLOWED_DELIVERY_TOOLS_BY_SHAPE.items():
        assert tools <= known_tools, f"shape {shape!r} maps to an unknown tool: {tools}"


# ---------------------------------------------------------------------- #
# render_trigger_brief — allowed_delivery_tools surfaced as a hard
# constraint, not silently dropped
# ---------------------------------------------------------------------- #


def test_brief_states_allowed_delivery_tools_as_hard_constraint():
    brief = render_trigger_brief(
        global_id="vulnbin#0000::candidate_001",
        trigger_shape="direct_call",
        oracle="o",
        disconfirm_condition="d",
        preconditions=[],
        vuln_class="command_execution",
        sink_expression="system(cmd)",
        emulation_mode="direct_call",
        allowed_delivery_tools=["deliver_via_direct_call"],
    )
    assert "deliver_via_direct_call" in brief
    assert "hard constraint" in brief.lower()


def test_brief_omits_constraint_line_when_not_given():
    """Backward-compatible: an omitted `allowed_delivery_tools` produces
    the same brief text this function always rendered."""
    brief = render_trigger_brief(
        global_id="g",
        trigger_shape="cli_argv",
        oracle="o",
        disconfirm_condition="d",
        preconditions=[],
        vuln_class="v",
        sink_expression="s",
        emulation_mode="user",
    )
    assert "hard constraint" not in brief.lower()


# ---------------------------------------------------------------------- #
# trigger_agent — end-to-end with the scripted LLM + fake session
# ---------------------------------------------------------------------- #


class _ScriptedLLM:
    """Mirrors `tests/test_fvvw_strategy.py::_ScriptedLLM` exactly — a
    duck-typed `ainvoke` double, since `trigger_agent` only ever calls
    `llm.ainvoke(messages, config=...)`, never anything `BaseChatModel`
    subclassing would be needed for."""

    def __init__(self, responses: list) -> None:
        self._responses = list(responses)
        self.calls: list = []

    async def ainvoke(self, messages, config=None):
        self.calls.append(messages)
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return AIMessage(content=item)


def _action(tool: str, **args) -> str:
    return json.dumps({"tool": tool, "args": args})


class _FakeSessionExecutor:
    """Same duck-typed `SandboxExecutor`-shaped double
    `tests/test_fvvw_dynamic_track.py::_FakeSessionExecutor` uses —
    `on_exec` returning `None` falls back to a bare successful
    `ExecutionResult` (empty stdout/stderr), which is exactly the
    "unproductive" default a delivery/observe round needs unless a test
    deliberately scripts a signal into the `gdb-multiarch` response."""

    def __init__(self, on_exec=None) -> None:
        self.exec_calls: list[str] = []
        self._on_exec = on_exec

    async def start(self, *, image=None, files=None, network=None):
        return SessionHandle(container_name="fake-session-abc123", workspace_dir=files)

    async def exec_in_session(self, handle, command, *, timeout=None, user=None):
        self.exec_calls.append(command)
        if self._on_exec is not None:
            result = self._on_exec(command)
            if result is not None:
                return result
        return ExecutionResult(command=command, returncode=0, stdout="", stderr="", timed_out=False)

    async def stop(self, handle):
        pass


def _target() -> TargetMeta:
    return TargetMeta(arch="mips", endianness="big", func_offset="0x445688")


def _dynamic_plan(**overrides) -> DynamicPlan:
    defaults = dict(
        reach_strategy="inferior_call",
        payload_marker=";touch /tmp/claim_001_proof;",
        decisive_observable="obs",
        entry_addr="0x445688",
        sink_addr="0x445688",
    )
    defaults.update(overrides)
    return DynamicPlan(**defaults)


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


def _candidate(*, binary_path: Path, rootfs_dir: Path) -> VerificationCandidate:
    return VerificationCandidate(
        global_id="vulnbin#0000::candidate_001",
        chunk_id="vulnbin#0000",
        bin_id="vulnbin",
        finding=_finding(),
        source_path=None,
        binary_path=binary_path,
        rootfs_dir=rootfs_dir,
    )


def _ctx(
    tmp_path: Path,
    *,
    session_executor,
    plan: DynamicPlan,
    settings: Settings | None = None,
) -> BringupContext:
    rootfs = tmp_path / "squashfs-root"
    (rootfs / "sbin").mkdir(parents=True, exist_ok=True)
    binary_path = rootfs / "sbin" / "hostapd"
    binary_path.write_bytes(b"\x7fELF")
    ctx = BringupContext(
        candidate=_candidate(binary_path=binary_path, rootfs_dir=rootfs),
        target=_target(),
        plan=plan,
        emulation_plan={"mode": "user", "arch_spec_key": ("mips", "big")},
        settings=settings or Settings(_env_file=None),
        session_executor=session_executor,
    )
    ctx.handle = SessionHandle(container_name="c1")
    return ctx


async def test_trigger_agent_refuses_out_of_shape_delivery(tmp_path: Path):
    """The exact production failure: `trigger_shape="direct_call"` but the
    LLM repeatedly proposes `deliver_via_network`. Must be refused every
    time — `deliver_via_network`'s own dispatch path (`_dispatch_delivery`,
    which would issue a real `exec_in_session` command) must never run."""
    llm = _ScriptedLLM(
        [
            _action("deliver_via_network", http_method="POST", body="EAP-WSC-M7-FRAME[...]"),
            _action("deliver_via_network", http_method="POST", body="EAP-WSC-M7-FRAME[...] v2"),
            _action("done", summary="gave up"),
        ]
    )
    executor = _FakeSessionExecutor()
    plan = _dynamic_plan(trigger_shape="direct_call")
    ctx = _ctx(tmp_path, session_executor=executor, plan=plan)

    result = await trigger_agent(
        ctx,
        llm=llm,
        settings=Settings(_env_file=None),
        target=_target(),
        plan=plan,
        vuln_class="command_execution",
        sink_expression="system(cmd)",
    )

    assert result.delivery_channel == ""
    assert not any("network" in c.lower() for c in executor.exec_calls if "gdb-multiarch" not in c)
    # The refusal message must have been shown back to the LLM.
    last_prompt = str(llm.calls[-1][-1].content)
    assert "not available for trigger_shape" in last_prompt or "deliver_via_direct_call" in str(
        llm.calls[1][-1].content
    )


async def test_trigger_agent_allows_in_shape_delivery(tmp_path: Path):
    """The matching-shape case: `deliver_via_direct_call` under
    `trigger_shape="direct_call"` must actually be dispatched (recorded as
    `ctx.real_payload_override`), not refused."""
    llm = _ScriptedLLM(
        [
            _action("deliver_via_direct_call", call_expression="hostapd_wps_call(0x1000)"),
            _action("done", summary="delivered"),
        ]
    )
    executor = _FakeSessionExecutor()
    plan = _dynamic_plan(trigger_shape="direct_call")
    ctx = _ctx(tmp_path, session_executor=executor, plan=plan)

    result = await trigger_agent(
        ctx,
        llm=llm,
        settings=Settings(_env_file=None),
        target=_target(),
        plan=plan,
        vuln_class="command_execution",
        sink_expression="system(cmd)",
    )

    assert result.delivery_channel == "deliver_via_direct_call"
    assert ctx.real_payload_override == "hostapd_wps_call(0x1000)"


async def test_trigger_agent_stops_early_after_unproductive_delivery_limit(tmp_path: Path):
    """Regression: the production run delivered 4 cosmetically-different
    `deliver_via_network` payloads in a row, none of which produced any
    observable effect, and the loop never recognized the pattern — it
    burned the whole step budget. With the default limit (2), the THIRD
    unproductive deliver+observe round must stop the loop early with a
    distinct summary, never reaching a 'done' the LLM would otherwise have
    to signal itself."""
    llm = _ScriptedLLM(
        [
            _action("deliver_via_argv"),
            _action("observe_result"),
            _action("deliver_via_argv"),
            _action("observe_result"),
            # A 3rd round should never be reached — the loop stops itself
            # after the 2nd unproductive observe_result (default limit=2).
            _action("deliver_via_argv"),
            _action("observe_result"),
        ]
    )
    # gdb-multiarch stdout carries no signal/crash/marker text at all —
    # every observe_result this round is unproductive by construction.
    executor = _FakeSessionExecutor()
    plan = _dynamic_plan(trigger_shape="cli_argv")
    ctx = _ctx(tmp_path, session_executor=executor, plan=plan)

    result = await trigger_agent(
        ctx,
        llm=llm,
        settings=Settings(_env_file=None),
        target=_target(),
        plan=plan,
        vuln_class="command_execution",
        sink_expression="system(cmd)",
        max_steps=10,
    )

    assert "unproductive" in result.summary
    assert "cli_argv" in result.summary
    # Only 4 of the 6 scripted actions should have been consumed (2 full
    # deliver+observe rounds), proving the loop stopped itself early.
    assert len(llm.calls) == 4


async def test_trigger_agent_resets_unproductive_counter_on_a_productive_round(tmp_path: Path):
    """A signal-producing round must reset the counter — an earlier
    unproductive attempt should not count against a later, genuinely
    different (productive) one."""

    def on_exec(command):
        if "gdb-multiarch" in command:
            return ExecutionResult(
                command=command,
                returncode=0,
                stdout="Program received signal SIGSEGV, Segmentation fault.\n",
                stderr="",
                timed_out=False,
            )
        return None

    llm = _ScriptedLLM(
        [
            _action("deliver_via_argv"),
            _action("observe_result"),
            _action("done", summary="crash reproduced"),
        ]
    )
    executor = _FakeSessionExecutor(on_exec)
    plan = _dynamic_plan(trigger_shape="cli_argv")
    ctx = _ctx(tmp_path, session_executor=executor, plan=plan)

    result = await trigger_agent(
        ctx,
        llm=llm,
        settings=Settings(_env_file=None),
        target=_target(),
        plan=plan,
        vuln_class="memory_corruption",
        sink_expression="strcpy(buf, argv[1])",
    )

    assert result.summary == "crash reproduced"
    assert "unproductive" not in result.summary


async def test_trigger_agent_unproductive_limit_is_configurable(tmp_path: Path):
    """`Settings.stage5_trigger_unproductive_delivery_limit` actually
    controls the cutoff, not a hardcoded constant."""
    llm = _ScriptedLLM(
        [
            _action("deliver_via_argv"),
            _action("observe_result"),
        ]
    )
    executor = _FakeSessionExecutor()
    plan = _dynamic_plan(trigger_shape="cli_argv")
    settings = Settings(_env_file=None).model_copy(
        update={"stage5_trigger_unproductive_delivery_limit": 1}
    )
    ctx = _ctx(tmp_path, session_executor=executor, plan=plan, settings=settings)

    result = await trigger_agent(
        ctx,
        llm=llm,
        settings=settings,
        target=_target(),
        plan=plan,
        vuln_class="command_execution",
        sink_expression="system(cmd)",
        max_steps=10,
    )

    assert "unproductive" in result.summary
    assert len(llm.calls) == 2  # stopped after the first unproductive round
