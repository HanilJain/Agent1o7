"""Tests for `stage5_verification.fvvw.dynamic_graph` — the dynamic
track's compiled 9-node agentic `StateGraph` (spec Nodes 2-8). Scoped to
what's cheaply unit-testable without a real QEMU/GDB session or LLM:

1. The router decision table (`route_after_*` pure functions) — every
   `RouteDecision.route`/state-flag combination maps to the correct next
   node, per the spec's §10 decision table.
2. `_build_track_result`/`_TERMINAL_ROUTES` — the confirmed/refuted/
   inconclusive -> `TrackResult` conversion this module owns (Node 8's
   `RouteDecision` itself carries no verdict, only a routing instruction).
3. `_run_evaluate_route`'s deterministic first pass: oracle match, the
   hard iteration-budget cutoff, and the "not reached" fallback — each
   checked BEFORE any LLM call, so these are exercised with a
   never-invoked LLM stub to prove the deterministic branches never
   reach it.
4. `build_dynamic_graph` compiles successfully and exposes the expected
   node/edge shape.

Full end-to-end dynamic-track runs (bring-up -> health-gate -> gdb-attach
-> trigger -> evaluate, looping through a fake session executor and
scripted agentic LLMs) are covered by `tests/test_fvvw_graph.py`'s
`run_fvvw`-level integration tests and `tests/test_fvvw_debug.py::
test_debug_dynamic_runs_only_dynamic_track` — not duplicated here.
"""

from __future__ import annotations

import pytest

from fw_audit.common.verification import (
    DynamicPlan,
    ObservationRecord,
    RouteDecision,
    VerificationVerdict,
)
from fw_audit.config.settings import Settings
from fw_audit.stage5_verification.fvvw.dynamic_graph import (
    _TERMINAL_ROUTES,
    DynamicGraphDeps,
    _build_track_result,
    _run_evaluate_route,
    route_after_bringup,
    route_after_evaluate,
    route_after_gdb_attach,
    route_after_health_gate,
    route_after_trigger,
)

# --------------------------------------------------------------------- #
# route_after_* — pure conditional-edge functions
# --------------------------------------------------------------------- #


def test_route_after_bringup_ends_on_exhaustion():
    assert route_after_bringup({"_bringup_exhausted": True}) == "__end__"


def test_route_after_bringup_proceeds_to_health_gate_otherwise():
    assert route_after_bringup({"_bringup_exhausted": False}) == "health_gate"
    assert route_after_bringup({}) == "health_gate"


def test_route_after_health_gate_ok_goes_to_gdb_attach():
    assert route_after_health_gate({"_health_ok": True}) == "gdb_attach"


def test_route_after_health_gate_failure_goes_to_bringup():
    assert route_after_health_gate({"_health_ok": False}) == "bringup"
    assert route_after_health_gate({}) == "bringup"


def test_route_after_gdb_attach_fault_goes_to_bringup():
    assert route_after_gdb_attach({"_gdb_fault": True}) == "bringup"


def test_route_after_gdb_attach_proceeds_to_trigger_even_when_not_reached():
    # Node 8 alone decides what "not reached" means — gdb_attach itself
    # never shortcuts back to bringup or straight to evaluate on a bare
    # "breakpoint didn't fire" (only a genuine setup DynamicFault does).
    assert route_after_gdb_attach({"_gdb_fault": False, "_reached": False}) == "trigger"
    assert route_after_gdb_attach({"_gdb_fault": False, "_reached": True}) == "trigger"


def test_route_after_trigger_fault_goes_to_bringup():
    assert route_after_trigger({"_trigger_fault": True}) == "bringup"


def test_route_after_trigger_success_goes_to_evaluate_route():
    assert route_after_trigger({"_trigger_fault": False}) == "evaluate_route"
    assert route_after_trigger({}) == "evaluate_route"


@pytest.mark.parametrize(
    ("route", "expected_node"),
    [
        ("confirmed", "__end__"),
        ("refuted", "__end__"),
        ("inconclusive", "__end__"),
        ("retry_bringup", "bringup"),
        ("retry_gdb_attach", "gdb_attach"),
        ("retry_trigger", "trigger"),
        ("escalate_direct_call", "plan_emulation_escalate"),
    ],
)
def test_route_after_evaluate_decision_table(route, expected_node):
    """Every route the spec's §10 decision table names maps to the
    correct next node — the full seven-row table in one parametrized
    test."""
    decision = RouteDecision(route=route, diagnosis="d", confidence="HIGH")
    assert route_after_evaluate({"route": decision}) == expected_node


def test_route_after_evaluate_none_decision_ends_the_graph():
    # No Node 8 decision recorded yet (shouldn't normally happen on the
    # path into this conditional edge, but must not crash) -> terminate
    # rather than raise.
    assert route_after_evaluate({"route": None}) == "__end__"
    assert route_after_evaluate({}) == "__end__"


# --------------------------------------------------------------------- #
# _build_track_result / _TERMINAL_ROUTES
# --------------------------------------------------------------------- #


def test_terminal_routes_covers_exactly_the_three_terminal_dispositions():
    assert set(_TERMINAL_ROUTES) == {"confirmed", "refuted", "inconclusive"}


def test_build_track_result_confirmed_proves_hypothesis_a():
    decision = RouteDecision(
        route="confirmed", diagnosis="deterministic oracle match: 'SIGSEGV'", confidence="HIGH"
    )
    observation = ObservationRecord(signal="SIGSEGV", faulting_pc="0x00012345")
    result = _build_track_result(decision, observation, iteration=2)
    assert result.verdict == VerificationVerdict.CONFIRMED
    assert result.proved_hypothesis == "A"
    assert result.iters_used == 2
    assert result.evidence["reason"] == decision.diagnosis
    assert result.evidence["faulting_pc"] == "0x00012345"
    assert result.evidence["signal"] == "SIGSEGV"
    assert "budget_exhausted" not in result.evidence


def test_build_track_result_refuted_proves_hypothesis_b():
    decision = RouteDecision(route="refuted", diagnosis="safely bounds-checked", confidence="HIGH")
    result = _build_track_result(decision, ObservationRecord(), iteration=3)
    assert result.verdict == VerificationVerdict.REFUTED
    assert result.proved_hypothesis == "B"
    assert "budget_exhausted" not in result.evidence


def test_build_track_result_inconclusive_proves_none_and_tags_budget_exhausted():
    decision = RouteDecision(route="inconclusive", diagnosis="budget spent", confidence="HIGH")
    result = _build_track_result(decision, ObservationRecord(), iteration=5)
    assert result.verdict == VerificationVerdict.INCONCLUSIVE
    assert result.proved_hypothesis == "none"
    assert result.evidence["budget_exhausted"] is True


def test_build_track_result_includes_memory_diff_and_artifacts_when_present():
    decision = RouteDecision(route="confirmed", diagnosis="d", confidence="HIGH")
    observation = ObservationRecord(
        memory_diff_detected=True, filesystem_artifacts=["/tmp/claim_001_proof"]
    )
    result = _build_track_result(decision, observation, iteration=1)
    assert result.evidence["memory_diff_detected"] is True
    assert result.evidence["filesystem_artifacts"] == ["/tmp/claim_001_proof"]


# --------------------------------------------------------------------- #
# _run_evaluate_route — deterministic first pass (never reaches the LLM)
# --------------------------------------------------------------------- #


class _NeverCalledLLM:
    """Fails the test immediately if the deterministic first pass falls
    through to an LLM call it shouldn't need — proves match_oracle/the
    budget cutoff/the not-reached fallback are checked BEFORE any LLM
    round-trip, per spec Design Principle #1."""

    async def ainvoke(self, messages, config=None):
        raise AssertionError("route_observation must not be called for this deterministic case")


def _deps(*, max_iterations: int = 3) -> DynamicGraphDeps:
    return DynamicGraphDeps(
        settings=Settings(_env_file=None, FWA_STAGE5_DYNAMIC_MAX_ITERATIONS=max_iterations),
        bringup_llm=_NeverCalledLLM(),
        trigger_llm=_NeverCalledLLM(),
        dynamic_evaluator_llm=_NeverCalledLLM(),
        session_executor=None,  # unused by _run_evaluate_route
    )


def _plan(
    *, oracle: str = "SIGSEGV", disconfirm_condition: str = "safely bounds-checked"
) -> DynamicPlan:
    return DynamicPlan(
        reach_strategy="inferior_call",
        oracle=oracle,
        disconfirm_condition=disconfirm_condition,
        decisive_observable=oracle,
    )


async def test_evaluate_route_deterministic_oracle_match_confirms_without_llm():
    observation = ObservationRecord(signal="SIGSEGV", faulting_pc="0x1000")
    result = await _run_evaluate_route(
        deps=_deps(),
        global_id="g1",
        plan=_plan(oracle="SIGSEGV"),
        observation=observation,
        reached=True,
        reached_sink=True,
        iteration=1,
    )
    assert result["route"].route == "confirmed"
    assert result["dynamic_result"].verdict == VerificationVerdict.CONFIRMED
    assert result["iteration_history"] == [result["route"]]
    assert result["dynamic_iteration"] == 1


async def test_evaluate_route_hard_budget_cutoff_overrides_router_without_llm():
    """Even though the router would normally be consulted (oracle doesn't
    match, sink was reached), a spent dynamic_iteration budget is a hard
    deterministic cutoff — the router must never be called once the
    budget is exhausted (see this module's risk note: never trust the LLM
    alone to stop looping)."""
    observation = ObservationRecord()  # no signal, no artifacts -> no oracle match
    result = await _run_evaluate_route(
        deps=_deps(max_iterations=2),
        global_id="g1",
        plan=_plan(oracle="SIGSEGV"),
        observation=observation,
        reached=True,
        reached_sink=True,
        iteration=2,  # == max_iterations
    )
    assert result["route"].route == "inconclusive"
    assert result["dynamic_result"].verdict == VerificationVerdict.INCONCLUSIVE
    assert result["dynamic_result"].evidence["budget_exhausted"] is True


async def test_evaluate_route_not_reached_routes_to_retry_gdb_attach_without_llm():
    observation = ObservationRecord()
    result = await _run_evaluate_route(
        deps=_deps(max_iterations=5),
        global_id="g1",
        plan=_plan(oracle="SIGSEGV"),
        observation=observation,
        reached=False,
        reached_sink=False,
        iteration=1,
    )
    assert result["route"].route == "retry_gdb_attach"
    assert "dynamic_result" not in result  # non-terminal route -> no TrackResult yet


async def test_evaluate_route_falls_through_to_router_when_ambiguous():
    """Reached, sink reached, no oracle match, disconfirm_condition text
    doesn't match the conservative deterministic-refutation shape, budget
    not spent -> must consult the LLM router (proves the non-deterministic
    branch IS reachable, complementing the _NeverCalledLLM tests above)."""
    import json

    class _RouterLLM:
        def __init__(self):
            self.calls = 0

        async def ainvoke(self, messages, config=None):
            from langchain_core.messages import AIMessage

            self.calls += 1
            return AIMessage(
                content=json.dumps(
                    {"route": "retry_trigger", "diagnosis": "ambiguous", "confidence": "LOW"}
                )
            )

    router_llm = _RouterLLM()
    deps = DynamicGraphDeps(
        settings=Settings(_env_file=None, FWA_STAGE5_DYNAMIC_MAX_ITERATIONS=5),
        bringup_llm=_NeverCalledLLM(),
        trigger_llm=_NeverCalledLLM(),
        dynamic_evaluator_llm=router_llm,
        session_executor=None,
    )
    observation = ObservationRecord(stdout="nothing interesting")
    result = await _run_evaluate_route(
        deps=deps,
        global_id="g1",
        plan=_plan(oracle="SIGSEGV", disconfirm_condition="input is always escaped"),
        observation=observation,
        reached=True,
        reached_sink=True,
        iteration=1,
    )
    assert router_llm.calls == 1
    assert result["route"].route == "retry_trigger"
    assert "dynamic_result" not in result


# --------------------------------------------------------------------- #
# build_dynamic_graph — compiles with the expected node/edge shape
# --------------------------------------------------------------------- #


def test_build_dynamic_graph_compiles():
    from fw_audit.common.findings import (
        Confidence,
        Decision,
        EvidenceSpan,
        Finding,
        FindingSink,
        FindingSource,
        Severity,
    )
    from fw_audit.common.verification import TargetMeta
    from fw_audit.stage5_verification.candidate_index import VerificationCandidate
    from fw_audit.stage5_verification.fvvw.dynamic_track import BringupContext

    finding = Finding(
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
    candidate = VerificationCandidate(
        global_id="vulnbin#0000::candidate_001",
        chunk_id="vulnbin#0000",
        bin_id="vulnbin",
        finding=finding,
        source_path=None,
    )
    target = TargetMeta(
        arch="arm",
        endianness="little",
        is_64bit=False,
        pie=False,
        stripped=True,
        func_offset="0x1000",
        dispatch_resolvable=True,
    )
    plan = _plan()
    settings = Settings(_env_file=None)
    ctx = BringupContext(
        candidate=candidate,
        target=target,
        plan=plan,
        emulation_plan={"mode": "user", "arch_spec_key": ("arm", "little")},
        settings=settings,
        session_executor=None,
    )

    from fw_audit.stage5_verification.fvvw.dynamic_graph import build_dynamic_graph

    compiled = build_dynamic_graph(
        ctx=ctx,
        deps=_deps(),
        candidate=candidate,
        target=target,
        plan=plan,
        vuln_class=finding.category,
        sink_expression=finding.sink.expression,
    )
    node_names = set(compiled.get_graph().nodes.keys())
    for expected in (
        "plan_emulation",
        "plan_emulation_escalate",
        "bringup",
        "health_gate",
        "gdb_attach",
        "trigger",
        "evaluate_route",
    ):
        assert expected in node_names
