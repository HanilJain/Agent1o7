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
    VerificationState,
    VerificationVerdict,
)
from fw_audit.config.settings import Settings
from fw_audit.stage5_verification.fvvw.dynamic_graph import (
    _TERMINAL_ROUTES,
    DynamicGraphDeps,
    _build_track_result,
    _run_evaluate_route,
    _update_state_for_round,
    route_after_bringup,
    route_after_evaluate,
    route_after_gdb_attach,
    route_after_health_gate,
    route_after_resolve_address,
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


# ---------------------------------------------------------------------- #
# P0-2 regression: an UnresolvedPlanFault-shaped fault must route to
# resolve_address, never bringup — retry_bringup can never fix an address
# the strategy agent never resolved (the DIR-825 incident's actual failure
# mode). route_after_gdb_attach/route_after_trigger now follow the ACTUAL
# route `_run_gdb_attach`/`_run_trigger` set on state["route"], instead of
# hardcoding every fault to "bringup".
# ---------------------------------------------------------------------- #


def test_route_after_gdb_attach_unresolved_plan_fault_goes_to_resolve_address():
    decision = RouteDecision(
        route="resolve_address", diagnosis="unresolved entry_addr", confidence="HIGH"
    )
    assert (
        route_after_gdb_attach({"_gdb_fault": True, "route": decision}) == "resolve_address"
    )


def test_route_after_gdb_attach_genuine_setup_fault_still_goes_to_bringup():
    decision = RouteDecision(
        route="retry_bringup", diagnosis="connection refused", confidence="HIGH"
    )
    assert route_after_gdb_attach({"_gdb_fault": True, "route": decision}) == "bringup"


def test_route_after_gdb_attach_fault_with_no_route_falls_back_to_bringup():
    # Defensive fallback — should never happen in practice (every fault
    # branch sets "route"), but must not crash if it does.
    assert route_after_gdb_attach({"_gdb_fault": True}) == "bringup"


def test_route_after_gdb_attach_blocked_by_prior_instrumentation_failure():
    """P1-3: when a PRIOR round already demonstrated instrumentation is
    broken, this round must skip the expensive trigger loop and go
    straight to evaluate_route instead — even though THIS round's
    gdb_attach itself didn't raise a fault."""
    assert (
        route_after_gdb_attach({"_gdb_fault": False, "_instrumentation_blocked": True})
        == "evaluate_route"
    )


def test_route_after_gdb_attach_not_blocked_proceeds_to_trigger():
    assert (
        route_after_gdb_attach({"_gdb_fault": False, "_instrumentation_blocked": False})
        == "trigger"
    )


def test_route_after_trigger_unresolved_plan_fault_goes_to_resolve_address():
    decision = RouteDecision(
        route="resolve_address", diagnosis="unresolved sink_addr", confidence="HIGH"
    )
    assert route_after_trigger({"_trigger_fault": True, "route": decision}) == "resolve_address"


def test_route_after_trigger_genuine_setup_fault_still_goes_to_bringup():
    decision = RouteDecision(
        route="retry_bringup", diagnosis="connection refused", confidence="HIGH"
    )
    assert route_after_trigger({"_trigger_fault": True, "route": decision}) == "bringup"


def test_route_after_resolve_address_unresolvable_escalates():
    assert (
        route_after_resolve_address({"_entry_addr_unresolvable": True})
        == "plan_emulation_escalate"
    )


def test_route_after_resolve_address_resolved_proceeds_to_gdb_attach():
    assert route_after_resolve_address({"_entry_addr_unresolvable": False}) == "gdb_attach"
    assert route_after_resolve_address({}) == "gdb_attach"


# ---------------------------------------------------------------------- #
# _update_state_for_round — P1-1/P1-2: an instrumentation failure must
# never be conflated with an ordinary breakpoint miss.
# ---------------------------------------------------------------------- #


def _plan(**overrides) -> DynamicPlan:
    defaults = dict(reach_strategy="inferior_call", decisive_observable="obs")
    defaults.update(overrides)
    return DynamicPlan(**defaults)


def test_update_state_for_round_instrumentation_failure_leaves_breakpoint_unset():
    state = VerificationState(global_id="t")
    observation = ObservationRecord(
        instrumentation_ok=False,
        instrumentation_error="gdb: no symbol table is loaded",
    )
    new_state = _update_state_for_round(
        state, plan=_plan(), observation=observation, reached=False,
        reached_sink=False, emulation_mode="user",
    )
    # Never "missed" — that implies GDB successfully set the breakpoint
    # and the process ran past it; instrumentation never got that far.
    assert new_state.breakpoint_status == "unset"
    assert new_state.instrumentation_failures == 1
    assert "no symbol table" in new_state.failure_reason.lower()


def test_update_state_for_round_instrumentation_failures_accumulate_and_reset():
    state = VerificationState(global_id="t")
    failing_observation = ObservationRecord(instrumentation_ok=False)
    state = _update_state_for_round(
        state, plan=_plan(), observation=failing_observation, reached=False,
        reached_sink=False, emulation_mode="user",
    )
    state = _update_state_for_round(
        state, plan=_plan(), observation=failing_observation, reached=False,
        reached_sink=False, emulation_mode="user",
    )
    assert state.instrumentation_failures == 2

    ok_observation = ObservationRecord(instrumentation_ok=True)
    state = _update_state_for_round(
        state, plan=_plan(), observation=ok_observation, reached=False,
        reached_sink=False, emulation_mode="user",
    )
    assert state.instrumentation_failures == 0


def test_update_state_for_round_ordinary_miss_still_sets_missed():
    """A round where instrumentation WORKED but the breakpoint just wasn't
    hit yet must still advance breakpoint_status to 'missed' — the
    ordinary case this fix must not disturb."""
    state = VerificationState(global_id="t")
    observation = ObservationRecord(instrumentation_ok=True)
    new_state = _update_state_for_round(
        state, plan=_plan(), observation=observation, reached=False,
        reached_sink=False, emulation_mode="user",
    )
    assert new_state.breakpoint_status == "missed"
    assert new_state.instrumentation_failures == 0


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


def test_confirmed_route_refused_on_empty_observation():
    """T1-B defense in depth: even if some future bug lets a `confirmed`
    RouteDecision reach `_build_track_result` with an observation carrying
    NO positive evidence (no signal, no filesystem_artifacts, no captured
    sink argument via reached_sink, no memory diff), the verdict is
    downgraded to INCONCLUSIVE — never a persisted CONFIRMED TrackResult
    built on an empty observation. This is the exact DIR-825 fingerprint:
    a route claims confirmed but the ObservationRecord backing it is
    empty."""
    decision = RouteDecision(
        route="confirmed", diagnosis="deterministic oracle match: 'X'", confidence="HIGH"
    )
    empty_observation = ObservationRecord()  # signal=None, no artifacts, no memory diff
    result = _build_track_result(
        decision, empty_observation, iteration=1, reached_sink=False
    )
    assert result.verdict == VerificationVerdict.INCONCLUSIVE
    assert result.proved_hypothesis == "none"
    assert result.evidence["budget_exhausted"] is True
    assert "empty observation" in result.evidence["reason"].lower()


def test_confirmed_route_allowed_when_reached_sink_true():
    """The positive counterpart: a `confirmed` route with `reached_sink=
    True` (a genuinely captured sink argument, even with no crash signal)
    is NOT downgraded — reached_sink is one of T1-B's four positive-
    evidence signals."""
    decision = RouteDecision(route="confirmed", diagnosis="d", confidence="HIGH")
    result = _build_track_result(
        decision, ObservationRecord(), iteration=1, reached_sink=True
    )
    assert result.verdict == VerificationVerdict.CONFIRMED


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


async def test_process_exit_before_bp_routes_to_escalate():
    """T1-E: an observation showing `process_exited_before_bp=True`
    (the process died during startup/dispatch, before ever reaching the
    entry/sink breakpoint) must route to `escalate_direct_call` — NEVER
    `retry_gdb_attach`, which would re-attach to the same already-dead
    process forever until the budget forces INCONCLUSIVE (the DIR-825
    incident's actual failure loop). Checked entirely deterministically,
    via `fvvw.supervisor.propose_action` — no LLM call needed."""
    observation = ObservationRecord(process_exited_before_bp=True)
    result = await _run_evaluate_route(
        deps=_deps(max_iterations=5),
        global_id="g1",
        plan=_plan(oracle="SIGSEGV"),
        observation=observation,
        reached=False,
        reached_sink=False,
        iteration=1,
    )
    assert result["route"].route == "escalate_direct_call"
    assert "dynamic_result" not in result  # not a terminal route


async def test_evaluate_route_persists_verification_state_across_rounds():
    """T3-O: the canonical VerificationState returned in one round's
    result must be exactly what a caller passes back in as the NEXT
    round's `verification_state` — proving the state genuinely
    accumulates (attempt_history grows) rather than resetting each
    call."""
    deps = _deps(max_iterations=10)
    plan = _plan(oracle="SIGSEGV")
    observation = ObservationRecord()  # never matches, never has evidence

    state = None
    for i in range(1, 4):
        result = await _run_evaluate_route(
            deps=deps,
            global_id="g1",
            plan=plan,
            observation=observation,
            reached=False,
            reached_sink=False,
            iteration=i,
            verification_state=state,
        )
        state = result["verification_state"]
        assert state is not None

    # Three rounds of an unchanging "not reached" condition must have
    # accumulated attempt history — proving persistence, not a fresh
    # state each call.
    assert len(state.attempt_history) == 3


async def test_confirmed_refused_without_evidence_via_supervisor(monkeypatch):
    """Rejection of confirmation without evidence, exercised through the
    FULL `_run_evaluate_route` pipeline (not `_build_track_result` in
    isolation — see `test_confirmed_route_refused_on_empty_observation`/
    `test_confirmed_route_allowed_when_reached_sink_true` for that layer
    directly). `match_oracle`'s own current implementation makes
    `oracle_hit=True` co-occurring with `has_evidence=False` structurally
    unreachable (every one of its positive-match branches requires a
    fact that ALSO satisfies `_has_positive_evidence`) — this is
    deliberate defense in depth against a FUTURE bug in `match_oracle`
    (a new oracle shape that doesn't require positive evidence), so this
    test forces that hypothetical case directly by monkeypatching `match_
    oracle` to return True unconditionally, then asserts the pipeline
    still refuses to confirm on the empty observation and does not crash
    or silently fall through to a bare LLM call either."""
    from fw_audit.stage5_verification.fvvw import dynamic_graph as dynamic_graph_module

    monkeypatch.setattr(dynamic_graph_module, "match_oracle", lambda observation, plan: True)

    result = await _run_evaluate_route(
        deps=_deps(max_iterations=5),
        global_id="g1",
        plan=_plan(oracle="SIGSEGV"),
        observation=ObservationRecord(),  # empty — no signal/artifacts/memory diff
        reached=False,
        reached_sink=False,
        iteration=1,
    )
    assert result["route"].route != "confirmed"
    if "dynamic_result" in result:
        assert result["dynamic_result"].verdict != VerificationVerdict.CONFIRMED


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
