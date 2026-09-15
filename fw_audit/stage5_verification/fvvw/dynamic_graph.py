"""`build_dynamic_graph` — the dynamic track's compiled `StateGraph` (spec
Nodes 2-8), wiring the currently-aspirational `fvvw.state.FVVWState`'s
`dynamic_*` keys into real LangGraph nodes with conditional loop-back
edges, per the confirmed implementation direction (LangGraph StateGraph
over a hand-written async loop).

Mirrors `agent.graph.build_verifier_graph`'s shape exactly: a closure-based
factory function whose inner `*_node` functions capture their dependencies
(the `BringupContext`, resolved LLMs, `Settings`) by closure rather than
carrying them through graph state — graph state (`FVVWState`'s
`dynamic_*`/`emulation_plan`/`gdb_transcript`/`signals`/`observation`/
`route`/`iteration_history`/`dynamic_iteration` keys) carries only the
DATA each node produces, never live objects like a `SessionHandle` or a
`BaseChatModel`.

Node -> spec mapping:

    plan_emulation_node    -> spec Node 2  (deterministic; escalates to
                               direct_call when the router asks)
    bringup_node            -> spec Node 3  (agentic: dynamic_agents.
                               bringup_agent, then the deterministic
                               bringup_stabilize/_launch_qemu_and_wait
                               underneath it via BringupContext)
    health_gate_node        -> spec Node 4  (deterministic)
    gdb_attach_node         -> spec Node 5  (deterministic reach_target;
                               stripped-symbol fallback deferred to a
                               later iteration — see this module's
                               docstring note below)
    trigger_node            -> spec Node 6  (agentic: dynamic_agents.
                               trigger_agent, or the deterministic
                               instrument_trigger path when real payloads
                               are disabled)
    run_observe_node        -> spec Node 7  (deterministic: collect_
                               observation)
    evaluate_route_node     -> spec Node 8  (deterministic match_oracle
                               first pass; dynamic_agents.route_observation
                               LLM only when that doesn't settle it)

Node 9 (Report) stays OUTSIDE this graph — `fvvw.graph.run_fvvw` still
assembles the `FVVWReport` from this graph's terminal state exactly the
way it already assembles one from `run_dynamic_track_only`'s tuple return,
and `fvvw.report.write_report` is unchanged.

Repair back-edges (health_gate -> bringup, gdb_attach -> bringup on a
DynamicFault, trigger -> bringup on a DynamicFault) are real conditional
edges here — UNLIKE the pre-graph `run_dynamic_track_only`, which used
in-function `while` retry loops specifically to keep `BringupContext`'s
mutable session state naturally scoped (see the OLD `fvvw.graph` module
docstring). This graph keeps that same scoping by closing every node over
the SAME long-lived `BringupContext` instance (built once per graph
construction, exactly like `agent.graph`'s `cpg_build_holder`/`attempts`
lists) — a loop-back edge re-enters `bringup_node`, which mutates that
SAME `ctx` object, so a `SessionHandle` still never round-trips through
graph state as a value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from langchain_core.language_models import BaseChatModel

from fw_audit.common.verification import (
    DynamicPlan,
    ObservationRecord,
    RouteDecision,
    TargetMeta,
    TrackResult,
    VerificationVerdict,
)
from fw_audit.config.settings import Settings
from fw_audit.executors.sandbox_executor import SandboxExecutor
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.cmdlog import aphase
from fw_audit.stage5_verification.fvvw.dynamic_agents import (
    bringup_agent,
    route_observation,
    trigger_agent,
)
from fw_audit.stage5_verification.fvvw.dynamic_track import (
    BringupContext,
    BringupExhausted,
    DynamicFault,
    HealthGateFailure,
    cleanup_marker_artifact,
    collect_observation,
    health_gate,
    instrument_trigger,
    match_oracle,
    plan_emulation,
    reach_target,
    satisfy_guards,
)

# Terminal routes health_gate_node/evaluate_route_node can produce, sharing
# the same vocabulary `common.verification.RouteDecision.route` declares —
# used as the LangGraph conditional-edge return values.
_ROUTE_TO_NODE: dict[str, str] = {
    "confirmed": "__end__",
    "refuted": "__end__",
    "retry_bringup": "bringup",
    "retry_gdb_attach": "gdb_attach",
    "retry_trigger": "trigger",
    "escalate_direct_call": "plan_emulation_escalate",
    "inconclusive": "__end__",
}


@dataclass
class DynamicGraphDeps:
    """Every resolved dependency the dynamic graph's nodes need, built once
    per `run_dynamic_track_only` call — mirrors `fvvw.graph.FVVWDeps`'s own
    shape, narrowed to just what the dynamic track (not the static track or
    strategy/report roles) needs."""

    settings: Settings
    bringup_llm: BaseChatModel
    trigger_llm: BaseChatModel
    dynamic_evaluator_llm: BaseChatModel
    session_executor: SandboxExecutor


async def _run_bringup(
    ctx: BringupContext, *, deps: DynamicGraphDeps
) -> dict:
    """spec Node 3 body: run the agentic bring-up/arbitration loop
    (`dynamic_agents.bringup_agent`), then attempt the actual QEMU
    stand-up via the existing deterministic `bringup_stabilize` machinery
    UNDERNEATH it — the agent decides WHAT fixes to apply (dummy files,
    env overrides, ...), `bringup_stabilize`'s own launch-command assembly
    and readiness poll is what actually starts/relaunches QEMU with those
    fixes in effect. On a `BringupExhausted`, this node's own repair
    budget (mem.repair) is spent and the graph should terminate rather
    than loop again — surfaced as a `DynamicFault`-shaped dict the router
    recognizes."""
    from fw_audit.stage5_verification.fvvw.dynamic_track import bringup_stabilize

    async with aphase("bringup"):
        try:
            result = await bringup_agent(ctx, llm=deps.bringup_llm, settings=deps.settings)
        except DynamicFault:
            # agent couldn't even start (no session yet) — fall through to
            # bringup_stabilize itself starting one.
            result = None

        # bringup_stabilize itself can raise a bare DynamicFault (a staging
        # failure, or its OWN readiness-probe timeout via
        # _launch_qemu_and_wait) — retriable via the same repair-count
        # budget every other dynamic-track fault uses, not fatal on the
        # first attempt. Retry it in a bounded loop here rather than let it
        # escape this node uncaught: bringup_stabilize's own repair_count
        # check is what actually bounds this loop, raising BringupExhausted
        # (caught below) once Settings.stage5_bringup_max_repairs is spent —
        # see the pre-graph run_dynamic_track_only's identical handling of
        # this exact fault class (Bug C regression, test_fvvw_graph.py::
        # test_run_fvvw_recovers_from_dynamic_fault_raised_by_bringup_itself).
        try:
            while True:
                try:
                    await bringup_stabilize(ctx)
                    break
                except DynamicFault:
                    continue
        except BringupExhausted as exc:
            return {
                "dynamic_result": TrackResult(
                    verdict=VerificationVerdict.ERROR,
                    proved_hypothesis="none",
                    evidence={"reason": f"not_run: {exc}", "budget_exhausted": True},
                ),
                "arbitration_log": result.arbitration_log if result else None,
                "_bringup_exhausted": True,
            }

        await cleanup_marker_artifact(ctx)

        return {
            "arbitration_log": result.arbitration_log if result else None,
            "repair_applied_fixes": result.applied_fixes if result else [],
            "_bringup_exhausted": False,
        }


async def _run_health_gate(ctx: BringupContext) -> dict:
    """spec Node 4 body: the deterministic health checks. A failure routes
    back to Node 3 (bring-up) — recorded as a route decision so the
    iteration history is complete even for this non-LLM diagnosis."""
    async with aphase("health_gate"):
        try:
            await health_gate(ctx)
            return {"route": None, "_health_ok": True}
        except HealthGateFailure as exc:
            decision = RouteDecision(
                route="retry_bringup",
                diagnosis=f"health_gate failed: {exc.reason}",
                confidence="HIGH",
            )
            return {"route": decision, "iteration_history": [decision], "_health_ok": False}


async def _run_gdb_attach(
    ctx: BringupContext, *, transcript_so_far: str
) -> dict:
    """spec Node 5 body: attach + reach the functional entry
    (`reach_target`, reused unchanged). A `DynamicFault` here routes back
    to Node 3 — the existing `_looks_like_setup_fault` heuristic inside
    `reach_target` already distinguishes a genuine QEMU/GDB setup problem
    from "connected fine, breakpoint just never fired" (which is NOT a
    fault — that is Node 8's job to diagnose from `reached=False`).

    Stripped-symbol -> address fallback (spec Node 5's agent-fallback
    case) is NOT implemented in this graph revision — `reach_target`
    already resolves its entry address from `Settings`-independent facts
    (`plan.entry_addr` or `target.func_offset`, both supplied upstream by
    `characterize_target`/the strategy agent), so the symbol-resolution
    problem this fallback exists for is handled BEFORE this node runs, not
    inside it. Flagged here rather than silently omitted: a future
    revision wanting a true in-node symbol-recovery agent should add it as
    a new bounded loop in `dynamic_agents.py`, following the same shape as
    `bringup_agent`/`trigger_agent`, and call it from here when
    `reach_target` reports `reached=False` with no addr resolved at all.
    """
    async with aphase("gdb_attach"):
        try:
            transcript, reached = await reach_target(ctx, gdb_transcript_so_far=transcript_so_far)
            return {"gdb_transcript": transcript, "_reached": reached, "_gdb_fault": False}
        except DynamicFault as exc:
            decision = RouteDecision(
                route="retry_bringup",
                diagnosis=f"gdb_attach setup fault: {exc}",
                confidence="HIGH",
            )
            return {
                "route": decision,
                "iteration_history": [decision],
                "_gdb_fault": True,
                "gdb_transcript": transcript_so_far,
            }


async def _run_trigger(
    ctx: BringupContext,
    *,
    deps: DynamicGraphDeps,
    target: TargetMeta,
    plan: DynamicPlan,
    vuln_class: str,
    sink_expression: str,
    transcript_so_far: str,
) -> dict:
    """spec Node 6 body: satisfy guards (reused unchanged), then either the
    agentic trigger loop (`dynamic_agents.trigger_agent`, when real
    payloads are enabled) or the deterministic `instrument_trigger` path
    (benign-marker-only posture). A `DynamicFault` from either routes back
    to Node 3."""
    async with aphase("trigger"):
        try:
            transcript, guard_logs = await satisfy_guards(
                ctx, gdb_transcript_so_far=transcript_so_far
            )
        except DynamicFault as exc:
            decision = RouteDecision(
                route="retry_bringup",
                diagnosis=f"satisfy_guards setup fault: {exc}",
                confidence="HIGH",
            )
            return {
                "route": decision,
                "iteration_history": [decision],
                "_trigger_fault": True,
                "gdb_transcript": transcript_so_far,
            }

        try:
            if deps.settings.stage5_allow_real_payloads:
                result = await trigger_agent(
                    ctx,
                    llm=deps.trigger_llm,
                    settings=deps.settings,
                    target=target,
                    plan=plan,
                    vuln_class=vuln_class,
                    sink_expression=sink_expression,
                )
                observation = result.observation
                gdb_transcript = transcript + result.gdb_transcript
                reached_sink = observation.faulting_pc is not None or bool(
                    observation.filesystem_artifacts
                )
            else:
                trig_transcript, captured = await instrument_trigger(
                    ctx, gdb_transcript_so_far=transcript
                )
                gdb_transcript = trig_transcript
                observation = await collect_observation(
                    ctx, result_stdout=trig_transcript, result_stderr=""
                )
                reached_sink = captured is not None
        except DynamicFault as exc:
            decision = RouteDecision(
                route="retry_bringup",
                diagnosis=f"instrument_trigger setup fault: {exc}",
                confidence="HIGH",
            )
            return {
                "route": decision,
                "iteration_history": [decision],
                "_trigger_fault": True,
                "gdb_transcript": transcript,
            }

        return {
            "gdb_transcript": gdb_transcript,
            "observation": observation,
            "signals": guard_logs,
            "_reached_sink": reached_sink,
            "_trigger_fault": False,
        }


async def _run_evaluate_route(
    *,
    deps: DynamicGraphDeps,
    global_id: str,
    plan: DynamicPlan,
    observation: ObservationRecord,
    reached: bool,
    reached_sink: bool,
    iteration: int,
) -> dict:
    """spec Node 8 body: the deterministic oracle-match first pass, then
    the LLM router only when that doesn't settle the round. Always returns
    a `RouteDecision`, appended to `iteration_history` either way — the
    spec's "Iteration history" report requirement covers BOTH the cheap
    deterministic matches and the LLM-diagnosed ones, not just the latter.
    """
    async with aphase("evaluate_route"):
        oracle = plan.oracle or plan.decisive_observable
        max_iterations = deps.settings.stage5_dynamic_max_iterations
        if match_oracle(observation, oracle):
            decision = RouteDecision(
                route="confirmed",
                diagnosis=f"deterministic oracle match: {oracle!r}",
                confidence="HIGH",
            )
        elif iteration >= max_iterations:
            # Hard deterministic cutoff — never trust the LLM router alone
            # to stop looping (spec's "a stuck run terminates INCONCLUSIVE,
            # never loops forever"; see this module's risk note). The
            # router is still given max_iterations/iteration in its own
            # prompt so it can choose to converge early, but once the
            # budget is actually spent this branch overrides whatever the
            # router would have said.
            decision = RouteDecision(
                route="inconclusive",
                diagnosis=f"dynamic_iteration budget exhausted ({iteration}/{max_iterations}) "
                "without a decisive oracle match.",
                confidence="HIGH",
            )
        elif observation.memory_diff_detected is False and reached_sink and (
            "safe" in plan.disconfirm_condition.lower()
            or "bounds" in plan.disconfirm_condition.lower()
        ) and observation.signal is None:
            # A conservative, purely deterministic refutation shape: sink
            # reached, no crash, no memory corruption observed, AND the
            # plan's own disconfirm_condition text already describes a
            # "safely handled" scenario — still requires the LLM router to
            # confirm/diagnose rather than auto-refuting from this alone
            # (spec's "no crash" is not automatically proof of safety);
            # falls through to the router below like every other
            # non-oracle-matching case.
            decision = await route_observation(
                llm=deps.dynamic_evaluator_llm,
                settings=deps.settings,
                global_id=global_id,
                oracle=oracle,
                disconfirm_condition=plan.disconfirm_condition,
                observation=observation,
                reached_sink=reached_sink,
                breakpoint_hit=reached,
                iteration=iteration,
                max_iterations=max_iterations,
            )
        elif not reached:
            decision = RouteDecision(
                route="retry_gdb_attach",
                diagnosis="breakpoint never hit this round — wrong sink location, "
                "missing symbol, or input never reached that code path.",
                confidence="MEDIUM",
            )
        else:
            decision = await route_observation(
                llm=deps.dynamic_evaluator_llm,
                settings=deps.settings,
                global_id=global_id,
                oracle=oracle,
                disconfirm_condition=plan.disconfirm_condition,
                observation=observation,
                reached_sink=reached_sink,
                breakpoint_hit=reached,
                iteration=iteration,
                max_iterations=max_iterations,
            )

        result: dict = {
            "route": decision,
            "iteration_history": [decision],
            "dynamic_iteration": iteration,
        }
        if decision.route in _TERMINAL_ROUTES:
            result["dynamic_result"] = _build_track_result(
                decision, observation, iteration=iteration
            )
        return result


_TERMINAL_ROUTES: dict[str, tuple[VerificationVerdict, str]] = {
    "confirmed": (VerificationVerdict.CONFIRMED, "A"),
    "refuted": (VerificationVerdict.REFUTED, "B"),
    "inconclusive": (VerificationVerdict.INCONCLUSIVE, "none"),
}
"""Maps a terminal `RouteDecision.route` to the `(verdict, proved_hypothesis)`
pair `_build_track_result` stamps onto the final `TrackResult` — the same
three-way split `dynamic_track._terminal` used pre-rewrite, now keyed off
the LLM router's/oracle-match's route instead of the old rule engine's own
branches."""


def _build_track_result(
    decision: RouteDecision, observation: ObservationRecord, *, iteration: int
) -> TrackResult:
    """Node 8's terminal-route case: turn a `confirmed`/`refuted`/
    `inconclusive` `RouteDecision` (which itself carries no verdict, only a
    routing instruction — see `RouteDecision`'s own docstring) plus the
    round's `ObservationRecord` into the `TrackResult` `fvvw.graph`/
    `fvvw.joint.joint_evaluate` need. Mirrors `dynamic_track._terminal`'s
    evidence shape (`reason`, `budget_exhausted` for INCONCLUSIVE) so
    `write_report`/HITL's budget-exhaustion trigger keep working unchanged
    against the new graph's output."""
    verdict, proved_hypothesis = _TERMINAL_ROUTES[decision.route]
    evidence: dict = {"reason": decision.diagnosis} if decision.diagnosis else {}
    if observation.faulting_pc:
        evidence["faulting_pc"] = observation.faulting_pc
    if observation.signal:
        evidence["signal"] = observation.signal
    if observation.filesystem_artifacts:
        evidence["filesystem_artifacts"] = observation.filesystem_artifacts
    if observation.memory_diff_detected:
        evidence["memory_diff_detected"] = observation.memory_diff_detected
    if verdict == VerificationVerdict.INCONCLUSIVE:
        # Same explicit fact-tag `dynamic_track._terminal` sets — HITL's
        # `is_budget_exhausted` trigger (`fvvw.hitl`) reads this key, not
        # a re-derivation of "verdict == INCONCLUSIVE" at the call site.
        evidence["budget_exhausted"] = True
    return TrackResult(
        verdict=verdict,
        proved_hypothesis=proved_hypothesis,
        evidence=evidence,
        iters_used=iteration,
    )


def route_after_bringup(state: dict) -> Literal["health_gate", "__end__"]:
    """`_run_bringup` sets `_bringup_exhausted=True` (with `dynamic_result`
    already a terminal ERROR `TrackResult`) once `bringup_stabilize`'s own
    repair-count budget (`Settings.stage5_bringup_max_repairs`) is spent —
    routing into `health_gate` anyway would just re-fail against a session
    that never started and loop back here, silently re-spending time
    without ever changing the already-terminal `dynamic_result`. End the
    graph immediately instead, exactly like the pre-rewrite
    `run_dynamic_track_only`'s own `except BringupExhausted` early return."""
    return "__end__" if state.get("_bringup_exhausted") else "health_gate"


def route_after_health_gate(state: dict) -> Literal["gdb_attach", "bringup"]:
    return "gdb_attach" if state.get("_health_ok") else "bringup"


def route_after_gdb_attach(state: dict) -> Literal["trigger", "bringup", "evaluate_route"]:
    if state.get("_gdb_fault"):
        return "bringup"
    # Even when the breakpoint never hit (_reached is False), proceed to
    # trigger/evaluate rather than looping locally — Node 8 is the ONLY
    # place that decides whether "not reached" means retry_gdb_attach vs.
    # something else, per the spec's decision table (never decided inline
    # here by a bare bool).
    return "trigger"


def route_after_trigger(state: dict) -> Literal["evaluate_route", "bringup"]:
    return "bringup" if state.get("_trigger_fault") else "evaluate_route"


def route_after_evaluate(
    state: dict,
) -> Literal["bringup", "gdb_attach", "trigger", "plan_emulation_escalate", "__end__"]:
    decision: RouteDecision | None = state.get("route")
    if decision is None:
        return "__end__"
    return _ROUTE_TO_NODE.get(decision.route, "__end__")  # type: ignore[return-value]


def build_dynamic_graph(
    *,
    ctx: BringupContext,
    deps: DynamicGraphDeps,
    candidate: VerificationCandidate,
    target: TargetMeta,
    plan: DynamicPlan,
    vuln_class: str,
    sink_expression: str,
):
    """Construct (compiled) the dynamic track's `StateGraph` for ONE
    candidate — mirrors `agent.graph.build_verifier_graph`'s closure-based
    factory shape exactly. `ctx` is the SAME `BringupContext` instance
    across every node/loop-back (see this module's docstring on why that
    preserves the old in-function-loop's session-state scoping)."""
    from langgraph.graph import END, StateGraph

    from fw_audit.stage5_verification.fvvw.state import FVVWState

    async def plan_emulation_node(state: FVVWState) -> dict:
        result = plan_emulation(target, plan)
        ctx.emulation_plan = result["emulation_plan"]
        return result

    async def plan_emulation_escalate_node(state: FVVWState) -> dict:
        """Re-entry point for the router's `escalate_direct_call` route —
        forces `emulation_mode="direct_call"` and routes straight back to
        bringup so a NEW session stands up under that mode."""
        result = plan_emulation(target, plan, escalate_to_direct_call=True)
        ctx.emulation_plan = result["emulation_plan"]
        return result

    async def bringup_node(state: FVVWState) -> dict:
        return await _run_bringup(ctx, deps=deps)

    async def health_gate_node(state: FVVWState) -> dict:
        return await _run_health_gate(ctx)

    async def gdb_attach_node(state: FVVWState) -> dict:
        transcript_so_far = state.get("gdb_transcript", "") or ""
        result = await _run_gdb_attach(ctx, transcript_so_far=transcript_so_far)
        ctx._last_reached = result.get("_reached", False)  # type: ignore[attr-defined]
        return result

    async def trigger_node(state: FVVWState) -> dict:
        transcript_so_far = state.get("gdb_transcript", "") or ""
        return await _run_trigger(
            ctx,
            deps=deps,
            target=target,
            plan=plan,
            vuln_class=vuln_class,
            sink_expression=sink_expression,
            transcript_so_far=transcript_so_far,
        )

    async def evaluate_route_node(state: FVVWState) -> dict:
        iteration = state.get("dynamic_iteration", 0) + 1
        observation = state.get("observation") or ObservationRecord()
        reached = getattr(ctx, "_last_reached", False)
        reached_sink = state.get("_reached_sink", reached)
        return await _run_evaluate_route(
            deps=deps,
            global_id=candidate.global_id,
            plan=plan,
            observation=observation,
            reached=reached,
            reached_sink=bool(reached_sink),
            iteration=iteration,
        )

    graph = StateGraph(FVVWState)
    graph.add_node("plan_emulation", plan_emulation_node)
    graph.add_node("plan_emulation_escalate", plan_emulation_escalate_node)
    graph.add_node("bringup", bringup_node)
    graph.add_node("health_gate", health_gate_node)
    graph.add_node("gdb_attach", gdb_attach_node)
    graph.add_node("trigger", trigger_node)
    graph.add_node("evaluate_route", evaluate_route_node)

    graph.set_entry_point("plan_emulation")
    graph.add_edge("plan_emulation", "bringup")
    graph.add_edge("plan_emulation_escalate", "bringup")
    graph.add_conditional_edges(
        "bringup",
        route_after_bringup,
        {"health_gate": "health_gate", "__end__": END},
    )
    graph.add_conditional_edges(
        "health_gate",
        route_after_health_gate,
        {"gdb_attach": "gdb_attach", "bringup": "bringup"},
    )
    graph.add_conditional_edges(
        "gdb_attach",
        route_after_gdb_attach,
        {"trigger": "trigger", "bringup": "bringup", "evaluate_route": "evaluate_route"},
    )
    graph.add_conditional_edges(
        "trigger",
        route_after_trigger,
        {"evaluate_route": "evaluate_route", "bringup": "bringup"},
    )
    graph.add_conditional_edges(
        "evaluate_route",
        route_after_evaluate,
        {
            "bringup": "bringup",
            "gdb_attach": "gdb_attach",
            "trigger": "trigger",
            "plan_emulation_escalate": "plan_emulation_escalate",
            "__end__": END,
        },
    )

    return graph.compile()


__all__ = [
    "DynamicGraphDeps",
    "build_dynamic_graph",
    "route_after_bringup",
    "route_after_evaluate",
    "route_after_gdb_attach",
    "route_after_health_gate",
    "route_after_trigger",
]
