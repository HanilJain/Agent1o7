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
    VerificationState,
    VerificationVerdict,
)
from fw_audit.config.settings import Settings
from fw_audit.executors.sandbox_executor import SandboxExecutor
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.cmdlog import CommandLog, aphase
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
    UnresolvedPlanFault,
    cleanup_marker_artifact,
    collect_observation,
    health_gate,
    instrument_trigger,
    match_oracle,
    plan_emulation,
    reach_target,
    restart_session,
    satisfy_guards,
)
from fw_audit.stage5_verification.fvvw.supervisor import (
    propose_action,
    record_attempt,
    validate_action,
)
from fw_audit.stage5_verification.llm_logging import LoggingChatModel
from fw_audit.stage5_verification.tools.qemu_gdb_tool import is_resolved_addr

# Terminal routes health_gate_node/evaluate_route_node can produce, sharing
# the same vocabulary `common.verification.RouteDecision.route` declares —
# used as the LangGraph conditional-edge return values. Tier 3 additions
# (T3-N — see `fvvw.supervisor`'s module docstring for the full
# separation-of-concerns rationale): `resolve_address` re-runs T2-F sink
# resolution before returning to Node 5; `restart_execution` returns to
# `bringup` but with a FRESH session (`restart_session`, called from
# `bringup_node` itself when it sees this route — see that node's own
# body), distinct from `retry_bringup`'s repair-in-place semantics.
# `"escalate"` is deliberately ABSENT here — `fvvw.supervisor.
# validate_action` always resolves it into a concrete route
# (`escalate_direct_call` or `inconclusive`) before a `RouteDecision`
# carrying it can ever reach this dict.
_ROUTE_TO_NODE: dict[str, str] = {
    "confirmed": "__end__",
    "refuted": "__end__",
    "retry_bringup": "bringup",
    "retry_gdb_attach": "gdb_attach",
    "retry_trigger": "trigger",
    "escalate_direct_call": "plan_emulation_escalate",
    "inconclusive": "__end__",
    "resolve_address": "resolve_address",
    "restart_execution": "bringup",
}


@dataclass
class DynamicGraphDeps:
    """Every resolved dependency the dynamic graph's nodes need, built once
    per `run_dynamic_track_only` call — mirrors `fvvw.graph.FVVWDeps`'s own
    shape, narrowed to just what the dynamic track (not the static track or
    strategy/report roles) needs.

    `command_log`, when given, is threaded into `bringup_agent`/
    `trigger_agent`/`route_observation` (via `_run_bringup`/`_run_trigger`/
    `_run_evaluate_route` below) so each agentic loop can log+live-print its
    own PARSED per-turn action/decision — the "after parser" half these
    three roles had zero visibility into before (see `dynamic_agents.py`'s
    module docstring; the log already carries its own `gid` from
    construction — see `cmdlog.CommandLog` — so nothing else here needs
    one). `command_log=None` (the default, e.g. a caller that never
    resolved one) skips this — every `dynamic_agents.py` function treats it
    as optional."""

    settings: Settings
    bringup_llm: BaseChatModel | LoggingChatModel
    trigger_llm: BaseChatModel | LoggingChatModel
    dynamic_evaluator_llm: BaseChatModel | LoggingChatModel
    session_executor: SandboxExecutor
    command_log: CommandLog | None = None


async def _run_bringup(
    ctx: BringupContext, *, deps: DynamicGraphDeps
) -> dict:
    """spec Node 3 body: provision a live session, run the agentic
    bring-up/arbitration loop (`dynamic_agents.bringup_agent`) against it,
    then attempt the actual QEMU stand-up via the existing deterministic
    `bringup_stabilize` machinery UNDERNEATH it — the agent decides WHAT
    fixes to apply (dummy files, env overrides, ...), `bringup_stabilize`'s
    own launch-command assembly and readiness poll is what actually
    starts/relaunches QEMU with those fixes in effect. On a
    `BringupExhausted`, this node's own repair budget (mem.repair) is
    spent and the graph should terminate rather than loop again — surfaced
    as a `DynamicFault`-shaped dict the router recognizes.

    `ensure_session(ctx)` runs FIRST, before `bringup_agent` — a fixed
    ordering bug: `bringup_agent` raises immediately when `ctx.handle is
    None` (see its own docstring), and the session handle used to only
    ever get created *inside* `bringup_stabilize`, which ran AFTER the
    agent. On every fresh candidate that meant the agent's `ctx.handle is
    None` check always fired, `bringup_agent` never got to run a single
    turn, and the "LLM decides what to fix" half of Node 3 was dead code —
    only the deterministic launch/retry loop underneath it ever executed.
    Calling `ensure_session` here first means the agent's discovery/repair
    tools (`run_strace_discovery`, `create_dummy_file`, `relaunch_and_
    check`, ...) always have a real session to drive."""
    from fw_audit.stage5_verification.fvvw.dynamic_track import (
        bringup_stabilize,
        ensure_session,
    )

    async with aphase("bringup"):
        result = None  # bound up front — several except branches below
        # read it, and bringup_agent() can fail before ever assigning it
        # (e.g. relaunch_and_check hitting a BringupExhausted precondition
        # deep inside the agent's own tool loop).
        try:
            await ensure_session(ctx)

            result = await bringup_agent(
                ctx,
                llm=deps.bringup_llm,
                settings=deps.settings,
                command_log=deps.command_log,
            )

            # bringup_stabilize itself can raise a bare DynamicFault (a
            # staging failure, or its OWN readiness-probe timeout via
            # _launch_qemu_and_wait) — retriable via the same repair-count
            # budget every other dynamic-track fault uses, not fatal on
            # the first attempt. Retry it in a bounded loop here rather
            # than let it escape this node uncaught: bringup_stabilize's
            # own repair_count check is what actually bounds this loop,
            # raising BringupExhausted (caught below) once Settings.
            # stage5_bringup_max_repairs is spent — see the pre-graph
            # run_dynamic_track_only's identical handling of this exact
            # fault class (Bug C regression, test_fvvw_graph.py::
            # test_run_fvvw_recovers_from_dynamic_fault_raised_by_bringup_
            # itself). Additionally: if the SAME fault signature fires
            # twice in a row with no new fix applied in between
            # (`ctx.no_progress_since_last_fault()`), stop retrying early
            # rather than spend the rest of the budget re-running an
            # unchanged failure — the diagnosis from the classified fault
            # is what makes it into BringupExhausted's message either way.
            while True:
                try:
                    await bringup_stabilize(ctx)
                    break
                except DynamicFault as exc:
                    if ctx.no_progress_since_last_fault():
                        signature = ctx.fault_log[-1][0] if ctx.fault_log else str(exc)
                        raise BringupExhausted(
                            f"{ctx.candidate.global_id}: repair attempt made no "
                            f"progress against a repeated bring-up fault — "
                            f"{signature}"
                        ) from exc
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
        except DynamicFault:
            # ensure_session's own start() failing raises a plain
            # RuntimeError (uncaught, matching pre-existing behavior — see
            # SandboxExecutor.start()'s docstring), so the only DynamicFault
            # that can reach here is bringup_agent's "no active session"
            # guard — now unreachable in normal operation since
            # ensure_session runs first, but kept as a defensive fallback
            # in case a future caller invokes bringup_agent without it.
            result = None

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
        except UnresolvedPlanFault as exc:
            # An unresolved entry_addr is a PLAN problem, not an
            # environment problem — retry_bringup can never fix an address
            # the strategy agent never resolved (the DIR-825 incident's
            # actual failure mode: `entry_addr="unspecified"` retried
            # against `retry_gdb_attach`/`retry_bringup` for 10 rounds with
            # no possible resolution). Route to `resolve_address` instead,
            # which falls `entry_addr` back to `target.func_offset` — if
            # THAT is also unresolved, `resolve_address_node` itself routes
            # onward to escalation rather than bouncing back here forever.
            decision = RouteDecision(
                route="resolve_address",
                diagnosis=f"gdb_attach: unresolved plan address, cannot instrument: {exc}",
                confidence="HIGH",
            )
            return {
                "route": decision,
                "iteration_history": [decision],
                "_gdb_fault": True,
                "gdb_transcript": transcript_so_far,
            }
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
        except UnresolvedPlanFault as exc:
            decision = RouteDecision(
                route="resolve_address",
                diagnosis=f"satisfy_guards: unresolved plan address, cannot instrument: {exc}",
                confidence="HIGH",
            )
            return {
                "route": decision,
                "iteration_history": [decision],
                "_trigger_fault": True,
                "gdb_transcript": transcript_so_far,
            }
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
                    command_log=deps.command_log,
                )
                observation = result.observation
                gdb_transcript = transcript + result.gdb_transcript
                reached_sink = observation.faulting_pc is not None or bool(
                    observation.filesystem_artifacts
                )
                if result.is_direct_call:
                    # T2-H: whatever this round's ObservationRecord shows,
                    # it came from a DIRECT invocation (GDB `call`), never
                    # a realistic end-to-end trigger — force the emulation
                    # mode label to reflect that regardless of what
                    # `ctx.emulation_plan["mode"]` happened to be set to
                    # (a trigger agent may choose deliver_via_direct_call
                    # for its OWN trigger_shape reasons even when the
                    # emulation MODE itself never escalated to
                    # direct_call). `fvvw.report`/`FVVWReport.
                    # emulation_mode` reads this straight off `ctx.
                    # emulation_plan`, so a reader can never mistake this
                    # for a realistic front-door reach.
                    ctx.emulation_plan["mode"] = "direct_call"
            else:
                trig_transcript, captured = await instrument_trigger(
                    ctx, gdb_transcript_so_far=transcript
                )
                gdb_transcript = trig_transcript
                observation = await collect_observation(
                    ctx, result_stdout=trig_transcript, result_stderr=""
                )
                reached_sink = captured is not None
        except UnresolvedPlanFault as exc:
            decision = RouteDecision(
                route="resolve_address",
                diagnosis=f"instrument_trigger: unresolved plan address, cannot instrument: "
                f"{exc}",
                confidence="HIGH",
            )
            return {
                "route": decision,
                "iteration_history": [decision],
                "_trigger_fault": True,
                "gdb_transcript": transcript,
            }
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


def _has_positive_evidence(observation: ObservationRecord, *, reached_sink: bool) -> bool:
    """T1-B's positive-evidence test, shared by BOTH choke points
    (`_run_evaluate_route`'s confirm-gate below AND `_build_track_result`'s
    own defense-in-depth refusal) so the two can never quietly drift apart
    on what "positive evidence" means. `True` only when the round carries
    at least one STRUCTURED, harness-derived fact: a captured crash
    signal, a captured filesystem artifact, a detected memory diff, or a
    genuinely reached sink with a captured argument (`reached_sink`,
    already computed by the caller from `observation.faulting_pc is not
    None or bool(observation.filesystem_artifacts)`/`captured is not
    None` — see `_run_trigger`). An empty observation with NONE of these
    — the exact DIR-825 fingerprint — is never positive evidence, no
    matter what a deterministic match or an LLM router's own confidence
    claims."""
    return bool(
        observation.signal
        or observation.filesystem_artifacts
        or observation.memory_diff_detected
        or reached_sink
    )


def _update_state_for_round(
    state: VerificationState,
    *,
    plan: DynamicPlan,
    observation: ObservationRecord,
    reached: bool,
    reached_sink: bool,
    emulation_mode: str,
) -> VerificationState:
    """Fold this round's already-gathered structured facts
    (`observation`/`reached`/`reached_sink`, all produced by harness code
    earlier this SAME round — `collect_observation`/`reach_target`) into
    the canonical `VerificationState`, WITHOUT going through `fvvw.
    supervisor.apply_event`. These facts were not delivered as a live
    monitor event — they are the SAME per-round facts every dynamic-track
    node already computes deterministically — so this is the synchronous
    equivalent of `apply_events(state, ctx.drain_pending_events())` for
    exactly what the existing (pre-T3-L-monitor-wiring) call chain already
    produces; a future revision wiring T3-L's concurrent monitors directly
    into this node would REPLACE most of this function's body with a
    drain+`apply_events` call, not add a second, competing mechanism.

    Never re-derives a fact this function doesn't have positive evidence
    for — `sink_addr` is only updated when `plan.sink_addr` is actually
    set (never cleared once known); `sink_reachable` only ever advances to
    `True` (never forced back to `False`, since "not reached THIS round"
    is not proof of permanent unreachability — that absence is what
    `fvvw.supervisor.propose_action`'s `resolve_address` branch itself
    reasons about); `breakpoint_status`/`process_status` only advance when
    the round's own `reached`/`observation.process_exited_before_bp` facts
    say so. `process_status` defaults to `"running"` once this function is
    reached at all (Node 8 only ever runs AFTER Node 5/6 already attempted
    to execute the target this round) UNLESS the round's own facts show
    otherwise (`process_exited_before_bp` -> `"exited"`) — leaving it at
    `VerificationState`'s bare `"not_started"` default here would
    incorrectly make `propose_action`'s OWN "startup failure observed
    before the target ever ran" branch fire for an ordinary "reached the
    breakpoint stage but the exact hit didn't happen yet" round.

    P1-1/P1-2: when `observation.instrumentation_ok` is False (GDB never
    managed to set a real breakpoint this round — a recipe/setup error,
    NOT an ordinary miss), `breakpoint_status` is deliberately left at
    `"unset"` rather than advanced to `"missed"` — "missed" means "GDB set
    it, the process ran past it, it just didn't fire"; an instrumentation
    failure never got that far. `instrumentation_failures` increments (and
    is reset to 0 the moment instrumentation DOES succeed), and
    `failure_reason` carries the specific `instrumentation_error` text
    instead of the generic "breakpoint not hit this round" — this is the
    exact distinction whose absence let the DIR-825 incident's `break
    *unspecified` failure collapse into an ordinary "breakpoint never hit"
    diagnosis for 9 consecutive rounds."""
    updates: dict = {
        "current_strategy": emulation_mode or state.current_strategy,
        "reached": reached,
        "process_exited_before_bp": (
            state.process_exited_before_bp or observation.process_exited_before_bp
        ),
        "oracle_match": observation.oracle_match,
        "process_status": "running",
        "instrumentation_failures": (
            0 if observation.instrumentation_ok else state.instrumentation_failures + 1
        ),
    }
    if reached:
        updates["breakpoint_status"] = "hit"
    elif observation.process_exited_before_bp:
        updates["process_status"] = "exited"
        if state.breakpoint_status != "hit":
            updates["breakpoint_status"] = "missed"
    elif not observation.instrumentation_ok:
        # Instrumentation itself failed — never advance breakpoint_status
        # to "missed" (that implies GDB successfully set it and the
        # process simply ran past without hitting it, which did not
        # happen here). Leave it at whatever it already was (typically
        # "unset").
        pass
    elif state.breakpoint_status == "unset":
        updates["breakpoint_status"] = "missed"

    if observation.signal and observation.signal not in state.signals:
        updates["signals"] = [*state.signals, observation.signal]
    if observation.filesystem_artifacts:
        merged = list(
            dict.fromkeys([*state.filesystem_artifacts, *observation.filesystem_artifacts])
        )
        updates["filesystem_artifacts"] = merged
    if observation.memory_diff_detected:
        note = "memory_diff_detected"
        if note not in state.memory_observations:
            updates["memory_observations"] = [*state.memory_observations, note]
    if plan.sink_addr.strip():
        updates["sink_addr"] = plan.sink_addr
    if reached_sink:
        updates["sink_reachable"] = True

    if updates.get("process_exited_before_bp"):
        updates["failure_reason"] = (
            "process exited before the entry/sink breakpoint was ever hit"
        )
    elif not observation.instrumentation_ok:
        updates["failure_reason"] = (
            observation.instrumentation_error
            or "instrumentation failed this round — GDB did not successfully set a "
            "breakpoint (setup/recipe error, not a breakpoint miss)"
        )
    elif not reached and updates.get("breakpoint_status") in ("unset", "missed"):
        updates["failure_reason"] = "breakpoint not hit this round"
    else:
        updates["failure_reason"] = ""

    return state.model_copy(update=updates)


async def _run_evaluate_route(
    *,
    deps: DynamicGraphDeps,
    global_id: str,
    plan: DynamicPlan,
    observation: ObservationRecord,
    reached: bool,
    reached_sink: bool,
    iteration: int,
    emulation_mode: str = "",
    verification_state: VerificationState | None = None,
) -> dict:
    """spec Node 8 body: the deterministic oracle-match first pass
    (unchanged, still authoritative for `confirmed` — T1-A/T1-B), the hard
    iteration-budget cutoff (unchanged, still checked before ANY LLM
    call), then the Tier 3 Continuous Verification Supervisor
    (`fvvw.supervisor.propose_action`/`validate_action`) BEFORE falling
    through to the LLM router — the supervisor SUBSUMES the pre-Tier-3
    inline `elif not reached`/disconfirm-shape branches (moved into
    `fvvw.supervisor.propose_action`), and every route — whether the
    supervisor's own deterministic proposal or the LLM router's choice —
    passes through `validate_action`'s no-repeat/bounded-recovery gate
    before it is ever acted on. Always returns a `RouteDecision`, appended
    to `iteration_history` either way — the spec's "Iteration history"
    report requirement covers every kind of round, not just the
    LLM-diagnosed ones.

    `verification_state`, when given, is the canonical state accumulated
    across every PRIOR round this run (`BringupContext.verification_state`
    — see T3-O); `None` (every existing caller/test that predates Tier 3)
    starts a fresh, empty one for just this call — the SAME single-round
    behavior every pre-Tier-3 test already exercises, since a fresh state
    carries no prior `attempt_history` to escalate against.
    """
    async with aphase("evaluate_route"):
        oracle = plan.oracle or plan.decisive_observable
        max_iterations = deps.settings.stage5_dynamic_max_iterations

        oracle_hit = match_oracle(observation, plan)
        # T1-B: write the check result back onto the record IMMEDIATELY —
        # the record, the route, and the eventual report can never
        # silently disagree about what the deterministic gate decided.
        observation = observation.model_copy(update={"oracle_match": oracle_hit})
        has_evidence = _has_positive_evidence(observation, reached_sink=reached_sink)

        state = (
            verification_state if verification_state is not None
            else VerificationState(global_id=global_id)
        )
        state = _update_state_for_round(
            state,
            plan=plan,
            observation=observation,
            reached=reached,
            reached_sink=reached_sink,
            emulation_mode=emulation_mode,
        )

        if oracle_hit and has_evidence:
            decision = RouteDecision(
                route="confirmed",
                diagnosis=f"deterministic oracle match: {oracle!r}",
                confidence="HIGH",
            )
        elif iteration >= max_iterations:
            # Hard deterministic cutoff — never trust the LLM router (or
            # the Tier 3 supervisor) alone to stop looping (spec's "a
            # stuck run terminates INCONCLUSIVE, never loops forever"; see
            # this module's risk note). Checked BEFORE the supervisor is
            # even consulted — a spent budget always wins.
            decision = RouteDecision(
                route="inconclusive",
                diagnosis=f"dynamic_iteration budget exhausted ({iteration}/{max_iterations}) "
                "without a decisive oracle match.",
                confidence="HIGH",
            )
        else:
            if oracle_hit and not has_evidence:
                # T1-B: a bug-shaped contradiction — the deterministic
                # gate fired but nothing structured backs it. NEVER
                # confirm on this; record the contradiction as this
                # round's failure_reason so it is visible in the audit
                # trail, then fall into the SAME supervisor/router
                # pipeline every other non-confirming round uses (never a
                # bespoke ad-hoc route here, so the no-repeat protection
                # still applies uniformly).
                state = state.model_copy(
                    update={
                        "failure_reason": (
                            "deterministic oracle match fired but the observation carries "
                            "no positive evidence (no signal/filesystem_artifacts/captured "
                            "argument/memory diff) — refusing to confirm on an empty "
                            "observation."
                        )
                    }
                )

            proposed = propose_action(state)
            if proposed is not None:
                decision = proposed
            elif observation.memory_diff_detected is False and reached_sink and (
                "safe" in plan.disconfirm_condition.lower()
                or "bounds" in plan.disconfirm_condition.lower()
            ) and observation.signal is None:
                # A conservative, purely deterministic refutation SHAPE:
                # sink reached, no crash, no memory corruption observed,
                # AND the plan's own disconfirm_condition text already
                # describes a "safely handled" scenario — still requires
                # the LLM router to confirm/diagnose rather than
                # auto-refuting from this alone (spec's "no crash" is not
                # automatically proof of safety).
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
                    command_log=deps.command_log,
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
                    command_log=deps.command_log,
                )
            # T3-M: every non-terminal-by-construction decision — whether
            # the supervisor's own deterministic proposal or the LLM
            # router's choice — passes through the SAME no-repeat/bounded
            # recovery gate before it is ever acted on.
            decision = validate_action(decision, state, deps.settings)

        state = record_attempt(state, decision)

        result: dict = {
            "route": decision,
            "iteration_history": [decision],
            "dynamic_iteration": iteration,
            "observation": observation,
            "verification_state": state,
        }
        if decision.route in _TERMINAL_ROUTES:
            result["dynamic_result"] = _build_track_result(
                decision, observation, iteration=iteration, reached_sink=reached_sink
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
the LLM router's/oracle-match's/the Tier 3 supervisor's route instead of
the old rule engine's own branches. `resolve_address`/`restart_execution`
are deliberately ABSENT — both are repair routes, never terminal;
`"escalate"` is likewise absent — `fvvw.supervisor.validate_action`
resolves it into a concrete route before a `RouteDecision` carrying it can
ever reach here."""


def _build_track_result(
    decision: RouteDecision,
    observation: ObservationRecord,
    *,
    iteration: int,
    reached_sink: bool | None = None,
) -> TrackResult:
    """Node 8's terminal-route case: turn a `confirmed`/`refuted`/
    `inconclusive` `RouteDecision` (which itself carries no verdict, only a
    routing instruction — see `RouteDecision`'s own docstring) plus the
    round's `ObservationRecord` into the `TrackResult` `fvvw.graph`/
    `fvvw.joint.joint_evaluate` need. Mirrors `dynamic_track._terminal`'s
    evidence shape (`reason`, `budget_exhausted` for INCONCLUSIVE) so
    `write_report`/HITL's budget-exhaustion trigger keep working unchanged
    against the new graph's output.

    T1-B defense in depth: even if some future bug lets a `confirmed`
    route reach this function with an observation carrying NO positive
    evidence (the SAME `_has_positive_evidence` test `_run_evaluate_route`
    already applies upstream — this is a SECOND, independent check of the
    identical condition, mirroring `fvvw.joint.collect_residual_unknowns`'
    own "REFUTED without a proved B" defense-in-depth caveat), the verdict
    is downgraded to INCONCLUSIVE here rather than ever persisting a
    CONFIRMED `TrackResult` built on an empty observation.

    `reached_sink`, when given, is the SAME already-computed fact
    `_run_evaluate_route` passes through (a genuinely reached sink with a
    captured argument — `observation.faulting_pc is not None or
    filesystem_artifacts` for the agentic path, `captured is not None`
    for the deterministic path — see `_run_trigger`); `None` (every
    caller/test that predates this parameter) derives a best-effort proxy
    from the observation's own `faulting_pc`/`filesystem_artifacts`
    fields, sufficient for every case that doesn't depend on a bare
    captured-argument-with-no-crash outcome."""
    verdict, proved_hypothesis = _TERMINAL_ROUTES[decision.route]
    effective_reached_sink = (
        reached_sink
        if reached_sink is not None
        else bool(observation.faulting_pc is not None or observation.filesystem_artifacts)
    )
    if verdict == VerificationVerdict.CONFIRMED and not _has_positive_evidence(
        observation, reached_sink=effective_reached_sink
    ):
        verdict, proved_hypothesis = VerificationVerdict.INCONCLUSIVE, "none"
        decision = RouteDecision(
            route="inconclusive",
            diagnosis="confirmed route with an empty observation — refused. Original "
            f"diagnosis: {decision.diagnosis}",
            confidence="LOW",
        )
    evidence: dict = {"reason": decision.diagnosis} if decision.diagnosis else {}
    if observation.faulting_pc:
        evidence["faulting_pc"] = observation.faulting_pc
    if observation.signal:
        evidence["signal"] = observation.signal
    if observation.filesystem_artifacts:
        evidence["filesystem_artifacts"] = observation.filesystem_artifacts
    if observation.memory_diff_detected:
        evidence["memory_diff_detected"] = observation.memory_diff_detected
    if observation.oracle_match is not None:
        evidence["oracle_match"] = observation.oracle_match
    if not observation.instrumentation_ok:
        # P2-2: preserve the much more important fact that instrumentation
        # itself failed before any meaningful observation was possible —
        # without this, an INCONCLUSIVE verdict's evidence is
        # indistinguishable from "genuinely tried and found nothing",
        # which is exactly how the DIR-825 incident's report/route
        # diagnosis language ("breakpoint never hit — wrong sink location,
        # missing symbol, or input never reached that code path") implied
        # a normal miss instead of a harness failure. Surfaced here so
        # both the persisted evidence dict AND the report writer (which
        # reads `TrackResult.evidence`) can state the distinction plainly.
        evidence["instrumentation_ok"] = False
        if observation.instrumentation_error:
            evidence["instrumentation_error"] = observation.instrumentation_error
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


def route_after_resolve_address(
    state: dict,
) -> Literal["gdb_attach", "plan_emulation_escalate"]:
    """`resolve_address_node` sets `_entry_addr_unresolvable=True` when
    `plan.entry_addr` is STILL unresolved even after falling back to
    `target.func_offset` — meaning there is genuinely no address to reach
    with under the current strategy. Bouncing back to `gdb_attach` in that
    case would just raise the identical `UnresolvedPlanFault` again
    (`resolve_address` -> `gdb_attach` -> `resolve_address` -> ... — no
    worse than before this fix, since `validate_action`'s no-repeat ladder
    would eventually break it, but wasteful and slower to converge).
    Escalate directly to `plan_emulation_escalate` instead — the same
    last-resort `direct_call` mode the router's own `escalate_direct_call`
    route already reaches for a repeatedly-failing bring-up."""
    return (
        "plan_emulation_escalate"
        if state.get("_entry_addr_unresolvable")
        else "gdb_attach"
    )


def route_after_gdb_attach(
    state: dict,
) -> Literal["trigger", "bringup", "resolve_address", "evaluate_route"]:
    if state.get("_gdb_fault"):
        # `_run_gdb_attach` sets the ACTUAL target route on `state["route"]`
        # (`retry_bringup` for a genuine QEMU/GDB setup fault,
        # `resolve_address` for an `UnresolvedPlanFault` — see that
        # function's own docstring) — follow it via the same `_ROUTE_TO_
        # NODE` table `route_after_evaluate` uses, rather than hardcoding
        # every fault to `bringup`. An unresolved plan address can never be
        # fixed by re-running bring-up, so collapsing both fault kinds into
        # the same edge would recreate the DIR-825 infinite-retry loop this
        # fix exists to break.
        decision: RouteDecision | None = state.get("route")
        target = _ROUTE_TO_NODE.get(decision.route, "bringup") if decision else "bringup"
        return target if target in ("bringup", "resolve_address") else "bringup"  # type: ignore[return-value]
    if state.get("_instrumentation_blocked"):
        # P1-3: a PRIOR round already demonstrated instrumentation is
        # broken (see `gdb_attach_node`'s own comment) — skip the
        # expensive trigger loop and let Node 8/the supervisor diagnose
        # and escalate instead of spending an LLM trigger round with no
        # working observation channel.
        return "evaluate_route"
    # Even when the breakpoint never hit (_reached is False), proceed to
    # trigger/evaluate rather than looping locally — Node 8 is the ONLY
    # place that decides whether "not reached" means retry_gdb_attach vs.
    # something else, per the spec's decision table (never decided inline
    # here by a bare bool).
    return "trigger"


def route_after_trigger(
    state: dict,
) -> Literal["evaluate_route", "bringup", "resolve_address"]:
    if state.get("_trigger_fault"):
        # Same reasoning as `route_after_gdb_attach`: follow the ACTUAL
        # route `_run_trigger` set (`resolve_address` for an
        # `UnresolvedPlanFault`, `retry_bringup` for a genuine setup
        # fault) instead of collapsing every trigger-stage fault into
        # `bringup`.
        decision: RouteDecision | None = state.get("route")
        target = _ROUTE_TO_NODE.get(decision.route, "bringup") if decision else "bringup"
        return target if target in ("bringup", "resolve_address") else "bringup"  # type: ignore[return-value]
    return "evaluate_route"


def route_after_evaluate(
    state: dict,
) -> Literal[
    "bringup", "gdb_attach", "trigger", "plan_emulation_escalate", "resolve_address", "__end__"
]:
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
        # T3-N: `restart_execution` (unlike `retry_bringup`) means "tear
        # down the CURRENT session before repairing" — the supervisor's
        # own signal that repeated in-place repair against this session
        # has already been tried and exhausted (see `fvvw.supervisor`'s
        # `_ESCALATION_CHAIN`). Checked here, not as a separate graph
        # node, since `bringup_node`'s own body is otherwise identical
        # either way — the only difference is whether a fresh session is
        # forced first.
        incoming_route: RouteDecision | None = state.get("route")
        if incoming_route is not None and incoming_route.route == "restart_execution":
            await restart_session(ctx)
        return await _run_bringup(ctx, deps=deps)

    async def health_gate_node(state: FVVWState) -> dict:
        return await _run_health_gate(ctx)

    async def gdb_attach_node(state: FVVWState) -> dict:
        transcript_so_far = state.get("gdb_transcript", "") or ""
        result = await _run_gdb_attach(ctx, transcript_so_far=transcript_so_far)
        ctx._last_reached = result.get("_reached", False)  # type: ignore[attr-defined]
        # P1-3: if the harness demonstrably failed to INSTRUMENT the
        # target in a PRIOR round (verification_state.instrumentation_
        # failures — accumulated by _update_state_for_round, persisted
        # across rounds on this same long-lived ctx), do not let the
        # expensive trigger loop run again this round even when THIS
        # round's gdb_attach itself didn't raise a fault — entering
        # Node 6 (`trigger`, the agentic payload-crafting loop) with no
        # working instrumentation channel is exactly how the DIR-825
        # incident burned 56 trigger-agent calls / ~120k tokens
        # inventing payloads and unverified function names against a
        # target that was never actually instrumented. Route straight to
        # evaluate_route instead, where Node 8/the supervisor already
        # knows how to escalate a repeated instrumentation failure
        # (`propose_action`'s new case #1).
        result["_instrumentation_blocked"] = (
            not result.get("_gdb_fault")
            and ctx.verification_state.instrumentation_failures >= 1
        )
        return result

    async def resolve_address_node(state: FVVWState) -> dict:
        """T3-N's `resolve_address` repair route: re-derive `plan.
        sink_addr`/`plan.entry_addr` from the best already-known fact
        (`target.func_offset`) when either is still unresolved, record the
        attempt, then hand off to Node 5 (`gdb_attach`) for another try —
        UNLESS `entry_addr` is still unresolved even after the fallback
        (`target.func_offset` itself unresolved too), in which case there
        is nothing left to reach with and this node signals `_unresolvable`
        so the router escalates straight to `plan_emulation_escalate`
        rather than bouncing back to `gdb_attach` only to raise the
        identical `UnresolvedPlanFault` again.

        `entry_addr` resolution (added alongside the pre-existing `sink_
        addr` handling): before this fix, only `sink_addr` was ever
        repaired here, so an unresolved `entry_addr` (the DIR-825
        incident's actual failure — `entry_addr="unspecified"`) reaching
        this node would fall back to `target.func_offset` INSIDE `reach_
        target`/`_build_and_lint_recipe` every round but never get WRITTEN
        onto `plan.entry_addr` itself — meaning a resolvable func_offset
        would silently keep re-resolving each round instead of the plan
        converging on it once, and an UNRESOLVABLE one would keep raising
        `UnresolvedPlanFault` from `gdb_attach` every round with no exit.

        Never FABRICATES an address — an unresolvable field stays empty,
        and the Tier 1 positive-evidence gate (T1-B) already ensures an
        empty sink can never produce a false CONFIRMED (no meaningful
        sink breakpoint -> no captured argument -> no evidence)."""
        async with aphase("resolve_address"):
            if not is_resolved_addr(plan.sink_addr) and is_resolved_addr(target.func_offset):
                plan.sink_addr = target.func_offset
                ctx.applied_fixes.append(
                    f"resolve_address: fell back sink_addr to target.func_offset="
                    f"{target.func_offset!r} (T2-F resolution had no better answer)"
                )
            if not is_resolved_addr(plan.entry_addr) and is_resolved_addr(target.func_offset):
                plan.entry_addr = target.func_offset
                ctx.applied_fixes.append(
                    f"resolve_address: fell back entry_addr to target.func_offset="
                    f"{target.func_offset!r} (strategy agent left entry_addr unresolved)"
                )
            still_unresolvable = not is_resolved_addr(plan.entry_addr)
        return {"_entry_addr_unresolvable": still_unresolvable}

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
        result = await _run_evaluate_route(
            deps=deps,
            global_id=candidate.global_id,
            plan=plan,
            observation=observation,
            reached=reached,
            reached_sink=bool(reached_sink),
            iteration=iteration,
            emulation_mode=ctx.emulation_plan.get("mode", ""),
            verification_state=ctx.verification_state,
        )
        # T3-O: persist the updated canonical state back onto the
        # long-lived BringupContext — the SAME instance every node
        # closure shares — so the NEXT round (and, ultimately, `fvvw.
        # graph.run_dynamic_track_only`'s `dynamic_extras`) sees the
        # accumulated events/attempt_history rather than a fresh state
        # each round.
        ctx.verification_state = result.get("verification_state") or ctx.verification_state
        return result

    graph = StateGraph(FVVWState)
    graph.add_node("plan_emulation", plan_emulation_node)
    graph.add_node("plan_emulation_escalate", plan_emulation_escalate_node)
    graph.add_node("bringup", bringup_node)
    graph.add_node("health_gate", health_gate_node)
    graph.add_node("gdb_attach", gdb_attach_node)
    graph.add_node("resolve_address", resolve_address_node)
    graph.add_node("trigger", trigger_node)
    graph.add_node("evaluate_route", evaluate_route_node)

    graph.set_entry_point("plan_emulation")
    graph.add_edge("plan_emulation", "bringup")
    graph.add_edge("plan_emulation_escalate", "bringup")
    graph.add_conditional_edges(
        "resolve_address",
        route_after_resolve_address,
        {
            "gdb_attach": "gdb_attach",
            "plan_emulation_escalate": "plan_emulation_escalate",
        },
    )
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
        {
            "trigger": "trigger",
            "bringup": "bringup",
            "resolve_address": "resolve_address",
            "evaluate_route": "evaluate_route",
        },
    )
    graph.add_conditional_edges(
        "trigger",
        route_after_trigger,
        {
            "evaluate_route": "evaluate_route",
            "bringup": "bringup",
            "resolve_address": "resolve_address",
        },
    )
    graph.add_conditional_edges(
        "evaluate_route",
        route_after_evaluate,
        {
            "bringup": "bringup",
            "gdb_attach": "gdb_attach",
            "trigger": "trigger",
            "plan_emulation_escalate": "plan_emulation_escalate",
            "resolve_address": "resolve_address",
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
    "route_after_resolve_address",
    "route_after_trigger",
]
