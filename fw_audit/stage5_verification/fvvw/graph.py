"""`fvvw.graph` — the top-level fork-join `StateGraph(FVVWState)` (FVVW v3
§5/§10): `ingest -> characterize -> strategy`, forking into the static
track (the existing Joern pipeline, reused via `fvvw.static_track`) and the
dynamic track (the compiled 9-node agentic `StateGraph` from
`fvvw.dynamic_graph.build_dynamic_graph`, wrapped by `run_dynamic_track_only`
below) running concurrently, joining at `await_both_tracks`, then
`joint_evaluate -> write_report -> END`.

Track isolation (no static-track node reads `dynamic_*`, no dynamic-track
node reads `static_result`) is enforced by construction: each track is
wired as its own linear sequence of plain-dict-returning async closures
over `fvvw.state`'s `STATIC_TRACK_*`/`DYNAMIC_TRACK_*` key tuples — a node
literally cannot see a key nothing put in its own closure's inputs, since
every closure here reads only from the specific fields of `state` its own
docstring names, mirroring `agent.graph.build_verifier_graph`'s node-closure
shape rather than importing `state` wholesale.

Repair back-edges inside the dynamic track (Node 4/5/6 -> Node 3 bring-up
on a fault, per the spec's §10 decision table) are real LangGraph
conditional edges inside `fvvw.dynamic_graph.build_dynamic_graph` itself —
see that module's docstring for why looping back through a graph edge
still keeps `BringupContext`'s mutable session/launch state naturally
scoped to ONE long-lived context object shared by every node closure,
rather than round-tripping a `SessionHandle` through graph state.
"""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from langchain_core.language_models import BaseChatModel

from fw_audit.common.verification import HumanReviewRecord, TrackResult, VerificationVerdict
from fw_audit.config.llm_config import AgentRole, get_llm_for_agent
from fw_audit.config.settings import Settings
from fw_audit.executors.base import Executor
from fw_audit.executors.sandbox_executor import SandboxExecutor
from fw_audit.observability import run_config
from fw_audit.stage5_verification import layout
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.cmdlog import CommandLog, LoggingSessionExecutor
from fw_audit.stage5_verification.errors import (
    Stage5InputError,
    VerifierModelUnavailableError,
)
from fw_audit.stage5_verification.fvvw.dynamic_graph import DynamicGraphDeps, build_dynamic_graph
from fw_audit.stage5_verification.fvvw.dynamic_track import (
    BringupContext,
    plan_emulation,
)
from fw_audit.stage5_verification.fvvw.hitl import (
    HitlAction,
    HitlRequest,
    Prompter,
    build_human_review_record,
    force_verdict_result,
    is_budget_exhausted,
    neither_proved,
    prompt_for_track,
    terminal_prompter,
)
from fw_audit.stage5_verification.fvvw.joint import joint_evaluate
from fw_audit.stage5_verification.fvvw.static_track import (
    run_injected_static_script,
    run_static_track,
)
from fw_audit.stage5_verification.fvvw.strategy import strategy_agent
from fw_audit.stage5_verification.live_console import LiveConsole, make_transcript_on_step
from fw_audit.stage5_verification.llm_logging import LoggingChatModel
from fw_audit.stage5_verification.streaming import stream_graph_live
from fw_audit.stage5_verification.tools.characterize_tool import characterize_target
from fw_audit.stage5_verification.tools.crosscheck_tool import static_crosscheck
from fw_audit.stage5_verification.tools.joern_tool import joern_executor
from fw_audit.stage5_verification.tools.verification_sandbox import (
    verification_executor,
    verification_session_executor,
)


def resolve_checkpointer(settings: Settings):
    """Resolve the LangGraph checkpointer per `Settings.
    stage5_checkpoint_backend`. `"memory"` (default) needs no extra
    dependency; `"sqlite"` lazily imports `langgraph.checkpoint.sqlite`
    (the `stage5-fvvw` extra) — never a hard import at module load time, so
    a run using the default backend never needs that package installed at
    all, same "provider SDKs resolved lazily" discipline
    `config.llm_config.get_llm` already applies. Raises `ValueError` for an
    unrecognized backend — no silent fallback, matching
    `executors.manager.get_executor()`'s posture on an unrecognized
    executor backend name."""
    backend = settings.stage5_checkpoint_backend.lower()
    if backend == "memory":
        from langgraph.checkpoint.memory import MemorySaver

        return MemorySaver()
    if backend == "sqlite":
        try:
            from langgraph.checkpoint.sqlite import SqliteSaver
        except ImportError as exc:
            raise ImportError(
                "Settings.stage5_checkpoint_backend='sqlite' requires the 'stage5-fvvw' "
                "extra: pip install -e '.[stage5-fvvw]'"
            ) from exc
        db_path = Path(settings.stage5_dynamic_workspace_root or ".") / "fvvw_checkpoints.sqlite"
        return SqliteSaver.from_conn_string(str(db_path))
    raise ValueError(
        f"Unknown stage5_checkpoint_backend={backend!r}; expected 'memory' or 'sqlite'."
    )


@dataclass
class FVVWDeps:
    """Every resolved dependency the fork-join graph's nodes need, built
    once per `run_fvvw` call (mirrors `agent.verifier.verify_candidate`'s
    up-front role/executor resolution) — kept as one object rather than a
    long parameter list threaded through every node closure.

    `static_command_log`/`dynamic_command_log` are `CommandLog.disabled()`
    no-ops when `Settings.stage5_command_log` is `False` — every consumer
    (`run_static_track`'s `JsonlRecordingList`s, `dynamic_session_executor`
    when wrapped in `LoggingSessionExecutor`) works unchanged either way, so
    this flag never needs its own branch anywhere but here."""

    settings: Settings
    strategy_llm: BaseChatModel | LoggingChatModel
    static_generator_llm: BaseChatModel | LoggingChatModel
    static_evaluator_llm: BaseChatModel | LoggingChatModel
    report_llm: BaseChatModel | LoggingChatModel
    bringup_llm: BaseChatModel | LoggingChatModel
    trigger_llm: BaseChatModel | LoggingChatModel
    dynamic_evaluator_llm: BaseChatModel | LoggingChatModel
    static_executor: Executor
    crosscheck_executor: Executor
    dynamic_session_executor: SandboxExecutor
    static_workspace_dir: Path
    dynamic_workspace_dir: Path
    static_command_log: CommandLog
    dynamic_command_log: CommandLog
    system_prompt: str | None = None


async def resolve_fvvw_deps(
    *,
    db_subfolder: Path,
    candidate: VerificationCandidate,
    settings: Settings,
    live: bool = False,
) -> FVVWDeps:
    """Resolve every LLM role + executor the fork-join needs for one
    candidate, up front — mirrors `agent.verifier.verify_candidate`'s own
    "resolve everything before any tool invocation" order, extended to the
    five new roles (the dynamic track's 9-node agentic rewrite added
    STAGE5_BRINGUP_AGENT/STAGE5_TRIGGER_AGENT/STAGE5_DYNAMIC_EVALUATOR on
    top of the pre-existing two) and the two new executor kinds. Raises
    `VerifierModelUnavailableError` if any of the seven LLM roles can't be
    resolved — a fork-join run needs all of them, not just the static
    track's two.

    Also resolves the per-track `CommandLog`s (`stage5/fvvw/logs/<gid>.
    <static|dynamic>.jsonl`) and wraps `dynamic_session_executor` in a
    `LoggingSessionExecutor` so every dynamic-track command is captured
    centrally — see `cmdlog`'s module docstring for why this is composition
    over the executor, never an edit to `SandboxExecutor` itself.

    Every one of the seven resolved LLMs is wrapped in `llm_logging.
    LoggingChatModel` — full before/after-parser visibility (the exact
    prompt sent, the raw response before any downstream parsing) for every
    LLM call this candidate makes, with zero edits to any node/prompt file
    (see that module's docstring). `live`, when `True`, attaches a
    `LiveConsole` to both `CommandLog`s so every record (LLM call, tool
    call, parsed action/decision, node update) is ALSO echoed to the
    terminal, tagged `[gid]`, as it happens — `Settings.
    stage5_command_log=False` no longer forces a fully silent
    `CommandLog.disabled()` here, since a `--no-command-log --live` run
    should still get console visibility even with nothing landing on disk
    (see `cmdlog.CommandLog.record`'s docstring)."""
    try:
        strategy_llm = get_llm_for_agent(AgentRole.STAGE5_STRATEGY_AGENT, settings=settings)
        static_generator_llm = get_llm_for_agent(
            AgentRole.STAGE5_SCRIPT_GENERATOR, settings=settings
        )
        static_evaluator_llm = get_llm_for_agent(
            AgentRole.STAGE5_RESULT_EVALUATOR, settings=settings
        )
        report_llm = get_llm_for_agent(AgentRole.STAGE5_REPORT_WRITER, settings=settings)
        bringup_llm = get_llm_for_agent(AgentRole.STAGE5_BRINGUP_AGENT, settings=settings)
        trigger_llm = get_llm_for_agent(AgentRole.STAGE5_TRIGGER_AGENT, settings=settings)
        dynamic_evaluator_llm = get_llm_for_agent(
            AgentRole.STAGE5_DYNAMIC_EVALUATOR, settings=settings
        )
    except (ImportError, ValueError) as exc:
        raise VerifierModelUnavailableError(str(exc)) from exc

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    static_workspace_dir = layout.workspace_dir(stage5_dir_, candidate.global_id)
    fvvw_dir_ = layout.fvvw_dir(stage5_dir_)
    dynamic_workspace_dir = layout.fvvw_dynamic_workspace_dir(fvvw_dir_, candidate.global_id)

    live_console = (
        LiveConsole(truncate_chars=settings.stage5_live_console_truncate_chars) if live else None
    )
    static_path = (
        layout.fvvw_command_log_path(fvvw_dir_, candidate.global_id, "static")
        if settings.stage5_command_log
        else None
    )
    dynamic_path = (
        layout.fvvw_command_log_path(fvvw_dir_, candidate.global_id, "dynamic")
        if settings.stage5_command_log
        else None
    )
    static_command_log = CommandLog(
        static_path, track="static", gid=candidate.global_id, live=live_console
    )
    dynamic_command_log = CommandLog(
        dynamic_path, track="dynamic", gid=candidate.global_id, live=live_console
    )

    dynamic_session_executor = LoggingSessionExecutor(
        verification_session_executor(settings), dynamic_command_log
    )

    # strategy_agent/report_llm run once per candidate, upstream/downstream
    # of the fork rather than belonging to either track — logged through
    # static_command_log (an arbitrary but consistent choice) rather than
    # adding a third "shared" JSONL file just for two roles.
    return FVVWDeps(
        settings=settings,
        strategy_llm=LoggingChatModel(
            strategy_llm, role="strategy_agent", command_log=static_command_log
        ),
        static_generator_llm=LoggingChatModel(
            static_generator_llm, role="generator", command_log=static_command_log
        ),
        static_evaluator_llm=LoggingChatModel(
            static_evaluator_llm, role="evaluator", command_log=static_command_log
        ),
        report_llm=LoggingChatModel(
            report_llm, role="report_writer", command_log=static_command_log
        ),
        bringup_llm=LoggingChatModel(
            bringup_llm, role="bringup_agent", command_log=dynamic_command_log
        ),
        trigger_llm=LoggingChatModel(
            trigger_llm, role="trigger_agent", command_log=dynamic_command_log
        ),
        dynamic_evaluator_llm=LoggingChatModel(
            dynamic_evaluator_llm, role="dynamic_evaluate", command_log=dynamic_command_log
        ),
        static_executor=joern_executor(settings),
        crosscheck_executor=verification_executor(settings),
        dynamic_session_executor=dynamic_session_executor,
        static_workspace_dir=static_workspace_dir,
        dynamic_workspace_dir=dynamic_workspace_dir,
        static_command_log=static_command_log,
        dynamic_command_log=dynamic_command_log,
    )


async def run_dynamic_track_only(
    candidate: VerificationCandidate,
    plan,
    target,
    *,
    deps: FVVWDeps,
    settings_override: Settings | None = None,
    raw_recipe_override: str | None = None,
    stop_after: str | None = None,
) -> tuple[TrackResult, list[dict], bool | None, str, dict]:
    """The dynamic track's full run: compiles and `ainvoke`s the 9-node
    agentic `StateGraph` (`fvvw.dynamic_graph.build_dynamic_graph` — spec
    Nodes 2-8; Node 1 is the shared `strategy_agent` upstream, Node 9 stays
    downstream in `joint_evaluate`/`write_report`), a thin wrapper exactly
    as this module's docstring describes. Bring-up/arbitration (Node 3) and
    trigger crafting (Node 6) are agentic loops driving the persistent QEMU
    session themselves; Node 8 loops the graph back to Node 3/5/6 via real
    conditional edges instead of this function's own retry `while` loops
    (see `dynamic_graph`'s module docstring for why that still keeps
    `BringupContext`'s mutable session state naturally scoped).

    `settings_override`, when given, is used instead of `deps.settings` for
    this run only — HITL's "retry with more iterations" action
    (`fvvw.hitl`) passes a `Settings.model_copy` with a raised
    `stage5_dynamic_max_iterations` without touching `deps` itself.
    `raw_recipe_override`, when given, is threaded onto the `BringupContext`
    so `instrument_trigger` runs it verbatim instead of the plan-derived
    recipe — HITL's "inject" action. `stop_after`, when given (one of the
    graph's own node ids, e.g. `"bringup"`/`"health_gate"`), halts streaming
    right after that node fires — `fw-verify debug dynamic --stop-after`'s
    per-node diagnosis hook; `None` (every other caller, including
    production) runs the graph to completion exactly as before.

    Returns `(TrackResult, guard_logs, dynamic_reached_sink, gdb_transcript,
    dynamic_extras)` — the extra values `joint_evaluate`/`fvvw.report`/the
    persisted `FVVWReport` need beyond the bare `TrackResult`, unpacked from
    the graph's terminal state. `dynamic_extras` is a plain dict
    (`{"arbitration_log", "observation", "iteration_history",
    "emulation_mode"}`) — spec Node 9's required contents #3/#4/#6/#7 — kept
    as a bag rather than growing the positional tuple further, since it is
    purely additive bookkeeping no existing caller needs to unpack by
    position.
    """
    settings = settings_override or deps.settings
    emulation = plan_emulation(target, plan)["emulation_plan"]
    if emulation["mode"] == "unsupported":
        return (
            TrackResult(
                verdict=VerificationVerdict.ERROR,
                proved_hypothesis="none",
                evidence={"reason": emulation["reason"]},
            ),
            [],
            None,
            "",
            {"emulation_mode": emulation["mode"]},
        )

    ctx = BringupContext(
        candidate=candidate,
        target=target,
        plan=plan,
        emulation_plan=emulation,
        settings=settings,
        session_executor=deps.dynamic_session_executor,
        raw_recipe_override=raw_recipe_override,
    )

    graph_deps = DynamicGraphDeps(
        settings=settings,
        bringup_llm=deps.bringup_llm,
        trigger_llm=deps.trigger_llm,
        dynamic_evaluator_llm=deps.dynamic_evaluator_llm,
        session_executor=deps.dynamic_session_executor,
        command_log=deps.dynamic_command_log,
    )

    compiled = build_dynamic_graph(
        ctx=ctx,
        deps=graph_deps,
        candidate=candidate,
        target=target,
        plan=plan,
        vuln_class=candidate.finding.category,
        sink_expression=candidate.finding.sink.expression,
    )

    timed_out = False
    try:
        try:
            final_state = await asyncio.wait_for(
                stream_graph_live(
                    compiled,
                    {},
                    config=run_config(
                        run_name="stage5.dynamic_track",
                        metadata={"global_id": candidate.global_id},
                        settings=settings,
                    ),
                    command_log=deps.dynamic_command_log,
                    stop_after=stop_after,
                ),
                timeout=settings.stage5_dynamic_wall_clock_seconds,
            )
        except TimeoutError:
            # The spec's Node 8 "mandatory: hard maximum number of loop
            # iterations AND a wall-clock time budget" requirement — the
            # per-round iteration cutoff (dynamic_graph._run_evaluate_route)
            # bounds how many ROUNDS run, this bounds the WHOLE graph
            # invocation's real elapsed time regardless of round count (a
            # single slow QEMU/GDB round could otherwise blow past any
            # reasonable wall-clock even within the iteration budget).
            # ainvoke's own asyncio.Task is cancelled by wait_for on
            # timeout — no partial FVVWState survives to unpack here, so
            # this is a fixed INCONCLUSIVE/budget_exhausted result, not a
            # richer one built from graph state.
            timed_out = True
            final_state = {}
    finally:
        if ctx.handle is not None:
            await deps.dynamic_session_executor.stop(ctx.handle)

    result = final_state.get("dynamic_result")
    if timed_out:
        result = TrackResult(
            verdict=VerificationVerdict.INCONCLUSIVE,
            proved_hypothesis="none",
            evidence={
                "reason": f"dynamic graph exceeded its "
                f"stage5_dynamic_wall_clock_seconds="
                f"{settings.stage5_dynamic_wall_clock_seconds}s wall-clock budget.",
                "budget_exhausted": True,
            },
        )
    elif result is None and stop_after is not None:
        # A deliberate diagnostic cut-off (`debug dynamic --stop-after`),
        # not a bug — the graph never reached a terminal route because we
        # stopped consuming the stream right after `stop_after` fired.
        # Everything else this function returns (guard_logs, gdb_transcript,
        # dynamic_extras) still reflects whatever accumulated up to that
        # node, which is the whole point of the diagnosis.
        result = TrackResult(
            verdict=VerificationVerdict.INCONCLUSIVE,
            proved_hypothesis="none",
            evidence={
                "reason": f"stopped after node {stop_after!r} for diagnosis — "
                "no terminal verdict was reached (or requested) this round.",
                "stopped_after": stop_after,
            },
        )
    elif result is None:
        # Every terminal route (`_run_bringup`'s exhaustion early-exit,
        # `_run_evaluate_route`'s confirmed/refuted/inconclusive cases) sets
        # `dynamic_result` before the graph reaches END — reaching here
        # means the graph ended some other way (e.g. the recursion-limit
        # safety net LangGraph itself enforces). Surface it as ERROR rather
        # than let a bare KeyError/AttributeError propagate into the
        # driver's blanket exception handler with no diagnosis.
        result = TrackResult(
            verdict=VerificationVerdict.ERROR,
            proved_hypothesis="none",
            evidence={
                "reason": "dynamic graph reached its end state without a terminal "
                "dynamic_result — likely the LangGraph recursion-limit safety net.",
                "budget_exhausted": True,
            },
        )

    guard_logs = final_state.get("signals") or []
    gdb_transcript = final_state.get("gdb_transcript") or ""
    observation = final_state.get("observation")
    dynamic_reached_sink = (
        observation.faulting_pc is not None or bool(observation.filesystem_artifacts)
        if observation is not None
        else None
    )
    dynamic_extras = {
        "arbitration_log": final_state.get("arbitration_log"),
        "observation": observation,
        "iteration_history": final_state.get("iteration_history") or [],
        "emulation_mode": ctx.emulation_plan.get("mode", ""),
    }
    return result, guard_logs, dynamic_reached_sink, gdb_transcript, dynamic_extras


async def _run_hitl_for_track(
    *,
    candidate: VerificationCandidate,
    track: str,
    result: TrackResult,
    plan,
    target,
    deps: FVVWDeps,
    settings: Settings,
    prompter: Prompter,
    dynamic_reached_sink: bool | None,
    guard_logs: list[dict],
    gdb_transcript: str,
    dynamic_extras: dict | None = None,
    trigger: Callable[[TrackResult], bool] = is_budget_exhausted,
) -> tuple[TrackResult, bool | None, list[dict], str, dict, HumanReviewRecord | None]:
    """Run the HITL prompt loop for ONE track (`"static"` or `"dynamic"`),
    bounded by `Settings.stage5_hitl_max_rounds`. Returns the (possibly
    updated) `TrackResult` plus the dynamic-track extras that can also
    change on a retry/inject round (`dynamic_reached_sink`, `guard_logs`,
    `gdb_transcript`, `dynamic_extras` — unchanged/passed through for the
    static track), and a `HumanReviewRecord` if the operator's LAST action
    was anything but `skip` (a `skip` leaves the track's own result
    untouched and produces no review record — there was nothing to
    attribute to a human).

    `trigger` decides whether another round is offered, re-checked against
    each round's (possibly updated) `result` — defaults to
    `is_budget_exhausted` (this track's own cap was hit). `run_fvvw`'s
    "neither track proved anything" branch passes a different trigger
    (`fvvw.hitl.neither_proved`, closed over the sibling track's fixed
    snapshot) so a track that never individually exhausted its budget can
    still be offered for review when BOTH tracks settled on "none".

    Each round re-reads the track's own `CommandLog` for the "recent
    commands" context shown at the prompt — cheap (JSONL read-back,
    `CommandLog.read_all()`) and always reflects the LATEST round's activity
    without this function needing to track command history itself.
    """
    command_log = deps.static_command_log if track == "static" else deps.dynamic_command_log
    last_decision = None
    round_number = 0

    while trigger(result) and round_number < settings.stage5_hitl_max_rounds:
        round_number += 1
        recent_commands = command_log.read_all()[-10:]
        req = HitlRequest(
            global_id=candidate.global_id,
            track=track,
            result=result,
            plan=plan,
            target=target,
            recent_commands=recent_commands,
            round_number=round_number,
        )
        decision = await prompt_for_track(req, prompter=prompter)
        last_decision = decision

        if decision.action == HitlAction.SKIP:
            break

        if decision.action == HitlAction.FORCE_VERDICT:
            forced = decision.forced_verdict or VerificationVerdict.INCONCLUSIVE
            result = force_verdict_result(
                previous=result, verdict=forced, rationale=decision.rationale
            )
            break

        if track == "static":
            static_plan = (
                plan.model_copy(update=decision.plan_overrides)
                if decision.action == HitlAction.OVERRIDE_PLAN
                else plan
            )
            if decision.action == HitlAction.RETRY:
                extra = decision.extra_iterations or settings.stage5_hitl_extra_iterations
                retry_settings = settings.model_copy(
                    update={
                        "stage5_max_agent_iterations": settings.stage5_max_agent_iterations
                        + extra
                    }
                )
                result = await run_static_track(
                    candidate,
                    static_plan,
                    generator_llm=deps.static_generator_llm,
                    evaluator_llm=deps.static_evaluator_llm,
                    workspace_dir=deps.static_workspace_dir,
                    executor=deps.static_executor,
                    settings=retry_settings,
                    system_prompt=deps.system_prompt,
                    command_log=command_log,
                )
            elif decision.action == HitlAction.OVERRIDE_PLAN:
                plan = static_plan
                result = await run_static_track(
                    candidate,
                    static_plan,
                    generator_llm=deps.static_generator_llm,
                    evaluator_llm=deps.static_evaluator_llm,
                    workspace_dir=deps.static_workspace_dir,
                    executor=deps.static_executor,
                    settings=settings,
                    system_prompt=deps.system_prompt,
                    command_log=command_log,
                )
            elif decision.action == HitlAction.INJECT:
                result = await run_injected_static_script(
                    candidate,
                    decision.injected_payload,
                    workspace_dir=deps.static_workspace_dir,
                    executor=deps.static_executor,
                    settings=settings,
                    command_log=command_log,
                )
        else:  # dynamic
            dynamic_plan = (
                plan.model_copy(update=decision.plan_overrides)
                if decision.action == HitlAction.OVERRIDE_PLAN
                else plan
            )
            retry_settings = settings
            if decision.action == HitlAction.RETRY:
                extra = decision.extra_iterations or settings.stage5_hitl_extra_iterations
                retry_settings = settings.model_copy(
                    update={
                        "stage5_dynamic_max_iterations": settings.stage5_dynamic_max_iterations
                        + extra
                    }
                )
            if decision.action == HitlAction.OVERRIDE_PLAN:
                plan = dynamic_plan
            raw_override = (
                decision.injected_payload if decision.action == HitlAction.INJECT else None
            )
            (
                result,
                guard_logs,
                dynamic_reached_sink,
                gdb_transcript,
                dynamic_extras,
            ) = await run_dynamic_track_only(
                candidate,
                dynamic_plan,
                target,
                deps=deps,
                settings_override=retry_settings,
                raw_recipe_override=raw_override,
            )

    review = None
    if last_decision is not None and last_decision.action != HitlAction.SKIP:
        review = build_human_review_record(
            track=track, decision=last_decision, rounds=max(round_number, 1)
        )
    return result, dynamic_reached_sink, guard_logs, gdb_transcript, dynamic_extras or {}, review


async def run_fvvw(
    candidate: VerificationCandidate,
    *,
    db_subfolder: Path,
    settings: Settings,
    hitl_prompter: Prompter = terminal_prompter,
    live: bool = False,
) -> dict:
    """Run the complete fork-join workflow for one candidate: strategy ->
    fork(static, dynamic) -> join -> joint_evaluate -> (report composed
    separately by `fvvw.report.write_report`, called by the driver after
    this returns, mirroring `agent.verifier.verify_candidate`'s "assemble
    the report outside the graph" shape).

    Returns a plain dict with `target`, `plan`, `static_result`,
    `dynamic_result`, `agreement`, `mechanism_confidence`,
    `reachability_confidence`, `residual_unknowns`, `guard_logs`,
    `dynamic_gdb_transcript`, `crosscheck_evidence`, `human_review`,
    `arbitration_log`, `observation`, `iteration_history`,
    `emulation_mode` — everything `fvvw.report.write_report` and the
    persisted `FVVWReport` need (the last four are the dynamic track's
    Node 9 spec contents #3/#4/#6/#7, unpacked from `run_dynamic_track_
    only`'s `dynamic_extras` bag).

    When `Settings.stage5_hitl_mode == "prompt"`, a track whose terminal
    result is tagged `budget_exhausted` (see `fvvw.hitl`'s trigger
    condition) is offered to the operator via `hitl_prompter`
    (`fvvw.hitl.terminal_prompter` by default — a scripted fake in tests)
    AFTER the barrier below and BEFORE `joint_evaluate`, never inside
    either track's own concurrent task — see `fvvw.hitl`'s module docstring
    for why. `hitl_prompter` is a parameter (not read from `Settings`
    itself) purely so tests can inject a scripted `Prompter` with no real
    stdin.
    """
    if candidate.source_path is None:
        raise Stage5InputError(
            f"{candidate.global_id}: no resolved normalized Joern C for bin_id="
            f"{candidate.bin_id} — the static track cannot build a CPG."
        )

    deps = await resolve_fvvw_deps(
        db_subfolder=db_subfolder, candidate=candidate, settings=settings, live=live
    )
    deps.static_workspace_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(candidate.source_path, layout.source_path(deps.static_workspace_dir))

    target = await characterize_target(candidate)
    plan = await strategy_agent(
        candidate,
        target,
        llm=deps.strategy_llm,
        settings=settings,
        system_prompt=None,
        command_log=deps.static_command_log,
    )

    # ---- fork: static + dynamic run concurrently -----------------------
    on_step = make_transcript_on_step(candidate.global_id) if live else None
    static_task = asyncio.ensure_future(
        run_static_track(
            candidate,
            plan.static_plan,
            generator_llm=deps.static_generator_llm,
            evaluator_llm=deps.static_evaluator_llm,
            workspace_dir=deps.static_workspace_dir,
            executor=deps.static_executor,
            settings=settings,
            system_prompt=deps.system_prompt,
            command_log=deps.static_command_log,
            on_step=on_step,
        )
    )
    crosscheck_task = asyncio.ensure_future(
        static_crosscheck(
            candidate,
            plan.static_plan,
            executor=deps.crosscheck_executor,
            settings=settings,
            command_log=deps.static_command_log,
        )
    )
    dynamic_task = asyncio.ensure_future(
        run_dynamic_track_only(candidate, plan.dynamic_plan, target, deps=deps)
    )

    # ---- await_both_tracks: the hard barrier ----------------------------
    static_result = await static_task
    crosscheck_result = await crosscheck_task
    (
        dynamic_result,
        guard_logs,
        dynamic_reached_sink,
        gdb_transcript,
        dynamic_extras,
    ) = await dynamic_task

    # ---- HITL: offer intervention on any track that exhausted its budget,
    # AFTER the barrier (both tracks' results are in hand) and BEFORE
    # joint_evaluate — see fvvw.hitl's module docstring for why this can't
    # live inside either track's own concurrent task. ---------------------
    human_review: HumanReviewRecord | None = None
    if settings.stage5_hitl_mode == "prompt":
        if is_budget_exhausted(static_result):
            (
                static_result,
                _,
                _,
                _,
                _,
                static_review,
            ) = await _run_hitl_for_track(
                candidate=candidate,
                track="static",
                result=static_result,
                plan=plan.static_plan,
                target=target,
                deps=deps,
                settings=settings,
                prompter=hitl_prompter,
                dynamic_reached_sink=dynamic_reached_sink,
                guard_logs=guard_logs,
                gdb_transcript=gdb_transcript,
                dynamic_extras=dynamic_extras,
            )
            human_review = static_review or human_review
        if is_budget_exhausted(dynamic_result):
            (
                dynamic_result,
                dynamic_reached_sink,
                guard_logs,
                gdb_transcript,
                dynamic_extras,
                dynamic_review,
            ) = await _run_hitl_for_track(
                candidate=candidate,
                track="dynamic",
                result=dynamic_result,
                plan=plan.dynamic_plan,
                target=target,
                deps=deps,
                settings=settings,
                prompter=hitl_prompter,
                dynamic_reached_sink=dynamic_reached_sink,
                guard_logs=guard_logs,
                gdb_transcript=gdb_transcript,
                dynamic_extras=dynamic_extras,
            )
            # A candidate rarely needs BOTH tracks reviewed in one run; if it
            # does, the dynamic track's review record is what's persisted —
            # human_review is a single record, not a list, matching
            # FVVWReport.human_review's shape. Both actions are still fully
            # visible either way: residual_unknowns (fvvw.joint) carries a
            # caveat for EVERY human_attributed track, not just the last one.
            human_review = dynamic_review or human_review
        # A third, independent trigger: neither track individually
        # exhausted its budget, but neither positively proved a hypothesis
        # either (both settled on "none") — the exact case classify_agreement
        # now calls Agreement.NEITHER. Without this, two honestly-inconclusive
        # tracks would sail straight into joint_evaluate with no human ever
        # seeing them. Only fires when NEITHER budget-exhaustion branch above
        # already ran (each already offers its own review opportunity), and
        # prompts the static track — the actionable retry/override/inject
        # path for exactly the class of failure Phase 0/1 targets (a script
        # that never proved anything, with iterations still available).
        if (
            not is_budget_exhausted(static_result)
            and not is_budget_exhausted(dynamic_result)
            and neither_proved(static_result, dynamic_result)
        ):
            dynamic_result_snapshot = dynamic_result
            (
                static_result,
                _,
                _,
                _,
                _,
                neither_review,
            ) = await _run_hitl_for_track(
                candidate=candidate,
                track="static",
                result=static_result,
                plan=plan.static_plan,
                target=target,
                deps=deps,
                settings=settings,
                prompter=hitl_prompter,
                dynamic_reached_sink=dynamic_reached_sink,
                guard_logs=guard_logs,
                gdb_transcript=gdb_transcript,
                dynamic_extras=dynamic_extras,
                trigger=lambda r: neither_proved(r, dynamic_result_snapshot),
            )
            human_review = neither_review or human_review

    # ---- joint_evaluate ---------------------------------------------------
    verdict = joint_evaluate(
        static_result=static_result,
        dynamic_result=dynamic_result,
        crosscheck_evidence=crosscheck_result.to_evidence_dict(),
        guard_logs=guard_logs,
        dynamic_reached_sink=dynamic_reached_sink,
    )

    return {
        "target": target,
        "plan": plan,
        "static_result": static_result,
        "dynamic_result": dynamic_result,
        "agreement": verdict.agreement,
        "mechanism_confidence": verdict.mechanism_confidence,
        "reachability_confidence": verdict.reachability_confidence,
        "residual_unknowns": verdict.residual_unknowns,
        "guard_logs": guard_logs,
        "dynamic_gdb_transcript": gdb_transcript,
        "crosscheck_evidence": crosscheck_result.to_evidence_dict(),
        "human_review": human_review,
        "deps": deps,
        "arbitration_log": dynamic_extras.get("arbitration_log"),
        "observation": dynamic_extras.get("observation"),
        "iteration_history": dynamic_extras.get("iteration_history") or [],
        "emulation_mode": dynamic_extras.get("emulation_mode", ""),
    }


async def run_dynamic_only(
    candidate: VerificationCandidate,
    *,
    db_subfolder: Path,
    settings: Settings,
    live: bool = False,
    stop_after: str | None = None,
) -> dict:
    """Production single-track entry point: `characterize -> strategy -> the
    dynamic (QEMU+GDB) track alone` — no static track, no crosscheck, no
    `joint_evaluate`. The dynamic-only counterpart to `--joern-only`'s
    static-only `driver.run_queue`, for the case where only the dynamic
    track's own verdict is wanted (or the static track's `source_path`
    genuinely isn't available for this candidate).

    Unlike `run_fvvw`, this does NOT require `candidate.source_path` to be
    resolved — the dynamic track never reads it (only the static track's
    CPG build does).

    `agreement`/`mechanism_confidence`/`reachability_confidence` are
    deliberately absent from the returned dict — those are two-track
    reconciliation concepts `fvvw.joint.joint_evaluate` computes by
    comparing static and dynamic results, and don't mean anything for one
    track run alone (see `common.verification.DynamicOnlyReport`'s
    docstring for why this gets its own report schema instead of a
    `FVVWReport` with a placeholder `static_result`).

    Returns `{"target", "plan", "dynamic_result", "guard_logs",
    "dynamic_gdb_transcript", "arbitration_log", "observation",
    "iteration_history", "emulation_mode", "deps"}` — persistence is
    `fvvw.driver.run_dynamic_only_queue`'s job, mirroring `run_fvvw`'s own
    "return a plain dict, let the driver persist" shape.
    """
    deps = await resolve_fvvw_deps(
        db_subfolder=db_subfolder, candidate=candidate, settings=settings, live=live
    )
    target = await characterize_target(candidate)
    plan = await strategy_agent(
        candidate,
        target,
        llm=deps.strategy_llm,
        settings=settings,
        system_prompt=None,
        command_log=deps.dynamic_command_log,
    )

    (
        dynamic_result,
        guard_logs,
        _dynamic_reached_sink,
        gdb_transcript,
        dynamic_extras,
    ) = await run_dynamic_track_only(
        candidate, plan.dynamic_plan, target, deps=deps, stop_after=stop_after
    )

    return {
        "target": target,
        "plan": plan,
        "dynamic_result": dynamic_result,
        "guard_logs": guard_logs,
        "dynamic_gdb_transcript": gdb_transcript,
        "arbitration_log": dynamic_extras.get("arbitration_log"),
        "observation": dynamic_extras.get("observation"),
        "iteration_history": dynamic_extras.get("iteration_history") or [],
        "emulation_mode": dynamic_extras.get("emulation_mode", ""),
        "deps": deps,
    }


__all__ = [
    "FVVWDeps",
    "resolve_checkpointer",
    "resolve_fvvw_deps",
    "run_dynamic_only",
    "run_dynamic_track_only",
    "run_fvvw",
]
