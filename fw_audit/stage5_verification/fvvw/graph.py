"""`fvvw.graph` — the top-level fork-join `StateGraph(FVVWState)` (FVVW v3
§5/§10): `ingest -> characterize -> strategy`, forking into the static
track (the existing Joern pipeline, reused via `fvvw.static_track`) and the
dynamic track (`fvvw.dynamic_track`) running concurrently, joining at
`await_both_tracks`, then `joint_evaluate -> write_report -> END`.

Track isolation (no static-track node reads `dynamic_*`, no dynamic-track
node reads `static_result`) is enforced by construction: each track is
wired as its own linear sequence of plain-dict-returning async closures
over `fvvw.state`'s `STATIC_TRACK_*`/`DYNAMIC_TRACK_*` key tuples — a node
literally cannot see a key nothing put in its own closure's inputs, since
every closure here reads only from the specific fields of `state` its own
docstring names, mirroring `agent.graph.build_verifier_graph`'s node-closure
shape rather than importing `state` wholesale.

Repair back-edges (`reach_target`/`satisfy_guards`/`instrument_trigger` ->
`bringup_stabilize` on a `DynamicFault`) are implemented as in-node retry
loops bounded by `Settings.stage5_bringup_max_repairs`
(`fvvw.dynamic_track.BringupExhausted` raised past that budget) rather than
LangGraph conditional edges back to a `bringup_stabilize` NODE — this
keeps `BringupContext`'s mutable session/launch state naturally scoped to
one dynamic-track node closure instead of round-tripping it through graph
state on every repair, while still matching the FVVW §5 diagram's dotted
"any dynamic node -> bringup_stabilize -> resume that node" behavior
exactly from the outside.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from langchain_core.language_models import BaseChatModel

from fw_audit.common.verification import TrackResult, VerificationVerdict
from fw_audit.config.llm_config import AgentRole, get_llm_for_agent
from fw_audit.config.settings import Settings
from fw_audit.executors.base import Executor
from fw_audit.executors.sandbox_executor import SandboxExecutor
from fw_audit.stage5_verification import layout
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.cmdlog import CommandLog, LoggingSessionExecutor
from fw_audit.stage5_verification.errors import (
    Stage5InputError,
    VerifierModelUnavailableError,
)
from fw_audit.stage5_verification.fvvw.dynamic_track import (
    BringupContext,
    BringupExhausted,
    DynamicFault,
    bringup_stabilize,
    cleanup_marker_artifact,
    collect_signals,
    dynamic_evaluate,
    instrument_trigger,
    plan_emulation,
    reach_target,
    satisfy_guards,
)
from fw_audit.stage5_verification.fvvw.joint import joint_evaluate
from fw_audit.stage5_verification.fvvw.static_track import run_static_track
from fw_audit.stage5_verification.fvvw.strategy import strategy_agent
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
    strategy_llm: BaseChatModel
    static_generator_llm: BaseChatModel
    static_evaluator_llm: BaseChatModel
    report_llm: BaseChatModel
    static_executor: Executor
    crosscheck_executor: Executor
    dynamic_session_executor: SandboxExecutor
    static_workspace_dir: Path
    dynamic_workspace_dir: Path
    static_command_log: CommandLog
    dynamic_command_log: CommandLog
    system_prompt: str | None = None


async def resolve_fvvw_deps(
    *, db_subfolder: Path, candidate: VerificationCandidate, settings: Settings
) -> FVVWDeps:
    """Resolve every LLM role + executor the fork-join needs for one
    candidate, up front — mirrors `agent.verifier.verify_candidate`'s own
    "resolve everything before any tool invocation" order, extended to the
    two new roles and the two new executor kinds. Raises
    `VerifierModelUnavailableError` if any of the four LLM roles can't be
    resolved — a fork-join run needs all of them, not just the static
    track's two.

    Also resolves the per-track `CommandLog`s (`stage5/fvvw/logs/<gid>.
    <static|dynamic>.jsonl`) and wraps `dynamic_session_executor` in a
    `LoggingSessionExecutor` so every dynamic-track command is captured
    centrally — see `cmdlog`'s module docstring for why this is composition
    over the executor, never an edit to `SandboxExecutor` itself."""
    try:
        strategy_llm = get_llm_for_agent(AgentRole.STAGE5_STRATEGY_AGENT, settings=settings)
        static_generator_llm = get_llm_for_agent(
            AgentRole.STAGE5_SCRIPT_GENERATOR, settings=settings
        )
        static_evaluator_llm = get_llm_for_agent(
            AgentRole.STAGE5_RESULT_EVALUATOR, settings=settings
        )
        report_llm = get_llm_for_agent(AgentRole.STAGE5_REPORT_WRITER, settings=settings)
    except (ImportError, ValueError) as exc:
        raise VerifierModelUnavailableError(str(exc)) from exc

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    static_workspace_dir = layout.workspace_dir(stage5_dir_, candidate.global_id)
    fvvw_dir_ = layout.fvvw_dir(stage5_dir_)
    dynamic_workspace_dir = layout.fvvw_dynamic_workspace_dir(fvvw_dir_, candidate.global_id)

    if settings.stage5_command_log:
        static_command_log = CommandLog(
            layout.fvvw_command_log_path(fvvw_dir_, candidate.global_id, "static"),
            track="static",
        )
        dynamic_command_log = CommandLog(
            layout.fvvw_command_log_path(fvvw_dir_, candidate.global_id, "dynamic"),
            track="dynamic",
        )
    else:
        static_command_log = CommandLog.disabled()
        dynamic_command_log = CommandLog.disabled()

    dynamic_session_executor = LoggingSessionExecutor(
        verification_session_executor(settings), dynamic_command_log
    )

    return FVVWDeps(
        settings=settings,
        strategy_llm=strategy_llm,
        static_generator_llm=static_generator_llm,
        static_evaluator_llm=static_evaluator_llm,
        report_llm=report_llm,
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
) -> tuple[TrackResult, list[dict], bool | None, str]:
    """The dynamic track's full sequence, run as one function rather than
    discrete LangGraph nodes (see this module's docstring for why) —
    still internally shaped as the seven FVVW nodes in order, with the
    bring-up repair loop and the hypothesis A/B switch exactly as
    `fvvw.dynamic_track` implements them.

    Returns `(TrackResult, guard_logs, dynamic_reached_sink,
    gdb_transcript)` — the extra values `joint_evaluate`/`fvvw.report` need
    beyond the bare `TrackResult`.
    """
    settings = deps.settings
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
        )

    ctx = BringupContext(
        candidate=candidate,
        target=target,
        plan=plan,
        emulation_plan=emulation,
        settings=settings,
        session_executor=deps.dynamic_session_executor,
    )

    transcript = ""
    guard_logs: list[dict] = []
    reached: bool = False
    captured: str | None = None
    active_hypothesis: Literal["A", "B"] = "A"
    iteration = 0

    try:
        # bringup_stabilize's own readiness probe (QEMU gdbstub never
        # opened its port) raises DynamicFault, not BringupExhausted — that
        # fault is retriable via the same repair-budget mechanism every
        # other dynamic-track fault uses, not fatal on the first attempt.
        # Retry it here the same way the in-loop DynamicFault handler below
        # does; bringup_stabilize itself is what ends the branch by raising
        # BringupExhausted once ctx.repair_count exceeds
        # stage5_bringup_max_repairs, so this loop is bounded by that, not
        # by anything new here.
        while True:
            try:
                await bringup_stabilize(ctx)
                break
            except DynamicFault:
                continue

        # Best-effort: remove any stale marker artifact left behind by an
        # earlier run against the same rootfs — otherwise the
        # filesystem_artifact signal in collect_signals would report FOUND
        # unconditionally, regardless of whether THIS run's sink is ever
        # reached. See cleanup_marker_artifact's own docstring.
        await cleanup_marker_artifact(ctx)

        while True:
            iteration += 1
            try:
                transcript, reached = await reach_target(ctx, gdb_transcript_so_far=transcript)
                if reached:
                    transcript, guard_logs = await satisfy_guards(
                        ctx, gdb_transcript_so_far=transcript
                    )
                    transcript, captured = await instrument_trigger(
                        ctx, gdb_transcript_so_far=transcript
                    )
                    signals = await collect_signals(ctx, captured_sink_argument=captured)
                else:
                    signals = []
            except DynamicFault:
                # bringup_stabilize's own readiness probe can ALSO raise
                # DynamicFault (staging failure, gdbstub-never-opened
                # timeout) — that fault must not escape this handler
                # uncaught (it did before this fix: raised from inside an
                # `except DynamicFault:` block, it was not re-caught here,
                # so it propagated all the way out of run_dynamic_track_only
                # into the driver's blanket `except Exception`, recording
                # the candidate as "failed" with a message that looked
                # nothing like a QEMU problem). Retry bring-up itself the
                # same bounded way the pre-loop stand-up does — bounded by
                # bringup_stabilize's own repair_count check, which raises
                # BringupExhausted (caught below) once the budget is spent.
                while True:
                    try:
                        await bringup_stabilize(ctx)
                        break
                    except DynamicFault:
                        continue
                continue

            outcome = dynamic_evaluate(
                reached=reached,
                captured_sink_argument=captured,
                signals=signals,
                plan=plan,
                active_hypothesis=active_hypothesis,
                iteration=iteration,
                max_iterations=settings.stage5_dynamic_max_iterations,
            )
            if outcome["route"] == "done":
                return outcome["result"], guard_logs, reached, transcript
            if outcome["route"] == "switch_hypothesis":
                active_hypothesis = outcome["next_hypothesis"]
                iteration = 0
                continue
            # "retry" — loop again with the same active_hypothesis

    except BringupExhausted as exc:
        return (
            TrackResult(
                verdict=VerificationVerdict.ERROR,
                proved_hypothesis="none",
                evidence={"reason": f"not_run: {exc}"},
            ),
            guard_logs,
            None,
            transcript,
        )
    finally:
        if ctx.handle is not None:
            await deps.dynamic_session_executor.stop(ctx.handle)


async def run_fvvw(
    candidate: VerificationCandidate,
    *,
    db_subfolder: Path,
    settings: Settings,
) -> dict:
    """Run the complete fork-join workflow for one candidate: strategy ->
    fork(static, dynamic) -> join -> joint_evaluate -> (report composed
    separately by `fvvw.report.write_report`, called by the driver after
    this returns, mirroring `agent.verifier.verify_candidate`'s "assemble
    the report outside the graph" shape).

    Returns a plain dict with `target`, `plan`, `static_result`,
    `dynamic_result`, `agreement`, `mechanism_confidence`,
    `reachability_confidence`, `residual_unknowns`, `guard_logs`,
    `dynamic_gdb_transcript`, `crosscheck_evidence` — everything
    `fvvw.report.write_report` and the persisted `FVVWReport` need.
    """
    if candidate.source_path is None:
        raise Stage5InputError(
            f"{candidate.global_id}: no resolved normalized Joern C for bin_id="
            f"{candidate.bin_id} — the static track cannot build a CPG."
        )

    deps = await resolve_fvvw_deps(
        db_subfolder=db_subfolder, candidate=candidate, settings=settings
    )
    deps.static_workspace_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(candidate.source_path, layout.source_path(deps.static_workspace_dir))

    target = await characterize_target(candidate)
    plan = await strategy_agent(
        candidate, target, llm=deps.strategy_llm, settings=settings, system_prompt=None
    )

    # ---- fork: static + dynamic run concurrently -----------------------
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
        )
    )
    crosscheck_task = asyncio.ensure_future(
        static_crosscheck(
            candidate,
            plan.static_plan,
            executor=deps.crosscheck_executor,
            settings=settings,
        )
    )
    dynamic_task = asyncio.ensure_future(
        run_dynamic_track_only(candidate, plan.dynamic_plan, target, deps=deps)
    )

    # ---- await_both_tracks: the hard barrier ----------------------------
    static_result = await static_task
    crosscheck_result = await crosscheck_task
    dynamic_result, guard_logs, dynamic_reached_sink, gdb_transcript = await dynamic_task

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
        "deps": deps,
    }


__all__ = [
    "FVVWDeps",
    "resolve_checkpointer",
    "resolve_fvvw_deps",
    "run_dynamic_track_only",
    "run_fvvw",
]
