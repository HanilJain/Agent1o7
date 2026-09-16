"""FVVW v3's own debug module — inspect/run the strategy agent, the
dynamic (QEMU+GDB) track, and the full fork-join in isolation, without
persisting into `stage5/fvvw/reports/` (the fork-join's own tracked
output). Mirrors `stage5_verification.debug`'s exact "dry run, never
persist" discipline, kept as a SEPARATE module so that one is completely
untouched.

Per the user's explicit request: the Joern track and the QEMU track must
each be runnable individually via `fw-verify debug`, not only as part of
the combined `fw-verify run`. `debug_dynamic` below is that QEMU-only path
— `stage5_verification.debug`'s existing `debug_build_cpg`/`debug_run_script`
already cover the Joern-only path, reused as-is via `runner.py`'s existing
`debug build-cpg`/`debug script` subcommands.

Wired into `runner.py debug {strategy,dynamic,fvvw}`.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path

from fw_audit.common.verification import (
    ArbitrationLog,
    ObservationRecord,
    RouteDecision,
    StrategyPlan,
    TargetMeta,
    TrackResult,
)
from fw_audit.config.llm_config import AgentRole, get_llm_for_agent
from fw_audit.config.settings import Settings, get_settings
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.cmdlog import CommandLog
from fw_audit.stage5_verification.debug import find_candidate
from fw_audit.stage5_verification.errors import (
    Stage5InputError,
    VerifierModelUnavailableError,
)
from fw_audit.stage5_verification.fvvw.graph import (
    resolve_fvvw_deps,
    run_dynamic_track_only,
    run_fvvw,
)
from fw_audit.stage5_verification.fvvw.report import write_report
from fw_audit.stage5_verification.fvvw.strategy import strategy_agent
from fw_audit.stage5_verification.live_console import LiveConsole
from fw_audit.stage5_verification.llm_logging import LoggingChatModel
from fw_audit.stage5_verification.tools.characterize_tool import characterize_target


@dataclass(frozen=True)
class DebugStrategyResult:
    candidate: VerificationCandidate
    target: TargetMeta
    plan: StrategyPlan


async def debug_strategy(
    db_subfolder: Path,
    global_id: str,
    *,
    settings: Settings | None = None,
    live: bool = True,
) -> DebugStrategyResult:
    """Runs `characterize_target` + `strategy_agent` for ONE finding —
    emits the `StrategyPlan` only, without running either track. Useful
    for iterating on/inspecting the strategy prompt independent of the
    (much more expensive) tracks it feeds.

    `live` (default `True`, matching `debug verify`'s existing default)
    attaches a console-only `LiveConsole` (no JSONL persisted — this debug
    command has no track/`db_subfolder` output directory of its own) so the
    raw prompt/response and the parsed `StrategyPlan`/any parse failures
    print as they happen."""
    settings = settings or get_settings()
    candidate = find_candidate(db_subfolder, global_id)
    try:
        strategy_llm = get_llm_for_agent(AgentRole.STAGE5_STRATEGY_AGENT, settings=settings)
    except (ImportError, ValueError) as exc:
        raise VerifierModelUnavailableError(str(exc)) from exc

    live_console = (
        LiveConsole(truncate_chars=settings.stage5_live_console_truncate_chars) if live else None
    )
    command_log = CommandLog(None, track="strategy", gid=global_id, live=live_console)
    wrapped_llm = LoggingChatModel(strategy_llm, role="strategy_agent", command_log=command_log)

    target = await characterize_target(candidate)
    plan = await strategy_agent(
        candidate, target, llm=wrapped_llm, settings=settings, command_log=command_log
    )
    return DebugStrategyResult(candidate=candidate, target=target, plan=plan)


@dataclass(frozen=True)
class DebugDynamicResult:
    candidate: VerificationCandidate
    target: TargetMeta
    plan: StrategyPlan
    result: TrackResult
    gdb_transcript: str
    guard_logs: list[dict]
    arbitration_log: ArbitrationLog | None = None
    """Node 3's full structured bring-up/arbitration record — surfaced here
    (not persisted, per this module's "never write to stage5/fvvw/reports/"
    discipline) so `fw-verify debug dynamic` can inspect exactly which
    dummy files/env-fixes the bring-up agent applied this run."""
    observation: ObservationRecord | None = None
    """Node 7's final structured capture for the round that produced
    `result`."""
    iteration_history: list[RouteDecision] = dataclasses.field(default_factory=list)
    """Every `RouteDecision` Node 8 emitted this run, in order."""


async def debug_dynamic(
    db_subfolder: Path,
    global_id: str,
    *,
    settings: Settings | None = None,
    live: bool = True,
    stop_after: str | None = None,
) -> DebugDynamicResult:
    """Runs ONLY the dynamic (QEMU+GDB) track for one finding —
    characterize -> strategy (needed to get a `DynamicPlan`) ->
    plan_emulation -> bringup -> reach/guards/trigger/collect ->
    dynamic_evaluate. No static track, no crosscheck, no joint_evaluate, no
    report. This is the per-track debug entry point the user explicitly
    asked for, mirroring `stage5_verification.debug.debug_build_cpg`/
    `debug_run_script`'s Joern-only equivalent.

    `live` (default `True`, matching `debug verify`'s existing default)
    prints every LLM call, tool call, and dynamic-graph node update as it
    happens. `stop_after`, when given (one of the dynamic graph's own node
    ids — `plan_emulation`/`bringup`/`health_gate`/`gdb_attach`/`trigger`/
    `evaluate_route`/`plan_emulation_escalate`), halts the run right after
    that node fires — per-node diagnosis without running the rest of the
    track (see `fvvw.graph.run_dynamic_track_only`'s docstring).
    """
    settings = settings or get_settings()
    candidate = find_candidate(db_subfolder, global_id)

    deps = await resolve_fvvw_deps(
        db_subfolder=db_subfolder, candidate=candidate, settings=settings, live=live
    )
    target = await characterize_target(candidate)
    plan = await strategy_agent(
        candidate,
        target,
        llm=deps.strategy_llm,
        settings=settings,
        command_log=deps.dynamic_command_log,
    )

    result, guard_logs, _reached, transcript, dynamic_extras = await run_dynamic_track_only(
        candidate, plan.dynamic_plan, target, deps=deps, stop_after=stop_after
    )
    return DebugDynamicResult(
        candidate=candidate,
        target=target,
        plan=plan,
        result=result,
        gdb_transcript=transcript,
        guard_logs=guard_logs,
        arbitration_log=dynamic_extras.get("arbitration_log"),
        observation=dynamic_extras.get("observation"),
        iteration_history=dynamic_extras.get("iteration_history") or [],
    )


async def debug_fvvw(
    db_subfolder: Path,
    global_id: str,
    *,
    settings: Settings | None = None,
    live: bool = True,
) -> dict:
    """Runs the COMPLETE fork-join (both tracks, joint_evaluate, and
    write_report) for one finding — a dry run: everything `fw-verify run`
    would do, without persisting to `stage5/fvvw/reports/`. Returns the
    same outcome dict `fvvw.graph.run_fvvw` does, plus a `report_markdown`
    key with the composed disclosure report.

    `live` (default `True`, matching `debug verify`'s existing default)
    prints every LLM call/tool call/parsed result/dynamic-graph node update
    from both tracks as they happen, tagged `[gid]`."""
    settings = settings or get_settings()
    candidate = find_candidate(db_subfolder, global_id)
    if candidate.source_path is None:
        raise Stage5InputError(
            f"{global_id}: no resolved normalized Joern C for bin_id={candidate.bin_id} "
            "— the static track cannot build a CPG."
        )

    outcome = await run_fvvw(candidate, db_subfolder=db_subfolder, settings=settings, live=live)
    deps = outcome["deps"]
    report_markdown = await write_report(
        candidate=candidate,
        finding=candidate.finding,
        static_result=outcome["static_result"],
        dynamic_result=outcome["dynamic_result"],
        agreement=outcome["agreement"],
        mechanism_confidence=outcome["mechanism_confidence"].value,
        reachability_confidence=outcome["reachability_confidence"].value,
        residual_unknowns=outcome["residual_unknowns"],
        dynamic_gdb_transcript=outcome["dynamic_gdb_transcript"],
        llm=deps.report_llm,
        settings=settings,
    )
    outcome["report_markdown"] = report_markdown
    return outcome


__all__ = [
    "DebugDynamicResult",
    "DebugStrategyResult",
    "debug_dynamic",
    "debug_fvvw",
    "debug_strategy",
]
