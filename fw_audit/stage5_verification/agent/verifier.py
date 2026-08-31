"""The verification pipeline's entry point: one `VerificationCandidate` in,
one validated `VerificationReport` out.

Mirrors `stage3_analysis.agent.analyst.analyze_chunk`'s shape (`get_llm_for_agent`
-> build a graph/chain -> invoke -> funnel failures into one module-specific
error), extended for the two-role generate/run/evaluate loop `graph.py` wires.
Signature, return type, and the `on_step`/`system_prompt` contracts are
UNCHANGED from the previous tool-calling agent — `driver.py`/`debug.py`/
`runner.py` needed no changes for this replacement.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from fw_audit.common.verification import (
    CpgBuildRecord,
    JoernScriptAttempt,
    TranscriptEntry,
    VerificationReport,
    VerificationVerdict,
)
from fw_audit.config.llm_config import AgentRole, get_llm_for_agent
from fw_audit.config.settings import Settings
from fw_audit.observability import current_trace_url, run_config
from fw_audit.stage5_verification import layout
from fw_audit.stage5_verification.agent import transcript as tx
from fw_audit.stage5_verification.agent.graph import build_verifier_graph
from fw_audit.stage5_verification.agent.prompts import (
    GENERATOR_SYSTEM_PROMPT,
    render_finding_brief,
)
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.errors import (
    SandboxUnavailableError,
    VerifierModelUnavailableError,
)
from fw_audit.stage5_verification.tools.joern_tool import joern_executor

OnStep = Callable[[list[TranscriptEntry]], None]
"""Called once per graph step (see `verify_candidate`'s `on_step` param)
with only the transcript entries NEWLY produced by that step — never the
whole transcript so far, so a caller can print/stream incrementally
without re-printing earlier turns."""


async def verify_candidate(
    candidate: VerificationCandidate,
    *,
    db_subfolder: Path,
    settings: Settings,
    system_prompt: str | None = None,
    on_step: OnStep | None = None,
) -> VerificationReport:
    """Run the full build-CPG -> generate/run/evaluate loop -> conclude
    pipeline for one candidate, returning a `VerificationReport`. Does NOT
    persist anything — that's `driver.py`'s job (or a debug caller's, for a
    dry run).

    Raises `SandboxUnavailableError` if `candidate.source_path` never
    resolved (see `candidate_index.discover_candidates`'s docstring) or the
    sandbox executor isn't reachable, and `VerifierModelUnavailableError` if
    either `AgentRole.STAGE5_SCRIPT_GENERATOR`/`AgentRole.STAGE5_RESULT_EVALUATOR`
    model/credential can't be resolved — both checked before any Joern
    invocation, mirroring `AnalysisUnavailableError`'s "no repair possible"
    transport-failure contract.

    `system_prompt` overrides `agent.prompts.GENERATOR_SYSTEM_PROMPT` for
    this call only — the `--prompt-file` debugging control (see `runner.py`).

    `on_step`, when given, is called after every graph node (CPG build,
    script generation, script execution, or evaluation) with that step's
    newly-appended `TranscriptEntry` objects — this is what lets
    `fw-verify debug verify` print the pipeline's progress live, turn by
    turn, instead of only showing the finished report. When omitted (the
    default — `driver.py`'s production path never passes one), the graph
    still runs to completion the same way; only the live callback is
    skipped. Either way, the RETURNED report's `transcript` field always
    has the complete record — `on_step` is purely an additional live view.
    """
    if candidate.source_path is None:
        raise SandboxUnavailableError(
            f"{candidate.global_id}: no resolved normalized Joern C for bin_id="
            f"{candidate.bin_id} — cannot build a CPG."
        )

    executor = joern_executor(settings)
    if not executor.available():
        raise SandboxUnavailableError(
            "Sandbox executor unavailable (Docker unreachable?) — cannot verify "
            f"{candidate.global_id}."
        )

    try:
        generator_llm = get_llm_for_agent(AgentRole.STAGE5_SCRIPT_GENERATOR, settings=settings)
        evaluator_llm = get_llm_for_agent(AgentRole.STAGE5_RESULT_EVALUATOR, settings=settings)
    except (ImportError, ValueError) as exc:
        raise VerifierModelUnavailableError(str(exc)) from exc

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    workspace_dir_ = layout.workspace_dir(stage5_dir_, candidate.global_id)
    workspace_dir_.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(candidate.source_path, layout.source_path(workspace_dir_))

    cpg_build_holder: list[CpgBuildRecord] = []
    attempts: list[JoernScriptAttempt] = []
    graph = build_verifier_graph(
        llm=generator_llm,
        evaluator_llm=evaluator_llm,
        workspace_dir=workspace_dir_,
        executor=executor,
        settings=settings,
        max_iterations=settings.stage5_max_agent_iterations,
        cpg_build_holder=cpg_build_holder,
        attempts=attempts,
    )

    brief = render_finding_brief(candidate)
    effective_system_prompt = (
        system_prompt if system_prompt is not None else GENERATOR_SYSTEM_PROMPT
    )

    started_at = datetime.now(UTC)
    initial_state = {
        "brief": brief,
        "system_prompt": system_prompt,
        "max_iterations": settings.stage5_max_agent_iterations,
        "transcript": tx.initial_transcript(system_prompt=effective_system_prompt, brief=brief),
    }
    config = run_config(
        run_name="stage5.verify_candidate",
        metadata={"global_id": candidate.global_id, "bin_id": candidate.bin_id},
        settings=settings,
    ) or {}
    # See fvvw.static_track.run_static_track's identical comment — HITL's
    # "retry with more iterations" action can raise stage5_max_agent_iterations
    # well past LangGraph's default recursion_limit (25).
    config["recursion_limit"] = 3 * settings.stage5_max_agent_iterations + 8
    try:
        if on_step is None:
            final_state = await graph.ainvoke(initial_state, config=config)
        else:
            final_state = await _stream_with_callback(
                graph, initial_state, on_step, config=config
            )
    except (OSError, TimeoutError) as exc:
        raise VerifierModelUnavailableError(f"verification pipeline call failed: {exc}") from exc
    finished_at = datetime.now(UTC)
    trace_url = current_trace_url()

    transcript = final_state.get("transcript", [])

    # Workspace cleanup (when Settings.stage5_keep_workspace is False) happens
    # in driver.py, AFTER the report is persisted — not here, so a debug
    # caller inspecting verify_candidate()'s return value directly still has
    # the workspace on disk to look at.

    verdict = final_state.get("verdict")
    if verdict is None:
        # Should be unreachable: conclude_node always sets it.
        verdict = VerificationVerdict.ERROR  # pragma: no cover - defensive

    return VerificationReport(
        global_id=candidate.global_id,
        bin_id=candidate.bin_id,
        model=f"generator={_model_label(generator_llm)}, evaluator={_model_label(evaluator_llm)}",
        cpg_build=cpg_build_holder[0] if cpg_build_holder else CpgBuildRecord(),
        attempts=attempts,
        transcript=transcript,
        verdict=verdict,
        confidence=final_state.get("verdict_confidence", ""),
        summary=final_state.get("verdict_summary", ""),
        evidence=final_state.get("verdict_evidence", ""),
        recommended_next_steps=final_state.get("verdict_next_steps", []),
        started_at=started_at,
        finished_at=finished_at,
        trace_url=trace_url,
    )


async def _stream_with_callback(
    graph, initial_state: dict, on_step: OnStep, *, config: dict | None = None
) -> dict:
    """Drive `graph` via `astream(..., stream_mode="values")` instead of a
    single `ainvoke`, calling `on_step` with each step's newly-appended
    transcript entries as they arrive.

    `stream_mode="values"` yields the FULL accumulated state after every
    node runs (not a diff) — the previous transcript length is tracked here
    so only the slice a given step actually added gets passed to `on_step`,
    never a growing prefix the caller would have to de-duplicate itself.
    Returns the final state, same shape `ainvoke` would have returned.
    """
    seen = 0
    state = initial_state
    async for state in graph.astream(initial_state, config=config, stream_mode="values"):
        step_entries = state.get("transcript", [])
        new_entries = step_entries[seen:]
        if new_entries:
            on_step(new_entries)
        seen = len(step_entries)
    return state


def _model_label(llm: object) -> str:
    """Best-effort `<provider>:<model>` label for the report — `BaseChatModel`
    subclasses don't share one uniform attribute name, so this degrades to
    the class name rather than raising if neither common attribute exists."""
    model_name = getattr(llm, "model", None) or getattr(llm, "model_name", None)
    return str(model_name) if model_name else type(llm).__name__


__all__ = ["verify_candidate"]
