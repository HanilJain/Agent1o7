"""The verification agent's entry point: one `VerificationCandidate` in,
one validated `VerificationReport` out.

Mirrors `stage3_analysis.agent.analyst.analyze_chunk`'s shape (`get_llm_for_agent`
-> build a graph/chain -> invoke -> funnel failures into one module-specific
error), extended for the multi-turn tool-calling loop `graph.py` wires.
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
from fw_audit.stage5_verification import layout
from fw_audit.stage5_verification.agent.graph import build_verifier_graph, messages_to_transcript
from fw_audit.stage5_verification.agent.prompts import build_messages
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.errors import (
    SandboxUnavailableError,
    VerifierModelUnavailableError,
)
from fw_audit.stage5_verification.tools.joern_tool import build_joern_tools, joern_executor

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
    """Run the full build-CPG -> tool-calling-loop -> finalize pipeline for
    one candidate, returning a `VerificationReport`. Does NOT persist
    anything — that's `driver.py`'s job (or a debug caller's, for a dry run).

    Raises `SandboxUnavailableError` if `candidate.source_path` never
    resolved (see `candidate_index.discover_candidates`'s docstring) or the
    sandbox executor isn't reachable, and `VerifierModelUnavailableError` if
    the configured `AgentRole.STAGE5_VERIFIER` model/credential can't be
    resolved — both checked before any tool call, mirroring
    `AnalysisUnavailableError`'s "no repair possible" transport-failure
    contract.

    `system_prompt` overrides `agent.prompts.SYSTEM_PROMPT` for this call
    only — the `--prompt-file` debugging control (see `runner.py`).

    `on_step`, when given, is called after every graph node (agent turn,
    tool execution, or finalize) with that step's newly-appended
    `TranscriptEntry` objects — this is what lets `fw-verify debug verify`
    print the agent's reasoning and tool calls live, turn by turn, instead
    of only showing the finished report. When omitted (the default —
    `driver.py`'s production path never passes one), the graph still runs
    to completion the same way; only the live callback is skipped. Either
    way, the RETURNED report's `transcript` field always has the complete
    conversation — `on_step` is purely an additional live view, not the
    only way to get this data.
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
        llm = get_llm_for_agent(AgentRole.STAGE5_VERIFIER, settings=settings)
    except (ImportError, ValueError) as exc:
        raise VerifierModelUnavailableError(str(exc)) from exc

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    workspace_dir_ = layout.workspace_dir(stage5_dir_, candidate.global_id)
    workspace_dir_.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(candidate.source_path, layout.source_path(workspace_dir_))

    cpg_build_holder: list[CpgBuildRecord] = []
    attempts: list[JoernScriptAttempt] = []
    tools = build_joern_tools(
        workspace_dir=workspace_dir_,
        settings=settings,
        cpg_build_holder=cpg_build_holder,
        attempts=attempts,
    )
    graph = build_verifier_graph(
        llm=llm,
        tools=tools,
        max_iterations=settings.stage5_max_agent_iterations,
        repair_attempts=settings.stage5_repair_attempts,
    )

    messages = build_messages(candidate)
    if system_prompt is not None:
        messages[0] = messages[0].model_copy(update={"content": system_prompt})

    started_at = datetime.now(UTC)
    initial_state = {"messages": messages, "iterations": 0, "verdict": None}
    try:
        if on_step is None:
            final_state = await graph.ainvoke(initial_state)
        else:
            final_state = await _stream_with_callback(graph, initial_state, on_step)
    except (OSError, TimeoutError) as exc:
        raise VerifierModelUnavailableError(f"verification agent call failed: {exc}") from exc
    finished_at = datetime.now(UTC)

    transcript = messages_to_transcript(final_state.get("messages", []))

    # Workspace cleanup (when Settings.stage5_keep_workspace is False) happens
    # in driver.py, AFTER the report is persisted — not here, so a debug
    # caller inspecting verify_candidate()'s return value directly still has
    # the workspace on disk to look at.

    verdict = final_state.get("verdict")
    if verdict is None:
        # Should be unreachable: finalize_node always sets it or raises.
        verdict = VerificationVerdict.ERROR  # pragma: no cover - defensive

    return VerificationReport(
        global_id=candidate.global_id,
        bin_id=candidate.bin_id,
        model=f"{_model_label(llm)}",
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
    )


async def _stream_with_callback(graph, initial_state: dict, on_step: OnStep) -> dict:
    """Drive `graph` via `astream(..., stream_mode="values")` instead of a
    single `ainvoke`, calling `on_step` with each step's newly-appended
    transcript entries as they arrive.

    `stream_mode="values"` yields the FULL accumulated state after every
    node runs (not a diff) — the previous message count is tracked here so
    only the slice a given step actually added gets passed to `on_step`,
    never a growing prefix the caller would have to de-duplicate itself.
    Returns the final state, same shape `ainvoke` would have returned.
    """
    seen = 0
    state = initial_state
    async for state in graph.astream(initial_state, stream_mode="values"):
        step_messages = state.get("messages", [])
        new_messages = step_messages[seen:]
        if new_messages:
            on_step(messages_to_transcript(new_messages, start_turn=seen))
        seen = len(step_messages)
    return state


def _model_label(llm: object) -> str:
    """Best-effort `<provider>:<model>` label for the report — `BaseChatModel`
    subclasses don't share one uniform attribute name, so this degrades to
    the class name rather than raising if neither common attribute exists."""
    model_name = getattr(llm, "model", None) or getattr(llm, "model_name", None)
    return str(model_name) if model_name else type(llm).__name__


__all__ = ["verify_candidate"]
