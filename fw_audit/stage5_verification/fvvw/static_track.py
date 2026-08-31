"""The fork-join's static track (FVVW v3 §6 nodes 4-8: `build_cpg` /
`joern_generate` / `run_joern` / `joern_evaluate`) — a thin adapter around
the EXISTING, UNMODIFIED `agent.graph.build_verifier_graph`.

Per the confirmed reuse direction: this module does NOT refactor the
generate/run/evaluate loop into FVVW's "script-first rule engine" ideal
(template-first `joern_generate`, deterministic `joern_evaluate`) — it
keeps the existing two-LLM (generator + evaluator) loop verbatim and only
(a) layers `StaticPlan`/`mem.target` detail onto the brief text the
generator/evaluator already consume, and (b) maps the graph's terminal
`VerificationReport` into a `TrackResult` the fork-join's `joint_evaluate`
understands. `agent.graph`, `agent.prompts`, `agent.cleaning`,
`agent.transcript`, and `tools.joern_tool` are all imported here but never
edited — see this package's own `__init__.py` docstring for the "hard
reuse constraints" this commits to.
"""

from __future__ import annotations

from pathlib import Path

from langchain_core.language_models import BaseChatModel

from fw_audit.common.verification import (
    CpgBuildRecord,
    EvaluationVerdict,
    JoernScriptAttempt,
    StaticPlan,
    TrackResult,
    VerificationVerdict,
)
from fw_audit.config.settings import Settings
from fw_audit.executors.base import Executor
from fw_audit.observability import run_config
from fw_audit.stage5_verification.agent import transcript as tx
from fw_audit.stage5_verification.agent.graph import (
    build_verifier_graph,
    extract_result_marker,
    final_status,
)
from fw_audit.stage5_verification.agent.prompts import render_finding_brief
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.cmdlog import CommandLog, JsonlRecordingList
from fw_audit.stage5_verification.tools.joern_tool import run_joern_script_async


def render_static_brief(candidate: VerificationCandidate, plan: StaticPlan) -> str:
    """Layer `StaticPlan` detail on top of the EXISTING
    `agent.prompts.render_finding_brief`'s output — the generator/evaluator
    prompts (`agent.prompts.GENERATOR_SYSTEM_PROMPT`/
    `EVALUATOR_SYSTEM_PROMPT`) are untouched, so this brief still has to
    read as plain text those prompts already expect; it just adds a
    strategy-plan section the un-enriched brief didn't have, giving the
    existing generator a head start (expected intermediate calls, sanitizer
    patterns to watch for, the decisive observable this specific run needs
    settled) without changing what kind of input it's used to seeing.
    """
    base = render_finding_brief(candidate)
    plan_lines = [
        "",
        "## Strategy plan (from strategy_agent, this run's fork-join context)",
        f"target_function: {plan.target_function}",
        f"expected_intermediate_calls: {', '.join(plan.expected_intermediate_calls) or '(none)'}",
        f"sanitizer_patterns_to_check: {', '.join(plan.sanitizer_patterns) or '(none)'}",
        f"decisive_observable: {plan.decisive_observable}",
    ]
    return base + "\n".join(plan_lines)


def _cpg_build_evidence(record: CpgBuildRecord) -> dict:
    return {
        "command": record.command,
        "ok": record.ok,
        "duration_seconds": record.duration_seconds,
        "stderr": record.stderr,
    }


def _attempt_evidence(attempt: JoernScriptAttempt) -> dict:
    return {
        "attempt_index": attempt.attempt_index,
        "script": attempt.script,
        "stdout": attempt.stdout,
        "stderr": attempt.stderr,
        "returncode": attempt.returncode,
        "ok": attempt.ok,
        "result_marker": attempt.result_marker,
        "evaluator_verdict": attempt.evaluator_verdict,
        "evaluator_confidence": attempt.evaluator_confidence,
    }


def _cpg_build_log_fields(record: CpgBuildRecord) -> dict:
    """`JsonlRecordingList`'s `to_fields` for `cpg_build_holder` — the
    `joern-parse` command `CpgBuildRecord.command` already carries
    verbatim (`tools.joern_tool.build_cpg_async`), so this is a pure
    reshaping, no new data."""
    return {
        "command": record.command,
        "ok": record.ok,
        "stderr": record.stderr,
        "notes": {"duration_seconds": record.duration_seconds},
    }


def _joern_script_log_fields(attempt: JoernScriptAttempt) -> dict:
    """`JsonlRecordingList`'s `to_fields` for `attempts` — logs the exact
    Scala/CPGQL script text as `payload` (previously recoverable only from
    the persisted `VerificationReport`/`FVVWReport` JSON after the whole
    run finished) plus the full stdout/stderr, so a still-running or
    crashed candidate stays diagnosable mid-flight from the JSONL alone."""
    return {
        "command": f"joern --script query_{attempt.attempt_index:03d}.sc",
        "payload": attempt.script,
        "exit_code": attempt.returncode,
        "ok": attempt.ok,
        "stdout": attempt.stdout,
        "stderr": attempt.stderr,
        "notes": {
            "attempt_index": attempt.attempt_index,
            "result_marker": attempt.result_marker,
            "evaluator_verdict": attempt.evaluator_verdict,
            "evaluator_confidence": attempt.evaluator_confidence,
        },
    }


async def run_static_track(
    candidate: VerificationCandidate,
    plan: StaticPlan,
    *,
    generator_llm: BaseChatModel,
    evaluator_llm: BaseChatModel,
    workspace_dir: Path,
    executor: Executor,
    settings: Settings,
    system_prompt: str | None = None,
    command_log: CommandLog | None = None,
) -> TrackResult:
    """Run the EXISTING static verifier graph (`build_verifier_graph`,
    completely unmodified) against a strategy-enriched brief, and map its
    terminal state into a `TrackResult` — the shape `joint_evaluate`
    consumes.

    Mirrors `agent.verifier.verify_candidate`'s own invocation shape almost
    exactly (same `cpg_build_holder`/`attempts` shared-list wiring, same
    `graph.ainvoke(initial_state, config=...)` call) rather than importing
    that function directly — `verify_candidate` also does workspace
    copy-in, LLM-role resolution, and `VerificationReport` assembly for the
    STANDALONE `fw-verify run` path (`--joern-only`), none of which belong
    here: this function assumes the workspace/executor/roles are already
    resolved by its caller (`fvvw.graph`'s static-track subgraph node),
    which needs `TargetMeta`/`StrategyPlan` from `mem` that
    `verify_candidate` has no concept of.

    `command_log`, when given, wraps `cpg_build_holder`/`attempts` in
    `JsonlRecordingList` — `build_verifier_graph`'s nodes are the ONLY
    thing that ever mutates those two lists (`.clear()`/`.append()`/
    `attempts[-1] = ...`), so this gives full per-command static-track
    logging with ZERO edits to `agent/graph.py` (see `cmdlog`'s module
    docstring). `None` (the default) behaves exactly as before — a plain
    list, no logging — so every existing caller is unaffected.
    """
    brief = render_static_brief(candidate, plan)

    cpg_build_holder: list[CpgBuildRecord]
    attempts: list[JoernScriptAttempt]
    if command_log is not None:
        cpg_build_holder = JsonlRecordingList(
            command_log, node="build_cpg", kind="joern_parse", to_fields=_cpg_build_log_fields
        )
        attempts = JsonlRecordingList(
            command_log, node="run_script", kind="joern_script", to_fields=_joern_script_log_fields
        )
    else:
        cpg_build_holder = []
        attempts = []
    graph = build_verifier_graph(
        llm=generator_llm,
        evaluator_llm=evaluator_llm,
        workspace_dir=workspace_dir,
        executor=executor,
        settings=settings,
        max_iterations=settings.stage5_max_agent_iterations,
        cpg_build_holder=cpg_build_holder,
        attempts=attempts,
    )

    initial_state = {
        "brief": brief,
        "system_prompt": system_prompt,
        "max_iterations": settings.stage5_max_agent_iterations,
        "transcript": tx.initial_transcript(
            system_prompt=system_prompt or "", brief=brief
        ),
    }
    config = run_config(
        run_name="stage5.fvvw.static_track",
        metadata={"global_id": candidate.global_id, "bin_id": candidate.bin_id},
        settings=settings,
    ) or {}
    # LangGraph's default recursion_limit (25) caps this graph's
    # generate_script -> run_script -> evaluate loop (3 steps/iteration,
    # plus build_cpg + conclude) at max_iterations <= ~7 before the run
    # aborts mid-loop with a GraphRecursionError. HITL's "retry with more
    # iterations" action (fvvw.hitl) can push settings.stage5_max_agent_
    # iterations well above that, so this must be set explicitly rather than
    # left at the library default — see the FVVW HITL plan's "Recursion-limit
    # trap" note.
    config["recursion_limit"] = 3 * settings.stage5_max_agent_iterations + 8
    final_state = await graph.ainvoke(initial_state, config=config)

    verdict = final_state.get("verdict", VerificationVerdict.ERROR)
    evidence = {
        "cpg_build": _cpg_build_evidence(cpg_build_holder[0])
        if cpg_build_holder
        else _cpg_build_evidence(CpgBuildRecord()),
        "attempts": [_attempt_evidence(a) for a in attempts],
        # Previously discarded entirely in the fork-join path — the
        # `--joern-only` path keeps this via `VerificationReport.transcript`
        # (agent.verifier.verify_candidate), so the fork-join now matches.
        "transcript": [entry.model_dump() for entry in final_state.get("transcript", [])],
        "summary": final_state.get("verdict_summary", ""),
        "confidence": final_state.get("verdict_confidence", ""),
        "evidence_text": final_state.get("verdict_evidence", ""),
        "recommended_next_steps": final_state.get("verdict_next_steps", []),
    }
    if verdict in (VerificationVerdict.ERROR, VerificationVerdict.INCONCLUSIVE) and final_state.get(
        "iteration", 0
    ) >= settings.stage5_max_agent_iterations:
        # HITL's trigger condition (fvvw.hitl) — the static track's own
        # budget-exhaustion path (agent.graph's evaluate node downgrades a
        # FAIL_RETRY to FAIL_STOP at stage5_max_agent_iterations, which
        # conclude maps to ERROR) is tagged here the same way the dynamic
        # track tags its own exhaustion, so run_fvvw's post-barrier hook can
        # check `evidence.get("budget_exhausted")` uniformly across both
        # tracks without special-casing which one it's looking at.
        evidence["budget_exhausted"] = True

    # The static track has no A/B hypothesis-switch of its own (that logic
    # applies primarily to the dynamic track) — CONFIRMED implies A,
    # REFUTED implies B, matching joern_evaluate's existing
    # confirm/refute/inconclusive taxonomy, per the design doc's own
    # closing note on this.
    if verdict == VerificationVerdict.CONFIRMED:
        proved_hypothesis = "A"
    elif verdict == VerificationVerdict.REFUTED:
        proved_hypothesis = "B"
    else:
        proved_hypothesis = "none"

    return TrackResult(
        verdict=verdict,
        proved_hypothesis=proved_hypothesis,
        evidence=evidence,
        iters_used=final_state.get("iteration", 0),
    )


async def run_injected_static_script(
    candidate: VerificationCandidate,
    script: str,
    *,
    workspace_dir: Path,
    executor: Executor,
    settings: Settings,
    command_log: CommandLog | None = None,
) -> TrackResult:
    """HITL's "inject" action for the static track — run an OPERATOR-supplied
    Joern script verbatim against the already-built CPG in `workspace_dir`,
    with NO LLM generate/evaluate loop and NO edit to `agent/graph.py`. The
    verdict is derived the exact same mechanical way `agent.graph.
    conclude_node` derives it: parse the script's own `RESULT:` marker line
    (`extract_result_marker`) and treat a present marker as an implicit PASS
    (`final_status(EvaluationVerdict.PASS, marker)`) — a missing marker
    (script produced no RESULT: line, or errored) is INCONCLUSIVE rather
    than ERROR, since a raw script run isn't itself evidence the pipeline
    malfunctioned, only that the operator's script didn't conclude cleanly.

    Requires `workspace_dir` to already contain `cpg.bin` — i.e. the static
    track must have run at least once for this candidate first (this is a
    RE-run/inject action, not a way to bootstrap a CPG from nothing).
    """
    # A high, fixed index (rather than 0) so this never overwrites an
    # earlier real attempt's query_NNN.sc left in the same workspace_dir by
    # the generate/run/evaluate loop that ran before HITL kicked in.
    attempt = await run_joern_script_async(
        script,
        attempt_index=999,
        workspace_dir=workspace_dir,
        executor=executor,
        settings=settings,
    )
    if command_log is not None:
        command_log.record(
            node="run_script",
            kind="joern_script_injected",
            command="joern --script query_999.sc",
            payload=script,
            exit_code=attempt.returncode,
            ok=attempt.ok,
            stdout=attempt.stdout,
            stderr=attempt.stderr,
            notes={"injected": True},
        )

    marker = extract_result_marker(attempt.stdout, attempt.stderr)
    evaluation_verdict = EvaluationVerdict.PASS if attempt.ok else EvaluationVerdict.FAIL_STOP
    verdict = final_status(evaluation_verdict, marker)

    if verdict == VerificationVerdict.CONFIRMED:
        proved_hypothesis = "A"
    elif verdict == VerificationVerdict.REFUTED:
        proved_hypothesis = "B"
    else:
        proved_hypothesis = "none"

    return TrackResult(
        verdict=verdict,
        proved_hypothesis=proved_hypothesis,
        evidence={
            "attempts": [_attempt_evidence(attempt)],
            "injected": True,
            "result_marker": marker,
        },
        iters_used=0,
    )


__all__ = ["render_static_brief", "run_injected_static_script", "run_static_track"]
