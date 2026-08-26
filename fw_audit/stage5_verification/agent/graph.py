"""LangGraph wiring for the Stage 5 verification pipeline — a deterministic
generate -> execute -> evaluate loop with two independently-configurable
LLM roles and NO tool-calling, replacing the previous
tool-calling/`with_structured_output` agent (see git history for that
version). The switch exists specifically to run reliably on a local model
(qwen3:32b and similar): both LLM calls here are plain text in, text out —
`llm.ainvoke(messages) -> AIMessage`, nothing more — the one thing local
models handle best.

Shape::

    build_cpg
      ├─ cpg failed  -> conclude                     (short-circuit; see below)
      └─ cpg ok      -> generate_script -> run_script -> evaluate
                              ▲                              │
                              └──────── FAIL_RETRY ───────────┤
                                                    └─ PASS | FAIL_STOP -> conclude -> END

`build_cpg -> conclude` is a deliberate divergence from the ported
`joern_verification_pipeline`, which raises `RuntimeError` on a CPG build
failure. Raising here would break `verify_candidate`'s "always returns a
VerificationReport" contract and would burn `stage5_queue_max_attempts`
re-runs (`driver.py`) on a source file that will never parse — short-
circuiting to `conclude` yields a proper `ERROR` report instead, carrying
the CPG build's stderr, persisted and rendered like any other report.

The iteration cap is enforced INSIDE `evaluate` (matching the ported
pipeline): a `FAIL_RETRY` verdict at `max_iterations` is downgraded to
`FAIL_STOP`, so `conclude` always sees a decisive verdict rather than the
graph looping forever or `route_after_evaluation` needing its own
cap-awareness.

Unlike the old tool-calling graph, this one is NOT cached and is NOT
built once per process either — `build_verifier_graph()` is called once
per `verify_candidate()` call, since `workspace_dir`/`executor`/the two
shared result lists are all per-candidate.
"""

from __future__ import annotations

import operator
import re
from pathlib import Path
from typing import Annotated, Literal, TypedDict

from langchain_core.language_models import BaseChatModel
from pydantic import ValidationError

from fw_audit.common.verification import (
    CpgBuildRecord,
    EvaluationVerdict,
    EvaluatorVerdict,
    JoernScriptAttempt,
    TranscriptEntry,
    VerificationVerdict,
)
from fw_audit.config.settings import Settings
from fw_audit.executors.base import Executor
from fw_audit.stage5_verification.agent import transcript as tx
from fw_audit.stage5_verification.agent.cleaning import clean_json_payload, clean_script
from fw_audit.stage5_verification.agent.prompts import (
    build_evaluator_messages,
    build_generator_messages,
)
from fw_audit.stage5_verification.tools.joern_tool import build_cpg_async, run_joern_script_async

_RESULT_RE = re.compile(
    r"^[ \t]*RESULT:[ \t]*(FLOW_FOUND|FLOW_NOT_FOUND|QUERY_ERROR)\b", re.MULTILINE
)


class VerifierState(TypedDict, total=False):
    # ---- static inputs, seeded by verify_candidate ----
    brief: str
    system_prompt: str
    max_iterations: int

    # ---- CPG build ----
    cpg_ok: bool
    cpg_stderr: str

    # ---- generate / retry loop ----
    iteration: int
    current_script: str
    generator_feedback: str

    # ---- execution ----
    execution_stdout: str
    execution_stderr: str
    execution_returncode: int | None
    execution_ok: bool
    result_marker: str | None

    # ---- evaluation ----
    evaluation_verdict: EvaluationVerdict
    evaluation_reasoning: str
    evaluation_confidence: str

    # ---- conclusion (names UNCHANGED from the old tool-calling graph, so
    # agent.verifier's report-assembly block needed no changes) ----
    verdict: VerificationVerdict | None
    verdict_confidence: str
    verdict_summary: str
    verdict_evidence: str
    verdict_next_steps: list[str]

    # ---- transcript (each node returns only its OWN new entries; the
    # `operator.add` reducer below appends them to the running list rather
    # than overwriting it each step — same mechanism LangGraph's own
    # `add_messages` reducer used in the old tool-calling graph) ----
    transcript: Annotated[list[TranscriptEntry], operator.add]


def extract_result_marker(stdout: str, stderr: str = "") -> str | None:
    """Parse the `RESULT: FLOW_FOUND|FLOW_NOT_FOUND|QUERY_ERROR` marker line
    a generated script is instructed to print (see
    `agent.prompts.GENERATOR_SYSTEM_PROMPT`). Line-anchored (not a bare
    substring `in` check) so a script that merely quotes the marker text
    inside a comment or an intermediate diagnostic `println` can't mint a
    false verdict. Checked in stdout first, then stderr — Joern's JVM
    occasionally routes script output to stderr instead."""
    match = _RESULT_RE.search(stdout)
    if match:
        return match.group(1)
    match = _RESULT_RE.search(stderr)
    if match:
        return match.group(1)
    return None


def final_status(
    evaluation_verdict: EvaluationVerdict, marker: str | None
) -> VerificationVerdict:
    """Mechanical derivation of the final `VerificationVerdict` — no LLM
    call. Mirrors the ported pipeline's `conclude` node exactly."""
    if evaluation_verdict == EvaluationVerdict.PASS:
        if marker == "FLOW_FOUND":
            return VerificationVerdict.CONFIRMED
        if marker == "FLOW_NOT_FOUND":
            return VerificationVerdict.REFUTED
        return VerificationVerdict.INCONCLUSIVE
    return VerificationVerdict.ERROR


def parse_evaluator_response(raw: object) -> EvaluatorVerdict | None:
    """Clean + parse one evaluator LLM response into an `EvaluatorVerdict`.
    Returns `None` (never raises) if no valid JSON object could be extracted
    or it doesn't validate against the schema — the caller treats that as
    an unparseable response, same as the ported pipeline's
    `json.JSONDecodeError` handling."""
    payload = clean_json_payload(raw)
    if payload is None:
        return None
    try:
        return EvaluatorVerdict.model_validate_json(payload)
    except (ValidationError, ValueError):
        return None


def route_after_build_cpg(state: VerifierState) -> Literal["generate", "conclude"]:
    return "generate" if state.get("cpg_ok") else "conclude"


def route_after_evaluation(state: VerifierState) -> Literal["retry", "done"]:
    return "retry" if state["evaluation_verdict"] == EvaluationVerdict.FAIL_RETRY else "done"


_NEXT_STEPS_BY_STATUS: dict[VerificationVerdict, list[str]] = {
    VerificationVerdict.CONFIRMED: [
        "Confirm dynamically (e.g. QEMU+GDB) before treating this as fully verified.",
    ],
    VerificationVerdict.REFUTED: [],
    VerificationVerdict.INCONCLUSIVE: [
        "The script ran but never printed a RESULT: marker, or the query genuinely "
        "couldn't settle the question — try a more targeted CPGQL query by hand via "
        "`fw-verify debug script`.",
    ],
    VerificationVerdict.ERROR: [
        "Inspect the kept workspace (--keep-workspace) and re-run a hand-written "
        "query with `fw-verify debug script` to diagnose the failure directly.",
    ],
}


def build_verifier_graph(
    *,
    llm: BaseChatModel,
    evaluator_llm: BaseChatModel,
    workspace_dir: Path,
    executor: Executor,
    settings: Settings,
    max_iterations: int,
    cpg_build_holder: list[CpgBuildRecord],
    attempts: list[JoernScriptAttempt],
):
    """Construct (compiled) one candidate's verifier graph.

    `llm` is the generator, `evaluator_llm` the evaluator — they may be the
    same object (both roles resolve to the same model unless a role-specific
    override is set, see `config.llm_config`). Neither is bound to tools or
    wrapped in `with_structured_output`; both are called via plain
    `.ainvoke(messages)`.
    """
    from langgraph.graph import END, StateGraph

    async def build_cpg_node(state: VerifierState) -> dict:
        record = await build_cpg_async(
            workspace_dir=workspace_dir, executor=executor, settings=settings
        )
        cpg_build_holder.clear()
        cpg_build_holder.append(record)
        turn = tx.next_turn(state)
        return {
            "cpg_ok": record.ok,
            "cpg_stderr": record.stderr,
            "transcript": [tx.cpg_build_entry(turn, record)],
        }

    async def generate_script_node(state: VerifierState) -> dict:
        iteration = state.get("iteration", 0) + 1
        last_attempt = attempts[-1] if attempts else None
        messages = build_generator_messages(
            brief=state["brief"],
            system_prompt=state.get("system_prompt"),
            feedback=state.get("generator_feedback", ""),
            previous_script=(last_attempt.script if last_attempt else ""),
            previous_stdout=(last_attempt.stdout if last_attempt else ""),
            previous_stderr=(last_attempt.stderr if last_attempt else ""),
        )
        response = await llm.ainvoke(messages)
        script = clean_script(response.content)
        attempt_index = len(attempts)
        turn = tx.next_turn(state)
        return {
            "current_script": script,
            "iteration": iteration,
            "transcript": [
                tx.generator_entry(
                    turn, script=script, attempt_index=attempt_index, iteration=iteration
                )
            ],
        }

    async def run_script_node(state: VerifierState) -> dict:
        attempt_index = len(attempts)
        attempt = await run_joern_script_async(
            state["current_script"],
            attempt_index=attempt_index,
            workspace_dir=workspace_dir,
            executor=executor,
            settings=settings,
        )
        marker = extract_result_marker(attempt.stdout, attempt.stderr)
        attempt = attempt.model_copy(
            update={"iteration": state.get("iteration", 1), "result_marker": marker}
        )
        attempts.append(attempt)
        turn = tx.next_turn(state)
        return {
            "execution_stdout": attempt.stdout,
            "execution_stderr": attempt.stderr,
            "execution_returncode": attempt.returncode,
            "execution_ok": attempt.ok,
            "result_marker": marker,
            "transcript": [tx.execution_entry(turn, attempt)],
        }

    async def evaluate_node(state: VerifierState) -> dict:
        messages = build_evaluator_messages(
            brief=state["brief"],
            script=state["current_script"],
            stdout=state["execution_stdout"],
            stderr=state["execution_stderr"],
            returncode=state.get("execution_returncode"),
        )
        attempts_allowed = settings.stage5_repair_attempts + 1
        verdict: EvaluatorVerdict | None = None
        last_raw = ""
        for attempt_num in range(attempts_allowed):
            response = await evaluator_llm.ainvoke(messages)
            last_raw = str(getattr(response, "content", response))
            verdict = parse_evaluator_response(response.content)
            if verdict is not None:
                break
            if attempt_num < attempts_allowed - 1:
                from langchain_core.messages import HumanMessage

                messages = [
                    *messages,
                    HumanMessage(
                        content=(
                            "Your previous response did not parse as the required JSON "
                            "object. Return ONLY the JSON object this time, no markdown "
                            "fences, no reasoning outside it."
                        )
                    ),
                ]

        if verdict is None:
            verdict = EvaluatorVerdict(
                verdict=EvaluationVerdict.FAIL_STOP,
                confidence="LOW",
                reasoning=(
                    "Evaluator returned non-JSON output, treating as unrecoverable: "
                    f"{last_raw[:500]}"
                ),
                feedback_for_retry="",
            )

        iteration = state.get("iteration", 1)
        max_iter = state.get("max_iterations", max_iterations)
        if verdict.verdict == EvaluationVerdict.FAIL_RETRY and iteration >= max_iter:
            verdict = verdict.model_copy(
                update={
                    "verdict": EvaluationVerdict.FAIL_STOP,
                    "reasoning": (
                        f"{verdict.reasoning} [stopped: reached max_iterations={max_iter}]"
                    ),
                }
            )

        if attempts:
            attempts[-1] = attempts[-1].model_copy(
                update={
                    "evaluator_verdict": verdict.verdict.value,
                    "evaluator_confidence": verdict.confidence,
                    "evaluator_reasoning": verdict.reasoning,
                    "evaluator_feedback": verdict.feedback_for_retry,
                }
            )

        turn = tx.next_turn(state)
        return {
            "evaluation_verdict": verdict.verdict,
            "evaluation_reasoning": verdict.reasoning,
            "evaluation_confidence": verdict.confidence,
            "generator_feedback": verdict.feedback_for_retry,
            "transcript": [tx.evaluator_entry(turn, verdict)],
        }

    async def conclude_node(state: VerifierState) -> dict:
        if not state.get("cpg_ok", False):
            status = VerificationVerdict.ERROR
            cpg_stderr = state.get("cpg_stderr", "")
            summary = f"CPG build failed — no verification evidence obtained. {cpg_stderr[-2000:]}"
            confidence = "LOW"
            evidence = cpg_stderr
        else:
            status = final_status(state["evaluation_verdict"], state.get("result_marker"))
            summary = state.get("evaluation_reasoning", "")
            confidence = state.get("evaluation_confidence", "LOW")
            evidence = (state.get("execution_stdout") or state.get("execution_stderr") or "")[
                -4000:
            ]

        turn = tx.next_turn(state)
        return {
            "verdict": status,
            "verdict_confidence": confidence,
            "verdict_summary": summary,
            "verdict_evidence": evidence,
            "verdict_next_steps": _NEXT_STEPS_BY_STATUS.get(status, []),
            "transcript": [tx.conclusion_entry(turn, verdict=status, summary=summary)],
        }

    graph = StateGraph(VerifierState)
    graph.add_node("build_cpg", build_cpg_node)
    graph.add_node("generate_script", generate_script_node)
    graph.add_node("run_script", run_script_node)
    graph.add_node("evaluate", evaluate_node)
    graph.add_node("conclude", conclude_node)

    graph.set_entry_point("build_cpg")
    graph.add_conditional_edges(
        "build_cpg", route_after_build_cpg, {"generate": "generate_script", "conclude": "conclude"}
    )
    graph.add_edge("generate_script", "run_script")
    graph.add_edge("run_script", "evaluate")
    graph.add_conditional_edges(
        "evaluate", route_after_evaluation, {"retry": "generate_script", "done": "conclude"}
    )
    graph.add_edge("conclude", END)

    return graph.compile()


__all__ = [
    "VerifierState",
    "build_verifier_graph",
    "extract_result_marker",
    "final_status",
    "parse_evaluator_response",
    "route_after_build_cpg",
    "route_after_evaluation",
]
