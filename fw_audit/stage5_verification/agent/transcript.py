"""Transcript-entry builders for the generator/evaluator pipeline.

Replaces the old tool-calling graph's `messages_to_transcript` — there is no
LangChain message list to serialize any more, since neither the generator
nor the evaluator does real tool-calling (`agent.graph`'s nodes call
`llm.ainvoke(messages) -> AIMessage` directly, nothing more). Instead, every
`agent.graph` node builds its OWN new `TranscriptEntry` objects and returns
them under the `"transcript"` state key, which an `Annotated[list,
operator.add]` reducer appends to the running list — see `agent.graph.
VerifierState`.

Role mapping — chosen so `report_writer._render_transcript_section` and
`runner._print_transcript_entries` (which both branch on exactly the four
roles `"system"`/`"human"`/`"ai"`/`"tool"`) keep rendering a report that
looks like the old tool-calling agent's, with no changes to either renderer:

    generator system prompt (or --prompt-file override)  -> "system"
    rendered finding brief                                -> "human"
    CPG build outcome                                     -> "tool"  (tool_call_id="build_cpg")
    generator's script                                    -> "ai"    (synthesized tool call)
    Joern execution output                                -> "tool"  (tool_call_id matches above)
    evaluator's verdict                                   -> "ai"
    final conclusion                                      -> "ai"

The synthesized `ToolCallRecord` on the generator's "ai" entry (see
`common.verification.ToolCallRecord`'s docstring) is what makes
`report_writer.py` render `-> calls run_joern_script(script='...')` and
`runner.py` print the same live, matching the old agent's console output
even though no real tool call happens here.
"""

from __future__ import annotations

from fw_audit.common.verification import (
    CpgBuildRecord,
    EvaluatorVerdict,
    JoernScriptAttempt,
    ToolCallRecord,
    TranscriptEntry,
    VerificationVerdict,
)


def next_turn(state: dict) -> int:
    """The next turn number to use, given the transcript accumulated in
    `state` so far. Correct for a strictly sequential graph (this one has
    no parallel fan-out) — each node computes this once, right before
    building its own new entries."""
    return len(state.get("transcript", []))


def script_call_id(attempt_index: int) -> str:
    """Ties a generator "ai" entry's synthesized tool call to the matching
    execution "tool" entry — same `attempt_index` numbering
    `layout.script_path`/`JoernScriptAttempt.attempt_index` already use."""
    return f"attempt_{attempt_index:03d}"


def initial_transcript(*, system_prompt: str, brief: str) -> list[TranscriptEntry]:
    """Turns 0-1: the generator system prompt (verbatim, or the
    `--prompt-file` override) and the rendered finding brief — seeded once,
    up front, by `agent.verifier.verify_candidate` before the graph runs."""
    return [
        TranscriptEntry(turn=0, role="system", content=system_prompt),
        TranscriptEntry(turn=1, role="human", content=brief),
    ]


def cpg_build_entry(turn: int, record: CpgBuildRecord) -> TranscriptEntry:
    if record.ok:
        content = f"CPG built successfully in {record.duration_seconds:.1f}s."
    else:
        content = (
            f"CPG build FAILED after {record.duration_seconds:.1f}s. "
            f"stderr:\n{record.stderr[-2000:]}"
        )
    return TranscriptEntry(turn=turn, role="tool", content=content, tool_call_id="build_cpg")


def generator_entry(
    turn: int, *, script: str, attempt_index: int, iteration: int
) -> TranscriptEntry:
    label = f"Iteration {iteration}: generated a Joern script."
    return TranscriptEntry(
        turn=turn,
        role="ai",
        content=label,
        tool_calls=[
            ToolCallRecord(
                name="run_joern_script",
                args={"script": script},
                id=script_call_id(attempt_index),
            )
        ],
    )


def execution_entry(turn: int, attempt: JoernScriptAttempt) -> TranscriptEntry:
    if attempt.ok:
        content = attempt.stdout or "(script ran successfully but produced no stdout output)"
    else:
        content = (
            f"Script attempt {attempt.attempt_index} FAILED (returncode={attempt.returncode}). "
            f"stderr:\n{attempt.stderr[-2000:]}"
        )
    return TranscriptEntry(
        turn=turn,
        role="tool",
        content=content,
        tool_call_id=script_call_id(attempt.attempt_index),
    )


def evaluator_entry(turn: int, verdict: EvaluatorVerdict, *, raw: str = "") -> TranscriptEntry:
    content = f"Evaluator: {verdict.verdict.value} ({verdict.confidence}) — {verdict.reasoning}"
    if verdict.feedback_for_retry:
        content += f"\nFeedback for retry: {verdict.feedback_for_retry}"
    return TranscriptEntry(turn=turn, role="ai", content=content)


def conclusion_entry(turn: int, *, verdict: VerificationVerdict, summary: str) -> TranscriptEntry:
    return TranscriptEntry(
        turn=turn, role="ai", content=f"Final verdict: {verdict.value}. {summary}"
    )


__all__ = [
    "conclusion_entry",
    "cpg_build_entry",
    "evaluator_entry",
    "execution_entry",
    "generator_entry",
    "initial_transcript",
    "next_turn",
    "script_call_id",
]
