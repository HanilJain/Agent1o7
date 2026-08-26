"""Stage 5 Component (Joern verifier)'s schema.

`EvaluatorVerdict` is the per-round structured contract the evaluator LLM
returns as plain JSON text (parsed via `model_validate_json` after
`agent.cleaning` strips `<think>` blocks/markdown fences — NOT via
`BaseChatModel.with_structured_output`, which routes through Ollama's
`json_schema`/tool-calling paths that a local model like qwen3 handles
unreliably; see `Settings.stage3_structured_output_method`'s docstring for
the same class of failure already hit in Stage 3). Still, the same "the
schema-level `Field(description=...)` IS the prompt" convention as
`common.findings.Finding`/`common.taint.TaintPathReport` applies — these
descriptions are folded into `agent.prompts.EVALUATOR_SYSTEM_PROMPT`, not
enforced by the framework here.

Kept separate from `common/findings.py` and `common/taint.py` the same way
those two are kept separate from each other and from `common/schemas.py` —
a genuinely different concern (an executed, tool-backed verification
outcome, not a static candidate finding or a retrieved data-flow path).

Two kinds of model here, mirroring `common.findings`'s
`Finding`/`ChunkAnalysisRecord` split: `EvaluatorVerdict` is what the
evaluator LLM produces, once per generate/run round; `JoernScriptAttempt`,
`CpgBuildRecord`, `VerificationReport` and the run-level records below are
Python-only bookkeeping the orchestration code assembles around those
per-round verdicts — never themselves sent to an LLM.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class VerificationVerdict(str, Enum):
    """The agent's disposition for a candidate finding, after running Joern
    queries against its CPG. Fixed by the verifier system prompt — not
    something a downstream consumer should extend without updating that
    prompt too (see `stage5_verification.agent.prompts`)."""

    CONFIRMED = "CONFIRMED"
    """CPG evidence establishes the finding's claimed security condition."""
    REFUTED = "REFUTED"
    """CPG evidence contradicts the finding's claimed security condition."""
    INCONCLUSIVE = "INCONCLUSIVE"
    """Queries ran without error but neither proved nor disproved the claim
    within the allotted attempts."""
    ERROR = "ERROR"
    """The CPG could not be built, or every script attempt errored — no
    verification evidence was obtained at all."""


class EvaluationVerdict(str, Enum):
    """The evaluator agent's judgement of ONE generate -> run round. Fixed
    by `agent.prompts.EVALUATOR_SYSTEM_PROMPT` — not something a downstream
    consumer should extend without updating that prompt too."""

    PASS = "PASS"
    """The script ran and produced a real answer about the finding —
    including a clean FLOW_NOT_FOUND, which is a conclusive result, not a
    failure. Never loop just because the finding wasn't confirmed."""
    FAIL_RETRY = "FAIL_RETRY"
    """The script itself is broken (bad method name, CPGQL syntax error,
    forgotten `println`, timeout) — this run says nothing about the finding
    either way."""
    FAIL_STOP = "FAIL_STOP"
    """Never produced by the evaluator LLM directly (its prompt offers only
    PASS and FAIL_RETRY). Synthesized by `agent.graph`'s evaluate node in
    two cases: a FAIL_RETRY at `stage5_max_agent_iterations`, or an
    evaluator response that never parsed as `EvaluatorVerdict` JSON within
    `stage5_repair_attempts` retries."""


class EvaluatorVerdict(BaseModel):
    """The evaluator LLM's per-round output — parsed from a plain text
    response, not `with_structured_output` (see this module's docstring)."""

    verdict: EvaluationVerdict
    confidence: str = Field(
        default="LOW",
        description=(
            "HIGH, MEDIUM, or LOW — how confidently the script's output settles the question."
        ),
    )
    reasoning: str = Field(
        default="", description="2-4 sentences justifying the verdict."
    )
    feedback_for_retry: str = Field(
        default="",
        description=(
            "What must change in the script for a retry to succeed. Empty string "
            "when verdict is PASS."
        ),
    )


class JoernScriptAttempt(BaseModel):
    """One generate/run round's outcome — bookkeeping, not sent to the LLM."""

    attempt_index: int = Field(description="0-based position of this attempt.")
    script: str = Field(description="The exact Scala/CPGQL script text that was executed.")
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    ok: bool = Field(description="True if the script ran without error (returncode == 0).")
    iteration: int = 0
    """1-based generator round that produced this script. Equal to
    `attempt_index + 1` today; kept as its own field (rather than derived)
    so a future pre-flight/lint attempt can't desync the two."""
    result_marker: str | None = None
    """The FLOW_FOUND / FLOW_NOT_FOUND / QUERY_ERROR value parsed from the
    script's `RESULT:` line (see `agent.graph.extract_result_marker`), or
    `None` if the script never printed one."""
    evaluator_verdict: str | None = None
    """This attempt's `EvaluationVerdict` value, once the evaluator has
    judged it. `None` until then."""
    evaluator_confidence: str = ""
    evaluator_reasoning: str = ""
    evaluator_feedback: str = ""


class CpgBuildRecord(BaseModel):
    """The `build_cpg` tool call's outcome — bookkeeping, not sent to the LLM."""

    command: str = ""
    ok: bool = False
    duration_seconds: float = 0.0
    stderr: str = ""


class ToolCallRecord(BaseModel):
    """One "tool call" a transcript entry records — bookkeeping, not sent
    to the LLM. Distinct from `JoernScriptAttempt`/`CpgBuildRecord` (which
    record a tool's OUTCOME): this records the decision to invoke it, args
    and all, as part of `TranscriptEntry`. Since the generate/run/evaluate
    pipeline (`agent.graph`) has no real LLM tool-calling — the generator
    and evaluator are both plain text in/text out — these are SYNTHESIZED
    by `agent.transcript.generator_entry` around each generated script,
    purely so the Markdown report and `--live` console output keep showing
    "the agent decided to run this script" the same way they did when the
    graph used genuine LangChain tool calls."""

    name: str
    args: dict = Field(default_factory=dict)
    id: str = ""


class TranscriptEntry(BaseModel):
    """One entry in the verification pipeline's full turn-by-turn record —
    the generator's script, the Joern execution's output, and the
    evaluator's judgement, each round, in order. Emitted directly by each
    `agent.graph` node via `agent.transcript`'s builder functions (see that
    module's docstring for the exact role mapping) — there is no LangChain
    message list to serialize, since neither the generator nor the
    evaluator does real tool-calling.

    This is deliberately NOT sent to an LLM (it's the record OF the
    pipeline's run, not input to one) — kept in `common/verification.py`
    anyway, alongside `VerificationReport` which embeds it, rather than in
    `stage5_verification` itself, following this module's own "the
    structured-output/report schema lives in common/" convention.
    """

    turn: int = Field(description="0-based position in the raw message sequence.")
    role: str = Field(description='One of: "system", "human", "ai", "tool".')
    content: str = ""
    """The message's own text — for role="ai", this is the LLM's reasoning/
    commentary alongside (or instead of) any tool call; for role="tool",
    this is that tool's returned output (same string the LLM itself read)."""
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    """Set only on role="ai" entries that requested one or more tool calls."""
    tool_call_id: str | None = None
    """Set only on role="tool" entries — ties this response back to the
    `ToolCallRecord.id` on the `ai` entry that requested it."""


class VerificationReport(BaseModel):
    """The on-disk artifact: `stage5/verifications/<gid>.json`.

    Assembled by `agent.verifier.verify_candidate` from the graph's final
    `conclude` node output plus the transcript accumulated along the way —
    this model itself is never sent to an LLM (only `EvaluatorVerdict` is,
    once per round), matching `common.findings.AnalysisReport`/
    `ChunkAnalysisRecord`'s split between LLM-facing and bookkeeping-only
    models.
    """

    schema_version: int = 1
    global_id: str
    """`"<chunk_id>::<finding_id>"` — ties back to the Stage 3 finding this
    verifies, same format as `stage4_rag.sink_index.SinkCandidate.global_id`."""
    bin_id: str
    tool: str = "joern"
    """Which tool produced this report. Always "joern" today; reserved for
    "qemu_gdb" once that tool exists (see stage5_verification's README)."""
    model: str = ""
    """The resolved `<provider>:<model>` actually used, for reproducibility."""
    cpg_build: CpgBuildRecord = Field(default_factory=CpgBuildRecord)
    attempts: list[JoernScriptAttempt] = Field(default_factory=list)
    transcript: list[TranscriptEntry] = Field(default_factory=list)
    """The full turn-by-turn pipeline record — every generated script, its
    Joern output, and the evaluator's judgement, in order. `attempts`/
    `cpg_build` above are the STRUCTURED outcome summary specifically; this
    is the complete unabridged record, "what happened, in order,"
    independent of the underlying schema. The system prompt (role="system",
    turn 0) is included for completeness even though it's static — see
    `agent.prompts.GENERATOR_SYSTEM_PROMPT`."""
    verdict: VerificationVerdict
    confidence: str = ""
    summary: str = ""
    evidence: str = ""
    recommended_next_steps: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime | None = None


# --------------------------------------------------------------------- #
# Run-level aggregation (not sent to the LLM — Stage 5's own bookkeeping,
# analogous to common.findings.AnalysisRunSummary / common.taint.Stage4RunSummary).
# --------------------------------------------------------------------- #


class CandidateRunRecord(BaseModel):
    """One candidate's outcome as it passed through the verification driver."""

    global_id: str
    chunk_id: str
    bin_id: str
    status: str = Field(
        description="One of: verified (a VerificationReport was produced and persisted), "
        "failed (every attempt errored past stage5_queue_max_attempts)."
    )
    attempts: int = 0
    verdict: str | None = None
    error: str | None = None


class VerificationRunSummary(BaseModel):
    """Stage 5's machine-readable hand-off (`stage5/stage5_summary.json`),
    written by `stage5_verification.driver.run_queue()` itself — same
    "written by the orchestrator function, not only the CLI" discipline as
    `AnalysisRunSummary`/`Stage4RunSummary`."""

    schema_version: int = 1
    run_id: str | None = None
    status: str = Field(
        description="completed | no_targets | stage5_input_unavailable | "
        "sandbox_unavailable | verifier_unavailable"
    )
    db_subfolder: str
    model: str = ""
    candidates: list[CandidateRunRecord] = Field(default_factory=list)
    total_candidates: int = 0
    total_verified: int = 0
    total_failed: int = 0
    verdicts_by_type: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime | None = None
