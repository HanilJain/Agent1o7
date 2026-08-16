"""Stage 5 Component (Joern verifier)'s schema.

`VerifierVerdict` is the structured-output contract the verification agent's
finalize step is constrained against via `BaseChatModel.with_structured_output`
— same "the schema-level `Field(description=...)` IS the prompt the LLM
actually sees" convention as `common.findings.Finding` and
`common.taint.TaintPathReport` (see `common.findings`'s module docstring for
why prose-only enforcement was tried and abandoned).

Kept separate from `common/findings.py` and `common/taint.py` the same way
those two are kept separate from each other and from `common/schemas.py` —
a genuinely different concern (an executed, tool-backed verification
outcome, not a static candidate finding or a retrieved data-flow path).

Two kinds of model here, mirroring `common.findings`'s
`Finding`/`ChunkAnalysisRecord` split: `VerifierVerdict` is what the LLM
produces (sent through `with_structured_output`); `JoernScriptAttempt`,
`CpgBuildRecord`, `VerificationReport` and the run-level records below are
Python-only bookkeeping the orchestration code assembles around that verdict
— never themselves sent to an LLM.
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


class VerifierVerdict(BaseModel):
    """The verification agent's full structured output for one candidate.

    This is the Pydantic model passed to `with_structured_output(...)` at
    the graph's finalize step — framework-enforced schema compliance, not
    prompt-instruction-only enforcement (see this module's docstring).
    """

    verdict: VerificationVerdict
    confidence: str = Field(
        description=(
            "CONFIRMED, HIGH, MEDIUM, or LOW — same vocabulary as "
            "common.findings.Confidence, describing how well the Joern query "
            "evidence actually gathered supports this specific verdict."
        )
    )
    summary: str = Field(
        description="Concise prose explanation of the verdict and why the evidence supports it."
    )
    evidence: str = Field(
        description=(
            "The key Joern/CPGQL query output (verbatim or summarized) that backs the "
            "verdict. Never invented — must trace to an actual attempt's stdout."
        )
    )
    recommended_next_steps: list[str] = Field(
        default_factory=list,
        description=(
            "Concrete next steps for further verification (e.g. QEMU+GDB dynamic "
            "confirmation, or what additional CPG query would resolve remaining doubt)."
        ),
    )


class JoernScriptAttempt(BaseModel):
    """One `run_joern_script` tool call's outcome — bookkeeping, not sent to the LLM."""

    attempt_index: int = Field(description="0-based position of this attempt.")
    script: str = Field(description="The exact Scala/CPGQL script text that was executed.")
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    ok: bool = Field(description="True if the script ran without error (returncode == 0).")


class CpgBuildRecord(BaseModel):
    """The `build_cpg` tool call's outcome — bookkeeping, not sent to the LLM."""

    command: str = ""
    ok: bool = False
    duration_seconds: float = 0.0
    stderr: str = ""


class ToolCallRecord(BaseModel):
    """One tool call an `AIMessage` requested — bookkeeping, not sent to the
    LLM. Distinct from `JoernScriptAttempt`/`CpgBuildRecord` (which record a
    tool's OUTCOME): this records the LLM's own decision to call it, args
    and all, as part of `TranscriptEntry` — the full "what the agent said
    and did" record `JoernScriptAttempt` alone doesn't capture (it only
    covers `run_joern_script` calls, never `build_cpg` calls or the
    surrounding reasoning text)."""

    name: str
    args: dict = Field(default_factory=dict)
    id: str = ""


class TranscriptEntry(BaseModel):
    """One message in the verification agent's full turn-by-turn
    conversation — the literal "chat with tools" transcript: what the LLM
    said (`content`, its reasoning/commentary), which tool(s) it decided to
    call and with what arguments (`tool_calls`), and each tool's response
    (`role == "tool"` entries). Serialized from the LangGraph run's raw
    `BaseMessage` list by `agent.graph.messages_to_transcript` — see that
    function's docstring for the exact mapping.

    This is deliberately NOT sent to an LLM (it's the record OF an LLM
    conversation, not input to one) — kept in `common/verification.py`
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
    `VerifierVerdict` plus the tool-call transcript accumulated along the
    way — this model itself is never sent to an LLM (only `VerifierVerdict`
    is), matching `common.findings.AnalysisReport`/`ChunkAnalysisRecord`'s
    split between LLM-facing and bookkeeping-only models.
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
    """The full turn-by-turn agent conversation — every message the LLM
    produced (its reasoning, each tool call with arguments) and every tool
    response it read, in order. `attempts`/`cpg_build` above are the
    STRUCTURED outcome summary of the two tools specifically; this is the
    complete unabridged record, "what the agent said and did," independent
    of which tools exist. The system prompt (role="system", turn 0) is
    included for completeness even though it's static — see
    `agent.prompts.SYSTEM_PROMPT`."""
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
