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
    trace_url: str | None = None
    """Best-effort LangSmith URL for this run's live trace — set only when
    tracing was active for the call that produced this report (see
    `fw_audit.observability.current_trace_url`). `None` by default so
    existing persisted reports (written before this field existed) still
    validate unchanged; this is a cross-link ALONGSIDE `transcript` above,
    not a replacement for it — `transcript` remains the offline artifact of
    record and needs no network/LangSmith retention to read."""


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


# --------------------------------------------------------------------- #
# FVVW v3 — fork-join schema (Stage 5 Phase 1). Everything below is
# ADDITIVE: `VerificationReport`/`VerificationVerdict`/`EvaluatorVerdict`
# above are the existing Joern static-track contract, embedded unchanged
# as the evidence behind `TrackResult.evidence` for the static track. See
# the FVVW v3 implementation plan's "Architecture: FVVW nodes -> existing
# code" table for the full node-to-schema mapping.
# --------------------------------------------------------------------- #


class TargetMeta(BaseModel):
    """`mem.target.*` — written once by `characterize_target`, read by the
    strategy agent and both tracks. Mostly seeded from Stage 2's
    `common.schemas.DecompiledBinary`/`ELFInfo` (already computed, no need
    to re-derive); the two fields `ELFInfo` does NOT carry
    (`is_pie`/`dispatch_resolvable`) are the ones `characterize_target`
    actually has to compute itself, via `readelf`/binary inspection in the
    verification sandbox — see that tool's own module docstring."""

    arch: str = Field(description="e.g. arm, aarch64, mips, mipsel — from ELFInfo.arch.")
    endianness: str = Field(description='"little" or "big", from ELFInfo.is_little_endian.')
    is_64bit: bool | None = None
    pie: bool | None = Field(
        default=None,
        description=(
            "Position-independent (ET_DYN + no PT_INTERP-implied fixed base) — NOT "
            "captured by common.schemas.ELFInfo, so characterize_target re-derives it "
            "via `readelf -h` (ET_DYN vs ET_EXEC). None if undetermined."
        ),
    )
    stripped: bool | None = None
    libc: str | None = Field(
        default=None,
        description="Best-effort libc flavor (e.g. glibc/musl/uClibc), from ELFInfo.interpreter "
        "or a strings/symbol scan. None if undetermined.",
    )
    func_offset: str = Field(
        default="",
        description="The claimed function's validated entry_point address in the REAL binary "
        "(GhidraFunction.entry_point, cross-checked against the actual ELF) — empty string if "
        "it couldn't be resolved/validated.",
    )
    dispatch_resolvable: bool = Field(
        default=False,
        description="Best-effort: can a static caller/dispatch mechanism to the target "
        "function be resolved from the binary alone? Drives DynamicPlan.reach_strategy "
        "(natural_drive vs inferior_call).",
    )
    binary_path: str = Field(
        default="", description="Absolute host path to the real target ELF (rootfs_dir / "
        "DecompiledBinary.rootfs_path) — what the dynamic track actually emulates."
    )
    rootfs_dir: str = Field(
        default="", description="Absolute host path to the extracted firmware filesystem root "
        "— what bringup_stabilize chroots/binds into the session container."
    )


class GuardSpec(BaseModel):
    """One named guard/branch condition the dynamic track must satisfy —
    the structured form the strategy agent derives from a Stage 3 finding's
    PROSE `security_condition`/`data_flow` fields (see `common.findings.
    Finding`) plus `mem.target.func_offset`-relative addressing."""

    name: str = Field(description="Human-readable guard name, e.g. 'acscli2_acs_restart'.")
    addr: str = Field(default="", description="Address of the guard's branch/check, if resolved.")
    forced_value: str = Field(
        default="", description="The value satisfy_guards must force this guard to, to open "
        "the path being tested."
    )


class StaticPlan(BaseModel):
    """`mem.plan.static` — the strategy agent's translation of the finding
    into terms the EXISTING Joern static track (`agent.graph.
    build_verifier_graph`, reused unchanged) and the new `static_crosscheck`
    tool can act on. `target_function`/`source_fields`/`sink_names` feed
    `fvvw.static_track.render_static_brief`'s enrichment of the existing
    `prompts.render_finding_brief` text; `expected_intermediate_calls`/
    `sanitizer_patterns` feed `static_crosscheck` directly."""

    target_function: str
    source_fields: list[str] = Field(default_factory=list)
    sink_names: list[str] = Field(default_factory=list)
    expected_intermediate_calls: list[str] = Field(default_factory=list)
    sanitizer_patterns: list[str] = Field(default_factory=list)
    crosscheck_required: bool = Field(
        default=True,
        description="Whether static_crosscheck must run — true whenever the finding's "
        "evidence traces back to decompiler output (the common case).",
    )
    decisive_observable: str = Field(
        description="The finding's decisive observable, restated in static/CPGQL terms."
    )


class DynamicPlan(BaseModel):
    """`mem.plan.dynamic` — the strategy agent's translation of the finding
    into a concrete QEMU+GDB test the dynamic track's nodes execute
    (`tools.qemu_gdb_tool`, `fvvw.dynamic_track`)."""

    reach_strategy: str = Field(
        description='"natural_drive" (drive via argv/env/NVRAM through the binary\'s own '
        'dispatch) or "inferior_call" (break at the functional main and call the target '
        "function directly) — chosen from mem.target.dispatch_resolvable."
    )
    entry_addr: str = Field(
        default="", description='Functional "main": post-CRT dispatcher entry.'
    )
    target_addr: str = Field(
        default="", description="The claimed vulnerable function's address."
    )
    sink_addr: str = Field(
        default="", description="The sink call's address, if statically resolved."
    )
    guards: list[GuardSpec] = Field(default_factory=list)
    argv_template: list[str] = Field(default_factory=list)
    payload_marker: str = Field(
        description="The benign, distinguishing marker to inject — e.g. "
        "';touch /tmp/<claim_id>_proof;'. NEVER a functional exploit/reverse-shell/exfil "
        "payload; validated by instrument_trigger before use (hard invariant)."
    )
    required_signals: list[str] = Field(
        default_factory=list,
        description="The >=3 independent signals collect_signals must gather, e.g. "
        "['sink_argument_capture', 'target_self_report', 'filesystem_artifact'].",
    )
    decisive_observable: str = Field(
        description="The finding's decisive observable, restated in dynamic/GDB terms — "
        "must match StaticPlan.decisive_observable's underlying claim (validated post-check)."
    )


class Hypotheses(BaseModel):
    """`mem.plan.hypotheses` — the A/B pair `dynamic_evaluate`'s hypothesis
    switch (FVVW §9) tests, and `joern_evaluate`'s confirm/refute/inconclusive
    taxonomy already implicitly expresses."""

    a: str = Field(description="Hypothesis A: the exploitable scenario.")
    b: str = Field(description="Hypothesis B: the constrained/safe scenario.")
    decisive_observable: str = Field(
        description="The single observable that discriminates A from B, expressible by "
        "either track independently — must match both plans' own decisive_observable."
    )


class StrategyPlan(BaseModel):
    """`mem.plan.*` — the `strategy_agent` LLM node's full output (FVVW §6
    node 3). One LLM pass merges what the design doc calls three
    conceptual steps (threat model, hypotheses, per-track plan
    compilation) into one structured response."""

    threat_model: dict = Field(
        default_factory=dict,
        description="normal_data_flow, attack_scenario, trust_boundary (precisely stated, "
        "e.g. 'the argv[2] value', never 'network input' unless evidenced), and "
        "access_requirement (never an unearned 'unauthenticated remote' claim).",
    )
    hypotheses: Hypotheses
    static_plan: StaticPlan
    dynamic_plan: DynamicPlan
    static_runnable: bool = Field(
        default=True,
        description="False ONLY for hard infeasibility (no source for a CPG) — never merely "
        "'expected to be hard'.",
    )
    dynamic_runnable: bool = Field(
        default=True,
        description="False ONLY for hard infeasibility (no QEMU support for mem.target.arch) "
        "— never merely 'expected to be hard'.",
    )


class TrackResult(BaseModel):
    """`mem.static.result` / `mem.dynamic.result` — one track's terminal
    outcome, in the shape `joint_evaluate` (the only node reading both)
    consumes. For the static track, `evidence` embeds the existing
    `VerificationReport` (the unmodified Joern pipeline's own output) as a
    dict; for the dynamic track, `evidence` carries the GDB transcript +
    signal captures."""

    verdict: VerificationVerdict = Field(
        description="confirmed/refuted/inconclusive/error, reusing the SAME enum the "
        "existing static track already produces."
    )
    proved_hypothesis: str = Field(
        default="none", description='"A", "B", or "none".'
    )
    evidence: dict = Field(default_factory=dict)
    iters_used: int = 0


class Agreement(str, Enum):
    """`mem.joint.agreement` — how the two independent tracks' terminal
    verdicts relate. Fixed by `fvvw.joint.joint_evaluate`'s rule engine —
    not something a downstream consumer should extend without updating
    that function too."""

    CONCORDANT_CONFIRM = "concordant_confirm"
    CONCORDANT_REFUTE = "concordant_refute"
    DISCORDANT = "discordant"
    ONE_SIDED = "one_sided"


class MechanismConfidence(str, Enum):
    """`mem.joint.mechanism_confidence` — does unsanitized attacker data
    reach the sink unmodified, IF the path is taken."""

    CONFIRMED_STRONG = "confirmed_strong"
    """Both tracks independently confirmed (>= 3 corroborating signals, per
    FVVW's multi-signal-corroboration principle)."""
    CONFIRMED_SINGLE_TRACK = "confirmed_single_track"
    """Only one track ran to a confirmed verdict; the other was
    inconclusive/not_run — not a discordant disagreement."""
    DISCORDANT_HOLD = "discordant_hold"
    """One track confirmed, the other refuted — routed to human review,
    NEVER auto-resolved by trusting one track by default."""
    INCONCLUSIVE = "inconclusive"


class ReachabilityConfidence(str, Enum):
    """`mem.joint.reachability_confidence` — can the path be reached in
    production, independent of the mechanism axis (FVVW's two-axis-truth
    principle: these are never collapsed into one boolean)."""

    CONFIRMED = "confirmed"
    CONDITIONAL = "conditional"
    FORCED_UNKNOWN = "forced_unknown"
    """A guard was forced to reach the sink rather than satisfied by
    attacker-controlled input — caps confidence here, never raises it."""
    REFUTED = "refuted"


class FVVWReport(BaseModel):
    """The fork-join run's on-disk artifact: `stage5/fvvw/<gid>.json`.
    Assembled by `fvvw.graph`'s driver from the terminal STM after
    `joint_evaluate`/`write_report` — embeds both tracks' own results
    rather than replacing `VerificationReport` (which remains the static
    track's own persisted artifact at `stage5/verifications/<gid>.json`,
    unchanged)."""

    schema_version: int = 1
    global_id: str
    bin_id: str
    static_result: TrackResult
    dynamic_result: TrackResult
    agreement: Agreement
    mechanism_confidence: MechanismConfidence
    reachability_confidence: ReachabilityConfidence
    residual_unknowns: list[str] = Field(default_factory=list)
    report_markdown: str = ""
    """The `write_report` LLM node's composed seven-layer disclosure
    document plus reconciliation section (FVVW §11) — Markdown, not
    re-parsed by anything downstream."""
    guard_logs: list[dict] = Field(default_factory=list)
    """`fvvw.dynamic_track.satisfy_guards`'s per-guard
    name/addr/real_value/forced_value log — computed by `run_fvvw` and
    previously fed to `write_report` as LLM input only, then dropped.
    Persisted here so a guard's REAL (un-overridden) default is checkable
    without re-running the dynamic track, and so
    `reachability_confidence=forced_unknown` has durable supporting
    evidence."""
    dynamic_gdb_transcript: str = ""
    """The dynamic track's full concatenated GDB session transcript
    (`run_dynamic_track_only`'s return value) — previously fed to
    `write_report` as LLM input only, then dropped. This is the raw
    material `fvvw/logs/<gid>.dynamic.jsonl`'s individual records are
    assembled from; kept here too as one contiguous record matching what
    the disclosure document was actually written from."""
    crosscheck_evidence: dict = Field(default_factory=dict)
    """`tools.crosscheck_tool.static_crosscheck`'s
    `CrosscheckResult.to_evidence_dict()` — the disassembly-based
    confirm/refute of `StaticPlan.expected_intermediate_calls`/
    `.sanitizer_patterns`, an independent signal from the decompiled-C-based
    Joern track. Previously computed and returned by `run_fvvw` but never
    persisted."""
    command_log_paths: dict[str, str] = Field(default_factory=dict)
    """`{"static": "<path>", "dynamic": "<path>"}` — where each track's
    `cmdlog.CommandLog` JSONL landed for THIS run, so a reader of the
    report JSON doesn't have to re-derive `fvvw/logs/<gid>.<track>.jsonl`
    from `global_id` by hand. Empty when `Settings.stage5_command_log` was
    `False` for this run."""
    started_at: datetime
    finished_at: datetime | None = None
    trace_url: str | None = None
