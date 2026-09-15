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
from typing import Literal

from pydantic import BaseModel, Field


class VerificationVerdict(str, Enum):
    """The agent's disposition for a candidate finding, after running Joern
    queries against its CPG. Fixed by the verifier system prompt — not
    something a downstream consumer should extend without updating that
    prompt too (see `stage5_verification.agent.prompts`)."""

    CONFIRMED = "CONFIRMED"
    """CPG evidence establishes the finding's claimed security condition —
    requires `EvaluatorVerdict.hypothesis_proved == "A"` (a concrete
    source->sink path was exhibited)."""
    REFUTED = "REFUTED"
    """CPG evidence POSITIVELY contradicts the finding's claimed security
    condition — requires `EvaluatorVerdict.hypothesis_proved == "B"` (a
    specific sanitizer/guard/constant was exhibited, or a demonstrably
    healthy dataflow engine still found no path). An empty
    `reachableByFlows` result on its own is NEVER sufficient for REFUTED —
    see `agent.prompts.EVALUATOR_SYSTEM_PROMPT`'s cardinal rule."""
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
    """The script ran and its output can be judged on the merits — this is
    NOT the same as having settled the question. Which hypothesis (if any)
    the round positively proved is carried separately in
    `EvaluatorVerdict.hypothesis_proved`; `agent.graph.evaluate_node`
    converts a PASS with `hypothesis_proved == "none"` back into a retry
    rather than concluding on it."""
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
    hypothesis_proved: Literal["A", "B", "none"] = Field(
        default="none",
        description=(
            'Which competing hypothesis this round POSITIVELY proved. "A": a '
            'concrete source->sink path was exhibited. "B": a specific '
            'sanitizer, guard, or constant sink argument was exhibited, OR the '
            "script's own engine-health checks all passed and a demonstrably "
            'working dataflow engine still found no path. "none": neither. An '
            'empty reachableByFlows result, alone, is NEVER "B".'
        ),
    )
    confidence: str = Field(
        default="LOW",
        description=(
            "HIGH, MEDIUM, or LOW — how confidently the script's output settles the question, "
            "not how cleanly the script ran."
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
    trigger_shape: str = Field(
        default="",
        description="How the trigger agent should reach the sink: 'network_http', "
        "'cli_argv', 'direct_call', or another short label describing the delivery "
        "channel — mirrors the spec's Node 1 trigger_shape field, consumed by the "
        "Node 6 trigger agent to choose HTTP/argv/GDB-call delivery.",
    )
    preconditions: list[str] = Field(
        default_factory=list,
        description="Anything that must be true before the sink is reachable, e.g. "
        "'must be authenticated', 'NVRAM key X must be set' — re-applied by the trigger "
        "agent immediately before firing, per the spec's Node 6 precondition setup.",
    )
    payload_marker: str = Field(
        default="",
        description="A benign, distinguishing marker (e.g. ';touch /tmp/<claim_id>_proof;'), "
        "used only when Settings.stage5_allow_real_payloads is False (the benign-only "
        "kill-switch). When real payloads are allowed (the default), the trigger agent "
        "crafts the actual malicious input from 'oracle'/'trigger_shape' instead and this "
        "field is informational/unused.",
    )
    oracle: str = Field(
        default="",
        description="The exact, mechanically-checkable condition that means 'confirmed' — "
        "e.g. 'process receives SIGSEGV with PC inside the strcpy call site' or 'a file is "
        "written to /tmp/<id>_proof containing OVERFLOW_CONFIRMED'. This is what the Node 8 "
        "evaluator's deterministic first pass matches the ObservationRecord against, restated "
        "in dynamic/GDB terms — must describe the SAME underlying claim as "
        "Hypotheses.oracle/StaticPlan.decisive_observable (validated post-check).",
    )
    disconfirm_condition: str = Field(
        default="",
        description="What result means 'false positive' — e.g. 'input reaches the sink but "
        "is safely bounds-checked before use'. Restated in dynamic/GDB terms; must describe "
        "the same underlying claim as Hypotheses.disconfirm_condition.",
    )
    required_signals: list[str] = Field(
        default_factory=list,
        description="The >=3 independent signals collect_signals must gather, e.g. "
        "['sink_argument_capture', 'target_self_report', 'filesystem_artifact'] (benign-only "
        "mode), or ['crash_signal', 'register_state', 'memory_diff'] (real-payload mode).",
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
    oracle: str = Field(
        default="",
        description="The exact, mechanically-checkable condition that means hypothesis A is "
        "confirmed (spec Node 1's 'oracle' field) — a crash signal + PC location, a specific "
        "artifact, a specific string. Ground truth for the Node 8 evaluator's deterministic "
        "first pass; never the LLM's own opinion.",
    )
    disconfirm_condition: str = Field(
        default="",
        description="What result means hypothesis B / false-positive (spec Node 1's "
        "'disconfirm_condition' field) — e.g. 'the path is provably unreachable from any "
        "network-facing input', or 'input reaches the sink but is safely bounds-checked'.",
    )
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
    proved_hypothesis: Literal["A", "B", "none"] = Field(
        default="none",
        description='"A", "B", or "none" — "A"/"B" require POSITIVE proof, '
        "never inferred from absence of evidence (see EvaluatorVerdict.hypothesis_proved).",
    )
    evidence: dict = Field(default_factory=dict)
    iters_used: int = 0


class ArbitrationLogEntry(BaseModel):
    """One environment fix Node 3 (Bring-Up & Arbitration) applied — a
    dummy file, a stub library, an `LD_PRELOAD` shim, a forced environment
    variable, or a session/container-level action (e.g. 'started session'),
    per the spec's "Core idea — you do not need a real filesystem, you need
    a filesystem the binary is happy with" principle. Kept as a structured
    list (not free prose) so `write_report`'s "Full arbitration log" section
    (spec Node 9, required content #4) can enumerate every fix a human would
    need to reconstruct the exact working chroot, without re-parsing text."""

    kind: str = Field(
        description="'dummy_file' | 'dummy_dir' | 'device_node' | 'stub_library' | "
        "'ld_preload_shim' | 'env_override' | 'network_grant' | 'session_started' | "
        "'other' — the category of fix applied."
    )
    target: str = Field(
        default="", description="The path/env-var/device name the fix concerns, e.g. "
        "'/etc/config/wireless' or 'OPENSSL_armcap'."
    )
    detail: str = Field(
        default="", description="What was actually written/set, e.g. the placeholder file "
        "content, the forced value, or the stub symbol names exported.",
    )
    reasoning: str = Field(
        default="", description="Why the bring-up agent believed this fix was needed — e.g. "
        "the strace ENOENT line or missing-symbol error that motivated it.",
    )


class ArbitrationLog(BaseModel):
    """`mem.dynamic.arbitration_log` — Node 3's full structured record,
    required for reproducibility per the spec's "Critical requirement —
    record everything." Distinct from `BringupContext.applied_fixes` (a
    plain list of short strings the existing deterministic bring-up already
    keeps) — this is the richer, LLM-reasoned equivalent the agentic Node 3
    produces, with a `reasoning` field per entry the plain string list
    cannot carry."""

    entries: list[ArbitrationLogEntry] = Field(default_factory=list)
    strace_findings: list[str] = Field(
        default_factory=list,
        description="Raw ENOENT/failed-open lines the bring-up agent's strace pass "
        "surfaced, kept verbatim as the evidence base for `entries`.",
    )
    launch_recipe: str = Field(
        default="", description="The final qemu-<arch> launch command line that worked, "
        "after every fix in `entries` was applied — the spec's 'launch recipe' output."
    )


class ObservationRecord(BaseModel):
    """`mem.dynamic.observation` — Node 7's (Run & Observe) structured
    capture, read by Node 8's deterministic oracle-match first pass before
    any LLM judgement. Fields mirror the spec's Node 7 "Run & Observe"
    required contents exactly (signal capture / memory inspection /
    artifact proof / full transcript)."""

    signal: str | None = Field(
        default=None, description="The POSIX signal name the target died from, if any — "
        "'SIGSEGV' | 'SIGABRT' | 'SIGILL' | None (no crash)."
    )
    faulting_pc: str | None = Field(
        default=None, description="The instruction pointer ($pc) at the moment of the crash, "
        "hex string — None if no crash."
    )
    registers: dict[str, str] = Field(
        default_factory=dict, description="Register name -> value dump captured at the crash "
        "or at the trigger breakpoint (`info registers` output, parsed).",
    )
    memory_before: str = Field(
        default="", description="Hex dump of the watched buffer/region BEFORE the risky "
        "operation (`x/32xb <addr>`) — since QEMU user-mode has no hardware watchpoints, this "
        "before/after diff is the substitute the spec's Node 5 mandates.",
    )
    memory_after: str = Field(
        default="", description="Hex dump of the same region AFTER the risky operation."
    )
    memory_diff_detected: bool = Field(
        default=False, description="Whether memory_before != memory_after — the overwrite "
        "confirmation signal."
    )
    stdout: str = Field(default="", description="Captured target stdout.")
    stderr: str = Field(default="", description="Captured target stderr.")
    filesystem_artifacts: list[str] = Field(
        default_factory=list, description="Paths confirmed written/modified as a side effect "
        "of the trigger (command-injection/info-leak/auth-bypass style bugs)."
    )
    network_response: str = Field(
        default="", description="Captured HTTP/network response content, for network-facing "
        "triggers that don't crash the process outright."
    )
    oracle_match: bool | None = Field(
        default=None, description="Result of Node 8's DETERMINISTIC first-pass check of this "
        "record against DynamicPlan.oracle — True/False once checked, None before it runs. "
        "Never the LLM's own opinion; a literal string/signal/address match.",
    )
    transcript: str = Field(
        default="", description="Every GDB command executed and its output for this round, "
        "verbatim — the spec's Node 7 'full transcript capture' requirement."
    )


class RouteDecision(BaseModel):
    """Node 8's (Evaluator + Router) per-round output — the spec's §10
    decision table, expressed as data. `route` is read by the dynamic
    graph's conditional edges to decide the next node; `diagnosis` is the
    human-readable reason recorded in `iteration_history` (spec Node 9,
    required content #7)."""

    route: Literal[
        "confirmed",
        "refuted",
        "retry_bringup",
        "retry_gdb_attach",
        "retry_trigger",
        "escalate_direct_call",
        "inconclusive",
    ] = Field(
        description="Which node to resume at, or a terminal disposition — mirrors the spec's "
        "§10 decision table exactly: 'confirmed'/'refuted' end the loop; 'retry_bringup' "
        "routes to Node 3; 'retry_gdb_attach' to Node 5; 'retry_trigger' to Node 6; "
        "'escalate_direct_call' to Node 2 with emulation_mode='direct_call'; "
        "'inconclusive' ends the loop (budget exhausted or genuinely stuck)."
    )
    diagnosis: str = Field(
        default="", description="Why this route was chosen — e.g. 'breakpoint from Node 5 "
        "never hit: wrong sink location or input never reached that code path'."
    )
    confidence: str = Field(default="LOW", description="HIGH, MEDIUM, or LOW.")


class Agreement(str, Enum):
    """`mem.joint.agreement` — how the two independent tracks' terminal
    verdicts relate. Fixed by `fvvw.joint.joint_evaluate`'s rule engine —
    not something a downstream consumer should extend without updating
    that function too."""

    CONCORDANT_CONFIRM = "concordant_confirm"
    CONCORDANT_REFUTE = "concordant_refute"
    DISCORDANT = "discordant"
    ONE_SIDED = "one_sided"
    NEITHER = "neither"
    """Neither track reached a definite (CONFIRMED/REFUTED) verdict — distinct
    from ONE_SIDED, which requires exactly one track to have reached one."""


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


class HumanReviewRecord(BaseModel):
    """`mem.joint.human_review` / `FVVWReport.human_review` — set only when
    an operator intervened via HITL (`stage5_verification.fvvw.hitl`) on a
    track that exhausted its budget without a decisive verdict. `None` (the
    default on `FVVWReport`) means no human intervention happened for this
    candidate — the ordinary, unattended path. Recording this durably (not
    just noting it in `residual_unknowns`) is what lets a reader of the
    persisted report distinguish a machine-derived verdict from a
    human-attributed one at a glance, without re-deriving it from prose."""

    track: str = Field(description="'static' or 'dynamic' — which track the operator acted on.")
    action: str = Field(
        description="The HitlAction taken: 'retry', 'override_plan', 'inject', or "
        "'force_verdict'."
    )
    rationale: str = Field(
        default="", description="The operator's stated reasoning, verbatim."
    )
    overrides: dict = Field(
        default_factory=dict,
        description="Plan-field overrides applied ('override_plan') or the injected payload "
        "text ('inject') — empty for 'retry'/'force_verdict'.",
    )
    rounds: int = Field(
        default=1, description="How many HITL prompt rounds this candidate went through "
        "before reaching a final disposition (bounded by stage5_hitl_max_rounds)."
    )
    timestamp: datetime


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
    human_review: HumanReviewRecord | None = None
    """Set only when an operator intervened via HITL (`Settings.
    stage5_hitl_mode="prompt"`) on a track that exhausted its budget without
    a decisive verdict — see `HumanReviewRecord`'s own docstring. `None`
    (the default) for every ordinary, unattended run."""
    emulation_mode: str = ""
    """`"user"` | `"system"` | `"direct_call"` — the dynamic track's final
    `mem.dynamic.emulation_plan["mode"]`/Node 2 output. `"direct_call"`
    means the trigger was delivered via GDB's `call` command rather than a
    real front-door input (spec Node 9, required content #3/#8 — MUST be
    stated plainly so a reader knows whether this bypassed the normal
    dispatch path)."""
    arbitration_log: ArbitrationLog = Field(default_factory=ArbitrationLog)
    """Node 3's full structured record of every dummy file/stub/env-fix
    applied — spec Node 9, required content #4 ("Full arbitration log")."""
    observation: ObservationRecord = Field(default_factory=ObservationRecord)
    """Node 7's final structured capture (signal/registers/memory-diff/
    artifacts) for the round that produced the terminal verdict — spec
    Node 9, required content #6 ("Observation evidence")."""
    iteration_history: list[RouteDecision] = Field(default_factory=list)
    """Every `RouteDecision` Node 8 emitted across the whole dynamic-track
    run, in order — spec Node 9, required content #7 ("what was tried, what
    failed, and why"). Empty when the run confirmed/refuted on its first
    pass."""
    started_at: datetime
    finished_at: datetime | None = None
    trace_url: str | None = None
