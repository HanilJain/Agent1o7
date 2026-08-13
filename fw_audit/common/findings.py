"""Stage 3 Component 2's vulnerability-finding schema.

These are the structured-output contract the analyst LLM (`stage3_analysis.
agent`) is constrained against via `BaseChatModel.with_structured_output`,
and the on-disk shape of `stage3/findings/<chunk_id>.json` /
`stage3/analysis_summary.json`. Kept in its own module rather than appended
to `common/schemas.py` — that file already carries the Stage 1/2/3-Component-1
cross-stage contracts (442 lines before this), and this adds roughly a dozen
models for a genuinely separate concern (candidate security findings, not
pipeline plumbing).

Every `Finding` field carries a `Field(description=...)`. Per this project's
established convention (see `common.schemas.IdentifiedBinary` and
`stage1_ingestion.identifier.agent._IdentifiedBinaryList`), THAT description
is the schema-level instruction the LLM actually sees through
`with_structured_output` — it is the enforcement mechanism, not prose
elsewhere in the system prompt. Prose-only format enforcement was tried for
the Identifier Agent and abandoned as unreliable at small model sizes (see
`stage1_ingestion/identifier/prompts.py`); don't reintroduce it here.

`category` and `tags` are deliberately free-form `str`/`list[str]`, not
closed enums: the worker system prompt instructs the analyst to look across
memory safety, integer/type errors, unsafe parsing, auth, crypto, IPC,
firmware-update logic, and explicitly "not limit analysis to predefined
vulnerability classes" — a closed enum would contradict that brief.
`Confidence` and `Decision` ARE closed enums: the prompt fixes both value
sets exactly (CONFIRMED/HIGH/MEDIUM/LOW; ESCALATE/CONTEXT_REQUIRED/MERGE/
DISCARD), so constraining them catches a drifted or hallucinated value
rather than silently accepting it.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Confidence(str, Enum):
    """How strongly the supplied chunk itself supports a finding.

    Fixed by the worker system prompt's RANKING section — not something a
    downstream consumer should extend without updating that prompt too.
    """

    CONFIRMED = "CONFIRMED"
    """Evidence in this chunk establishes the condition."""
    HIGH = "HIGH"
    """Strong evidence; external context/verification remains."""
    MEDIUM = "MEDIUM"
    """Meaningful candidate requiring CPG or binary-level confirmation."""
    LOW = "LOW"
    """Weak signal; generally not worth prioritizing."""


class Decision(str, Enum):
    """The analyst's disposition for a candidate finding."""

    ESCALATE = "ESCALATE"
    """Strong candidate for verification."""
    CONTEXT_REQUIRED = "CONTEXT_REQUIRED"
    """Requires unavailable program context (caller/callee/global/macro/
    struct/ABI/protocol fact) — do not invent that behavior; this
    disposition names exactly what's missing instead."""
    MERGE = "MERGE"
    """Duplicate/overlapping candidate."""
    DISCARD = "DISCARD"
    """Insufficient security relevance."""


class Severity(BaseModel):
    """Independent 1-5 ratings, per the worker prompt's RANKING section."""

    impact: int = Field(ge=1, le=5, description="Severity of consequence if exploited, 1-5.")
    exploitability: int = Field(
        ge=1, le=5, description="How easily an attacker could trigger/exploit this, 1-5."
    )
    reachability: int = Field(
        ge=1,
        le=5,
        description="How reachable this code path is from an attacker-facing entry point, 1-5.",
    )


class EvidenceSpan(BaseModel):
    """The exact code evidence backing a finding — never invented."""

    function_id: str = Field(description="The function this evidence span is within.")
    line_start: int = Field(description="First line of the evidence span.")
    line_end: int = Field(description="Last line of the evidence span (inclusive).")
    code: str = Field(
        description=(
            "The exact source text of the evidence span, verbatim from the supplied "
            "chunk. Preserve [Lnnn] line markers if the chunk provides them."
        )
    )


class FindingSource(BaseModel):
    """Where the tainted/relevant value in this finding originates."""

    expression: str = Field(description="The source expression, e.g. a parameter or return value.")
    type: str = Field(
        description=(
            "The kind of source, e.g. FUNCTION_PARAMETER, GLOBAL_VARIABLE, "
            "RETURN_VALUE, ENVIRONMENT, FILE_READ, NETWORK_READ."
        )
    )
    attacker_control: str = Field(
        description=(
            "Whether this source is attacker-controlled: YES, NO, or UNKNOWN. Use "
            "UNKNOWN rather than inventing attacker controllability the chunk doesn't "
            "establish — downstream analysis verifies this."
        )
    )


class FindingSink(BaseModel):
    """Where the source value is used in a security-relevant way."""

    expression: str = Field(description="The sink expression, e.g. a dangerous function call.")
    type: str = Field(
        description=(
            "The kind of sink, e.g. MEMORY_WRITE, MEMORY_READ, COMMAND_EXECUTION, "
            "FORMAT_STRING, FILE_PATH, AUTH_DECISION, CRYPTO_OPERATION."
        )
    )


class Finding(BaseModel):
    """One candidate security finding within a chunk.

    Mirrors the required JSON schema's `findings[]` entries field-for-field.
    """

    finding_id: str = Field(
        description="A short identifier unique within this chunk's report, e.g. 'candidate_001'."
    )
    title: str = Field(description="A concise, specific title for the finding.")
    category: str = Field(
        description=(
            "The vulnerability category, free-form (not limited to a predefined list) "
            "e.g. memory_safety, integer_overflow, command_execution, format_string, "
            "hardcoded_secret, path_traversal, race_condition, auth_bypass."
        )
    )
    cwe: list[str] = Field(
        default_factory=list,
        description=(
            "Applicable CWE identifiers, e.g. ['CWE-121', 'CWE-787']. "
            "Empty if none clearly apply."
        ),
    )
    severity: Severity
    confidence: Confidence
    decision: Decision
    tags: list[str] = Field(
        default_factory=list,
        description=(
            "Free-form classification tags, e.g. UNSAFE_OPERATION, MEMORY_SAFETY, "
            "BOUNDS_CHECK, DATA_FLOW."
        ),
    )
    evidence_span: EvidenceSpan
    source: FindingSource
    sink: FindingSink
    data_flow: list[str] = Field(
        default_factory=list,
        description="Ordered steps describing how the value flows from source to sink.",
    )
    security_condition: str = Field(
        description="The specific security-relevant condition observed (e.g. an unchecked bound)."
    )
    exploitability: str = Field(
        description=(
            "Prose assessment of what would need to be true for this to be exploitable, "
            "and what is NOT established by this chunk alone."
        )
    )
    impact: str = Field(
        description="Prose assessment of the consequence if the condition is exploitable."
    )
    why_vulnerable: str = Field(
        description="Concise explanation of why this operation is security-relevant."
    )
    why_not_false_positive: str = Field(
        description=(
            "Why this candidate is grounded in concrete evidence rather than merely "
            "the presence of a dangerous-looking API."
        )
    )
    missing_context: list[str] = Field(
        default_factory=list,
        description=(
            "Specific unavailable context (functions, callers, globals, macros, ABI "
            "facts) needed to resolve this finding."
        ),
    )
    recommended_next_analysis: list[str] = Field(
        default_factory=list,
        description="Concrete next steps for downstream/CPG/binary-level verification.",
    )


class CheckedCategory(BaseModel):
    """A vulnerability category the analyst considered but did not escalate.

    Provides negative evidence — what was looked for and ruled out — not
    just what was found.
    """

    category: str = Field(
        description="The category considered, e.g. command_execution, hardcoded_secret."
    )
    status: str = Field(description="e.g. NOT_CONFIRMED, NOT_APPLICABLE.")
    reason: str = Field(description="Why this category was not escalated to a finding.")


class AnalysisReport(BaseModel):
    """The analyst LLM's full structured output for one chunk.

    This is the Pydantic model passed to `with_structured_output(...)` —
    framework-enforced schema compliance, not prompt-instruction-only
    enforcement (see this module's docstring).
    """

    chunk_id: str = Field(description="The chunk identifier this report covers.")
    function_id: str = Field(
        default="",
        description=(
            "The primary function this report concerns, if the chunk centers on one "
            "function. Empty string if the chunk spans multiple functions with no "
            "single primary one."
        ),
    )
    findings: list[Finding] = Field(
        default_factory=list, description="Candidate findings identified in this chunk."
    )
    checked_categories: list[CheckedCategory] = Field(
        default_factory=list,
        description="Categories considered but not escalated, with reasons — see CheckedCategory.",
    )
    analysis_limitations: list[str] = Field(
        default_factory=list,
        description="Caveats about what this chunk alone could not establish.",
    )


# --------------------------------------------------------------------- #
# Run-level aggregation (not sent to the LLM — Stage 3's own bookkeeping,
# analogous to common.schemas.Stage3Summary/ChunkRecord but for analysis
# outcomes rather than queue outcomes).
# --------------------------------------------------------------------- #


class ChunkAnalysisRecord(BaseModel):
    """One chunk's outcome as it passed through the analysis consumer.

    Distinct from `common.schemas.ChunkRecord`: that one records the
    chunk's QUEUE outcome (acked/failed, attempts) with no judgment about
    content; this one records the ANALYSIS outcome (did an LLM produce a
    valid report, how many findings, where is it on disk).
    """

    chunk_id: str
    bin_id: str
    rootfs_path: str
    status: str = Field(
        description="One of: analyzed (a validated AnalysisReport was produced and persisted), "
        "failed (every attempt errored or failed validation), "
        "skipped_oversized (chunk exceeded stage3_max_chunk_tokens; no LLM call made)."
    )
    attempts: int = 0
    finding_count: int = 0
    findings_relpath: str | None = None
    """Path to `findings/<chunk_id>.json`, relative to `db_subfolder` —
    mirrors `common.schemas.ChunkRecord.chunk_path`'s relativity
    convention. `None` when status != "analyzed"."""
    error: str | None = None


class AnalysisRunSummary(BaseModel):
    """Stage 3 Component 2's machine-readable hand-off
    (`stage3/analysis_summary.json`), written by
    `stage3_analysis.agent.orchestrator.run_analysis()` itself — same
    "written by the orchestrator function, not only the CLI" discipline as
    `Stage2Summary`/`Stage3Summary`.

    Deliberately a SEPARATE artifact from `Stage3Summary`, not an extension
    of it: `Stage3Summary`'s own docstring documents that it "deliberately
    carries NO findings/vulnerability data — that's Component 2's concern"
    and reserves that as a hand-off contract Component 1 keeps stable.
    """

    schema_version: int = 1
    run_id: str | None = None
    status: str = Field(
        description="completed | no_targets | stage3_input_unavailable | analyst_unavailable — "
        "mirrors Stage3Summary.status's vocabulary, plus analyst_unavailable for a "
        "missing/misconfigured LLM credential that stopped the run before any chunk "
        "was analyzed."
    )
    db_subfolder: str
    model: str
    """The resolved `<provider>:<model>` actually used, for reproducibility
    (e.g. "anthropic:claude-sonnet-4-5")."""
    chunks: list[ChunkAnalysisRecord] = Field(default_factory=list)
    total_chunks: int = 0
    total_analyzed: int = 0
    total_failed: int = 0
    total_skipped: int = 0
    total_findings: int = 0
    findings_by_decision: dict[str, int] = Field(default_factory=dict)
    findings_by_confidence: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime | None = None
