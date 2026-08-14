"""Stage 4 Component 5's taint-path schema.

The structured-output contract `taint.analyst.analyze_taint` is constrained
against via `BaseChatModel.with_structured_output`, and the on-disk shape of
`stage4/taint/<gid>.json`. Kept separate from `common/findings.py` (Stage 3's
own schema) the same way that file is kept separate from `common/schemas.py`
— a genuinely different concern (a resolved source-to-sink data-flow path,
not a chunk-local candidate finding).

Every field carries a `Field(description=...)` — same schema-is-the-prompt
convention as `common.findings.Finding` (see that module's docstring for the
"prose-only enforcement was tried and abandoned" precedent this follows).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class SourceClass(str, Enum):
    """Where a taint path's origin ultimately traces back to."""

    NVRAM = "NVRAM"
    """A persisted NVRAM/config key (e.g. `nvram_get("...")`)."""
    HTTP_PARAM = "HTTP_PARAM"
    """A web UI / CGI request parameter."""
    NETWORK = "NETWORK"
    """Raw socket/network input (not HTTP-parsed)."""
    IPC = "IPC"
    """Inter-process communication (UNIX socket, shared memory, message queue)."""
    FILE = "FILE"
    """Read from a filesystem path."""
    CLI = "CLI"
    """Command-line argument or environment passed at process start."""
    ENV = "ENV"
    """Process environment variable."""
    CONST = "CONST"
    """Not attacker-influenced — a compile-time constant or hardcoded value."""
    UNKNOWN = "UNKNOWN"
    """Origin could not be established from the retrieved context. Use this
    rather than guessing — pairs with `TaintPathReport.missing_context`."""


class TaintStep(BaseModel):
    """One hop in a source-to-sink data-flow path."""

    step_index: int = Field(description="0-based position of this step within its TaintPath.")
    code_location: str = Field(
        description=(
            "Where this step occurs, e.g. 'sbin/httpd:cgi_set_wifi#L142' — "
            "function/file identifier plus line, drawn from the retrieved chunk "
            "metadata, never invented."
        )
    )
    description: str = Field(
        description="What happens at this step: assignment, function call, comparison, etc."
    )
    source_class: SourceClass | None = Field(
        default=None,
        description="Set only on the path's origin step; null for intermediate/sink steps.",
    )


class TaintPath(BaseModel):
    """One candidate source-to-sink path resolving (part of) a Stage 3 finding."""

    steps: list[TaintStep] = Field(
        default_factory=list, description="Ordered hops from source to sink."
    )
    source_class: SourceClass
    confidence: str = Field(
        description="CONFIRMED, HIGH, MEDIUM, or LOW — same vocabulary as "
        "common.findings.Confidence, describing how well the retrieved context "
        "supports this specific path."
    )
    narrative: str = Field(
        description="Prose summary of how the value flows from source to sink."
    )


class TaintPathReport(BaseModel):
    """Component 5's full structured output for one Stage 3 finding.

    This is the Pydantic model passed to `with_structured_output(...)` —
    framework-enforced schema compliance, not prompt-instruction-only
    enforcement (see this module's docstring).
    """

    finding_id: str = Field(
        description="The global finding id this report resolves, "
        "'<chunk_id>::<finding_id>' — copied from the input, never invented."
    )
    resolved: bool = Field(
        description="True if at least one TaintPath with source_class != UNKNOWN was built."
    )
    taint_paths: list[TaintPath] = Field(default_factory=list)
    missing_context: list[str] = Field(
        default_factory=list,
        description="Specific context the retrieved chunks did not cover, preventing full "
        "resolution — names what's missing rather than leaving `resolved=False` unexplained.",
    )
    analysis_notes: str = Field(
        default="", description="Any caveats about the retrieved context's coverage or quality."
    )


# --------------------------------------------------------------------- #
# Run-level aggregation (not sent to the LLM — Component 6's own driver
# bookkeeping, analogous to common.findings.AnalysisRunSummary).
# --------------------------------------------------------------------- #


class FindingRunRecord(BaseModel):
    """One Stage 3 finding's outcome as it passed through the C3->C4->C5 driver."""

    global_id: str
    chunk_id: str
    bin_id: str
    status: str = Field(
        description="One of: completed (query+retrieval+taint all persisted), "
        "failed (an attempt errored past stage4_queue_max_attempts)."
    )
    attempts: int = 0
    retrieved_chunk_count: int = 0
    taint_path_count: int = 0
    error: str | None = None


class Stage4RunSummary(BaseModel):
    """Component 6's machine-readable hand-off (`stage4/stage4_summary.json`),
    written by `driver.run_queue()` itself — same "written by the
    orchestrator function, not only the CLI" discipline as
    `AnalysisRunSummary`."""

    schema_version: int = 1
    run_id: str | None = None
    status: str = Field(
        description="completed | no_targets | stage4_input_unavailable | "
        "vector_store_unavailable | planner_unavailable | analyst_unavailable"
    )
    db_subfolder: str
    query_planner_model: str = ""
    taint_analyst_model: str = ""
    embedding_model: str = ""
    findings: list[FindingRunRecord] = Field(default_factory=list)
    total_findings: int = 0
    total_completed: int = 0
    total_failed: int = 0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime | None = None
