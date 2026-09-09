"""Stage 3b's claim-extraction schema.

Stage 3b (`fw_audit.stage3b_claims`) reads a third-party PDF vulnerability
report and turns each claim it makes into a `common.findings.AnalysisReport`
that Stage 4/5 can verify unchanged — see that package's own docstring for
the parallel-to-Stage-3 framing. This module owns only the NARROW
LLM-structured-output contract used along the way
(`ClaimExtraction`/`ClaimExtractionBatch`) plus this stage's own run
bookkeeping (`ClaimRecord`/`ClaimsRunSummary`), kept separate from
`common/findings.py` the same way `common/taint.py` and
`common/verification.py` are kept separate from it — a genuinely different
concern (transcribing a report's own claims) from Stage 3's (discovering
findings by reading code), even though the two converge on the same
`Finding` shape at the end via `stage3b_claims.emit.to_analysis_report`.

`ClaimExtraction` is deliberately NARROW compared to `common.findings.
Finding` — this is the module's central cost decision (see
`stage3b_claims/CLAUDE.md`'s "cheap transcription, not analysis" framing).
Asking the LLM for the full ~18-field `Finding` schema on every claim would
put a large JSON schema in every request and demand a proportionally large
completion; asking for the handful of fields a report actually states does
not. `stage3b_claims.emit.to_analysis_report` expands a `ClaimExtraction`
into a full, valid `Finding` deterministically, spending no extra tokens.

Every field carries a `Field(description=...)` for the same reason
`common.findings`'s own docstring gives: that description is the
schema-level instruction the LLM actually sees through
`with_structured_output`, not prose elsewhere in the prompt.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ClaimExtraction(BaseModel):
    """One claim transcribed from a single block of report text.

    Fields mirror only what a report realistically states about a claimed
    vulnerability — never invented, never inferred beyond the block's own
    text. Leave a field empty/default rather than guessing; `emit.py`'s
    deterministic mapping is what turns "unknown" into an honest
    `Finding.missing_context` entry rather than a fabricated value.
    """

    claim_id: str = Field(
        description="A short identifier unique within this block's extraction, e.g. 'claim_001'."
    )
    title: str = Field(description="A concise, specific title for the claim.")
    category: str = Field(
        description=(
            "The vulnerability category the report itself uses or implies, free-form "
            "(not limited to a predefined list), e.g. memory_safety, command_execution, "
            "hardcoded_secret, auth_bypass."
        )
    )
    cwe: list[str] = Field(
        default_factory=list,
        description="CWE identifiers the report itself states, e.g. ['CWE-121']. Empty if none.",
    )
    cve_ids: list[str] = Field(
        default_factory=list,
        description=(
            "CVE identifiers the report itself states, e.g. ['CVE-2024-12345']. Empty if none."
        ),
    )
    binary_hint: str = Field(
        default="",
        description=(
            "The executable, service, or component name the report says is affected, "
            "verbatim, e.g. 'httpd' or '/usr/sbin/hostapd'. Empty string if the report "
            "doesn't name one."
        ),
    )
    function_hint: str = Field(
        default="",
        description=(
            "The function or symbol name the report says is affected, verbatim, e.g. "
            "'formSetWanNonLogin'. Empty string if the report doesn't name one."
        ),
    )
    source_expression: str = Field(
        default="",
        description="The tainted/attacker-influenced value the report describes, if any.",
    )
    source_type: str = Field(
        default="",
        description=(
            "The kind of source the report describes, e.g. FUNCTION_PARAMETER, "
            "NETWORK_READ, FILE_READ. Empty string if the report doesn't say."
        ),
    )
    attacker_control: str = Field(
        default="UNKNOWN",
        description=(
            "Whether the report claims this source is attacker-controlled: YES, NO, or "
            "UNKNOWN. Use UNKNOWN rather than inventing attacker controllability the "
            "report doesn't state."
        ),
    )
    sink_expression: str = Field(
        default="", description="The dangerous operation/call the report describes, if any."
    )
    sink_type: str = Field(
        default="",
        description=(
            "The kind of sink the report describes, e.g. MEMORY_WRITE, "
            "COMMAND_EXECUTION, AUTH_DECISION. Empty string if the report doesn't say."
        ),
    )
    security_condition: str = Field(
        description="The specific security-relevant condition the report asserts."
    )
    claimed_impact: str = Field(
        default="", description="The report's own description of consequence/impact, verbatim."
    )
    claimed_severity: str = Field(
        default="",
        description=(
            "The report's own severity label or score, verbatim, e.g. 'Critical', "
            "'CVSS 9.8', 'High'. Empty string if the report doesn't state one."
        ),
    )
    evidence_quote: str = Field(
        default="",
        description=(
            "The exact code listing, log excerpt, or other evidence text the report "
            "offers for this claim, verbatim. Empty string if the report offers none."
        ),
    )
    data_flow: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered source-to-sink steps IF the report itself describes them. Empty otherwise."
        ),
    )
    page_numbers: list[int] = Field(
        default_factory=list,
        description="1-indexed page number(s) within the source block this claim was found on.",
    )


class ClaimExtractionBatch(BaseModel):
    """The `with_structured_output(...)` target for one block of report text.

    A block usually yields zero or one claims; `claims` stays a list so a
    block that bundles multiple related claims (e.g. a summary table row
    covering several CVEs) isn't forced into one merged, lossy claim.
    """

    claims: list[ClaimExtraction] = Field(
        default_factory=list, description="Claims found in this block, if any."
    )
    not_a_finding: bool = Field(
        default=False,
        description=(
            "True if this block is prose, a table of contents, a disclosure timeline, "
            "boilerplate, or otherwise contains no vulnerability claim of its own."
        ),
    )


class ClaimRecord(BaseModel):
    """One claim's outcome as it passed through the ingestion driver.

    Distinct from `common.findings.ChunkAnalysisRecord`: this records a
    CLAIM's outcome (did it emit, did it resolve to a real binary), not a
    chunk's — Stage 3b never chunks decompiled code, it segments report text.
    """

    global_id: str
    """`f"{chunk_id}::{claim_id}"` — same format as
    `common.findings`-derived `global_id`s elsewhere in the pipeline."""
    claim_id: str
    chunk_id: str
    bin_id: str
    status: str = Field(
        description="One of: emitted (a valid AnalysisReport was written), "
        "failed (extraction or emission errored)."
    )
    binary_resolved: bool = False
    decision: str = ""
    findings_relpath: str | None = None
    """Path to `findings/<chunk_id>.json`, relative to `db_subfolder` — same
    relativity convention as `common.findings.ChunkAnalysisRecord.
    findings_relpath`. `None` when status != "emitted"."""
    error: str | None = None


class ClaimsRunSummary(BaseModel):
    """Stage 3b's machine-readable hand-off (`stage3b/claims_summary.json`),
    written by `stage3b_claims.driver.ingest_report()` itself — same
    "written by the orchestrator function, not only the CLI" discipline as
    `AnalysisRunSummary`. Best-effort (`except OSError: pass`), same as
    Stage 3's own summary writes; nothing downstream depends on this file
    existing — see that module's docstring.
    """

    schema_version: int = 1
    run_id: str | None = None
    status: str = Field(
        description="completed | no_claims | pdf_unreadable | extractor_unavailable"
    )
    db_subfolder: str
    source_pdf: str
    doc_stem: str
    model: str
    """The resolved `<provider>:<model>` actually used for extraction."""
    page_count: int = 0
    block_count: int = 0
    claims: list[ClaimRecord] = Field(default_factory=list)
    total_claims: int = 0
    total_emitted: int = 0
    total_failed: int = 0
    total_unresolved_binary: int = 0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime | None = None
