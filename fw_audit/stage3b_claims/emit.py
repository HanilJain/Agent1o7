"""Deterministic `ClaimExtraction` -> `common.findings.AnalysisReport`
expansion. Zero LLM calls.

This is where the narrow `ClaimExtraction` schema (the cheap LLM output)
becomes a full, schema-valid `Finding` (the shape Stage 4/5 already
consume) without spending a single extra token. Every unanswerable field
is filled HONESTLY — a placeholder that says "unknown" or "not stated" —
rather than invented; see each mapping below.

Two invariants this module enforces, both load-bearing for downstream
safety, and both intentional per the confirmed design:

* `Finding.confidence` is ALWAYS `MEDIUM`, never `CONFIRMED`/`HIGH`. This
  is an unverified third-party assertion — that's the entire premise of
  Stage 3b — so it must never present as strongly evidenced.
* `Finding.decision` is `ESCALATE` only when BOTH the binary and the
  function resolved against real Stage 2 output (see `resolve.py`).
  Otherwise it's `CONTEXT_REQUIRED`, which keeps the claim out of Stage
  5's `ESCALATE`-only default (`candidate_index.DEFAULT_DECISIONS`)
  instead of reaching `characterize_target`'s hard `Stage5InputError`
  ("target mismatch") for a function name Ghidra's table can't resolve.
"""

from __future__ import annotations

from fw_audit.common.claims import ClaimExtraction
from fw_audit.common.findings import (
    AnalysisReport,
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.stage3b_claims.models import BinaryResolution, EmittedClaim, FunctionResolution

_CHUNK_ORDINAL_BASE = 9000
"""Stage 3's own chunk ordinals are small sequential integers per binary
(`chunk.strategy.chunk_source`, format `<bin_id>#<ordinal:04d>`, starting
at 0). The 9000+ band is chosen so a Stage 3b-emitted `chunk_id` can never
collide with a real Stage 3 chunk for the same `bin_id` — a firmware would
need 9000+ chunks from one binary alone for that to become a risk, far
beyond anything `stage3_max_chunk_lines`/real chunking produces."""

_SEVERITY_TABLE: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
}


def _severity_from_claim(claimed_severity: str) -> Severity:
    """Deterministic keyword lookup on the report's OWN severity label —
    never an LLM judgment call. `exploitability`/`reachability` are fixed
    at 3 (the schema's midpoint) rather than guessed; `missing_context`
    (see `_missing_context`) records that these two axes are unassessed."""
    label = claimed_severity.strip().lower()
    impact = 3
    for keyword, score in _SEVERITY_TABLE.items():
        if keyword in label:
            impact = score
            break
    return Severity(impact=impact, exploitability=3, reachability=3)


def _bin_id_for(binary_hint: str, resolution: BinaryResolution) -> str:
    if resolution.bin_id:
        return resolution.bin_id
    hint = binary_hint.strip()
    if hint:
        slug = "".join(c if c.isalnum() else "_" for c in hint).strip("_") or "hint"
        return f"unresolved_{slug}"
    return "unresolved_unknown_binary"


def _missing_context(
    claim: ClaimExtraction,
    *,
    binary_resolution: BinaryResolution,
    function_resolution: FunctionResolution,
) -> list[str]:
    missing: list[str] = []
    if binary_resolution.bin_id is None:
        hint = claim.binary_hint or "(not stated by the report)"
        missing.append(f"Report-named binary {hint!r} did not resolve against Stage 2 output.")
    if function_resolution.function_name is None:
        hint = claim.function_hint or "(not stated by the report)"
        missing.append(
            f"Report-named function {hint!r} did not resolve against the binary's real "
            "Ghidra function table."
        )
    if not claim.evidence_quote.strip():
        missing.append("The report provided no code/log evidence for this claim.")
    missing.append(
        "severity.exploitability/reachability are unassessed placeholders (3/5) — this "
        "claim has not been independently evaluated."
    )
    return missing


def to_analysis_report(
    claim: ClaimExtraction,
    *,
    doc_stem: str,
    ordinal: int,
    binary_resolution: BinaryResolution,
    function_resolution: FunctionResolution,
) -> AnalysisReport:
    """Build one `AnalysisReport` (containing exactly one `Finding`) for a
    single extracted claim.

    One claim per `AnalysisReport`/file — see
    `stage3b_claims/CLAUDE.md`'s framing of why this differs from Stage 3
    (which batches several findings from one chunk into one report): a
    `ValidationError` on one bad file must never take out a sibling claim
    (see `stage5_verification.candidate_index.discover_candidates`'s
    per-file `except ... continue`).
    """
    bin_id = _bin_id_for(claim.binary_hint, binary_resolution)
    chunk_id = f"{bin_id}#{_CHUNK_ORDINAL_BASE + ordinal:04d}"

    both_resolved = (
        binary_resolution.bin_id is not None and function_resolution.function_name is not None
    )
    decision = Decision.ESCALATE if both_resolved else Decision.CONTEXT_REQUIRED

    function_id = function_resolution.function_name or claim.function_hint or ""
    pages = ", ".join(str(p) for p in claim.page_numbers) if claim.page_numbers else "?"
    code = (
        claim.evidence_quote
        if claim.evidence_quote.strip()
        else f"[no code evidence provided in {doc_stem} p.{pages}]"
    )

    tags = ["external_claim", f"doc:{doc_stem}"]
    tags.extend(f"page:{p}" for p in claim.page_numbers)
    tags.extend(claim.cve_ids)

    finding = Finding(
        finding_id=claim.claim_id,
        title=claim.title,
        category=claim.category,
        cwe=list(claim.cwe),
        severity=_severity_from_claim(claim.claimed_severity),
        confidence=Confidence.MEDIUM,
        decision=decision,
        tags=tags,
        evidence_span=EvidenceSpan(
            function_id=function_id,
            line_start=0,
            line_end=0,
            code=code,
        ),
        source=FindingSource(
            expression=claim.source_expression,
            type=claim.source_type,
            attacker_control=claim.attacker_control or "UNKNOWN",
        ),
        sink=FindingSink(
            expression=claim.sink_expression,
            type=claim.sink_type,
        ),
        data_flow=list(claim.data_flow),
        security_condition=claim.security_condition,
        exploitability=(
            f"As claimed by {doc_stem} (p.{pages}): "
            f"{claim.claimed_severity or 'no exploitability detail stated'}."
        ),
        impact=claim.claimed_impact or "Not stated by the report.",
        why_vulnerable=claim.security_condition,
        why_not_false_positive=(
            f"Unverified third-party claim transcribed from {doc_stem!r} (p.{pages}). "
            "Grounded only in the report's own assertion, not independently confirmed "
            "against source or binary — verification pending via Stage 4/5."
        ),
        missing_context=_missing_context(
            claim, binary_resolution=binary_resolution, function_resolution=function_resolution
        ),
        recommended_next_analysis=[
            "Run `fw-trace run --claims` to retrieve corroborating rootfs/decompiled context.",
            "Run `fw-verify run --claims` to attempt Joern static / QEMU+GDB dynamic verification.",
        ],
    )

    report = AnalysisReport(
        chunk_id=chunk_id,
        function_id=function_id,
        findings=[finding],
        checked_categories=[],
        analysis_limitations=[
            f"Derived from an external claim in {doc_stem!r}, page(s) {pages} — not "
            "independently analyzed by this pipeline."
        ],
    )

    return report


def to_emitted_claim(
    report: AnalysisReport, *, global_id: str, bin_id: str, binary_resolved: bool
) -> EmittedClaim:
    """Wrap a built `AnalysisReport` (exactly one `Finding`) plus its
    bookkeeping metadata into the `EmittedClaim` `driver.py` writes out."""
    finding = report.findings[0]
    return EmittedClaim(
        global_id=global_id,
        chunk_id=report.chunk_id,
        bin_id=bin_id,
        claim_id=finding.finding_id,
        decision=finding.decision.value,
        binary_resolved=binary_resolved,
        report_json=report.model_dump_json(indent=2),
    )
