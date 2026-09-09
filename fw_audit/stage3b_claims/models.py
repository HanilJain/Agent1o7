"""Internal, in-process shapes for Stage 3b.

Frozen dataclasses, not Pydantic models — these never cross a
`with_structured_output` boundary and never get individually serialized to
disk (see `stage3_analysis.models`'s own docstring for the same
Pydantic-only-for-wire-contracts convention this package follows).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class PageText:
    """One page's extracted text, 1-indexed to match how a human reads the
    PDF and how a citation ("p. 7") should be reported back."""

    page_number: int
    text: str


@dataclass(frozen=True)
class DocumentText:
    """The full deterministic extraction of one PDF — `extractor.py`'s
    return value, and what `segmenter.segment()` consumes."""

    doc_stem: str
    """Filesystem-safe stem derived from the source PDF's filename,
    e.g. `acme_pentest_2026` from `ACME Pentest 2026.pdf`. Used to
    namespace `bin_id`/`chunk_id`/cached artifacts so ingesting two
    different reports against the same firmware never collides."""
    pages: tuple[PageText, ...]
    source_path: Path
    """Host-absolute path to the original PDF, kept for logging/debugging
    only — never persisted as a relative path since Stage 3b's own output
    doesn't need to reconstruct it."""


@dataclass(frozen=True)
class ClaimBlock:
    """One segment of report text `segmenter.segment()` believes contains
    at most a handful of related claims — the unit `agent/converter.py`
    sends to the LLM in a single call."""

    block_id: str
    """Stable within one `segment()` call, e.g. `block_0007` — used only
    for debug output and log correlation, never persisted into a `Finding`."""
    page_numbers: tuple[int, ...]
    text: str


@dataclass(frozen=True)
class BinaryResolution:
    """The deterministic outcome of matching a claim's free-text
    `binary_hint` against a firmware's real binaries — `resolve.py`'s
    return value for `resolve_binary()`."""

    bin_id: str | None
    """The matched `DecompiledBinary.bin_id`, or `None` if nothing matched
    (never a guess)."""
    matched_on: str = ""
    """Which matching tier hit, purely for debug/logging: 'rootfs_path' |
    'basename' | 'normalized_basename' | 'bin_id_substring' | ''."""


@dataclass(frozen=True)
class FunctionResolution:
    """The deterministic outcome of matching a claim's free-text
    `function_hint` against one binary's real Ghidra function table —
    `resolve.py`'s return value for `resolve_function()`."""

    function_name: str | None
    """The matched `GhidraFunction.name`, or `None` if nothing matched."""
    matched_on: str = ""
    """'exact' | 'case_insensitive' | 'entry_point_substring' | ''."""


@dataclass(frozen=True)
class EmittedClaim:
    """One claim's fully-resolved, ready-to-write result — `emit.py`'s
    return value, consumed by `driver.py` to build both the
    `AnalysisReport` JSON and the `ClaimRecord` bookkeeping row."""

    global_id: str
    chunk_id: str
    bin_id: str
    claim_id: str
    decision: str
    binary_resolved: bool
    report_json: str
    """The full serialized `common.findings.AnalysisReport` — one claim per
    file, so one bad claim can never take out a sibling's file (see
    `stage3b_claims/CLAUDE.md`'s framing of why this differs from Stage 3,
    which batches multiple findings per chunk into one file)."""


@dataclass(frozen=True)
class SegmenterConfig:
    """Bundles `segmenter.segment()`'s tunables so callers don't have to
    thread three separate primitives through; defaults mirror
    `Settings.stage3b_max_block_chars`."""

    max_block_chars: int = 12_000
    min_block_chars: int = 200
    extra_headings: tuple[str, ...] = field(default_factory=tuple)
