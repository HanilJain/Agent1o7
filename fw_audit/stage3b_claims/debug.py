"""Debug module — inspect Stage 3b's deterministic (zero-LLM) steps in
isolation, without spending a single token.

`debug_extract` and `debug_segment` never touch an LLM or a credential at
all — they exist specifically so a report's extraction/segmentation
quality (and the resulting token cost, via block count x size) can be
checked BEFORE running `fw-claims ingest` for real. `debug_resolve`
likewise never calls an LLM; it exercises `resolve.py` directly against a
synthetic hint pair.

Wired into `runner.py debug {extract,segment,resolve}`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fw_audit.stage3b_claims.extractor import extract_document
from fw_audit.stage3b_claims.models import ClaimBlock, DocumentText, SegmenterConfig
from fw_audit.stage3b_claims.resolve import resolve_binary, resolve_function
from fw_audit.stage3b_claims.segmenter import segment
from fw_audit.stage5_verification.candidate_index import load_stage2_summary
from fw_audit.stage5_verification.errors import Stage5InputError


def debug_extract(pdf_path: Path, *, pages: str | None = None) -> DocumentText:
    """Run `extractor.extract_document` and return its result directly —
    zero tokens, no `db_subfolder` needed."""
    return extract_document(pdf_path, pages=pages)


@dataclass(frozen=True)
class BlockSummary:
    block_id: str
    page_numbers: tuple[int, ...]
    chars: int
    preview: str


def debug_segment(
    pdf_path: Path, *, pages: str | None = None, max_block_chars: int = 12_000
) -> tuple[BlockSummary, ...]:
    """Run extraction then segmentation and report block count/sizes —
    zero tokens. `chars` summed across the result is the direct proxy for
    what a real `fw-claims ingest` run against this document would spend:
    each block becomes exactly one LLM call in `driver._process_block`."""
    document = extract_document(pdf_path, pages=pages)
    blocks: tuple[ClaimBlock, ...] = segment(
        document, config=SegmenterConfig(max_block_chars=max_block_chars)
    )
    return tuple(
        BlockSummary(
            block_id=b.block_id,
            page_numbers=b.page_numbers,
            chars=len(b.text),
            preview=b.text[:200].replace("\n", " "),
        )
        for b in blocks
    )


@dataclass(frozen=True)
class ResolveResult:
    binary_hint: str
    function_hint: str
    bin_id: str | None
    binary_matched_on: str
    function_name: str | None
    function_matched_on: str


def debug_resolve(
    *, db_subfolder: Path, binary_hint: str, function_hint: str
) -> ResolveResult:
    """Run `resolve.resolve_binary`/`resolve_function` against
    `<db_subfolder>/stage2/stage2_summary.json` for one synthetic hint
    pair — zero tokens. Useful for checking whether a report's naming
    convention will actually resolve before running a full ingest."""
    try:
        stage2_summary = load_stage2_summary(db_subfolder / "stage2")
    except Stage5InputError as exc:
        return ResolveResult(
            binary_hint=binary_hint,
            function_hint=function_hint,
            bin_id=None,
            binary_matched_on=f"(no usable stage2_summary.json: {exc})",
            function_name=None,
            function_matched_on="",
        )

    binary_resolution = resolve_binary(binary_hint, stage2_summary=stage2_summary)
    functions: tuple = ()
    if binary_resolution.bin_id:
        for binary in stage2_summary.binaries:
            if binary.bin_id == binary_resolution.bin_id:
                functions = tuple(binary.functions)
                break
    function_resolution = resolve_function(function_hint, functions=functions)

    return ResolveResult(
        binary_hint=binary_hint,
        function_hint=function_hint,
        bin_id=binary_resolution.bin_id,
        binary_matched_on=binary_resolution.matched_on,
        function_name=function_resolution.function_name,
        function_matched_on=function_resolution.matched_on,
    )
