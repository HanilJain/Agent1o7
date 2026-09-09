"""Stage 3b's entry point: `ingest_report()`.

Sequence: extract (deterministic) -> cache page text -> segment
(deterministic) -> bounded concurrent extraction over blocks -> resolve
each claim against Stage 2 (deterministic) -> emit an `AnalysisReport` per
claim (deterministic) -> write. Only the extraction step calls an LLM.

Deliberately NOT `stage3_analysis.chunk_queue.ChunkQueue` — that machinery
exists to bound memory for a firmware's entire (potentially huge) chunk
set, persisted to disk as the queue's own source of truth. Stage 3b has no
such problem: one PDF's claim blocks are already in memory, already
bounded by the document's own size. A plain `asyncio.Semaphore`-bounded
pool over `asyncio.gather` is enough concurrency control.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from fw_audit.common.claims import ClaimRecord, ClaimsRunSummary
from fw_audit.common.schemas import ExtractionStatus, Stage2Summary
from fw_audit.config.llm_config import AgentRole, resolve_usable_spec
from fw_audit.config.settings import Settings
from fw_audit.observability import span, trace_context
from fw_audit.stage3b_claims import layout
from fw_audit.stage3b_claims.agent.converter import extract_claims
from fw_audit.stage3b_claims.emit import to_analysis_report, to_emitted_claim
from fw_audit.stage3b_claims.errors import ClaimExtractionUnavailableError
from fw_audit.stage3b_claims.extractor import doc_stem as compute_doc_stem
from fw_audit.stage3b_claims.extractor import extract_document
from fw_audit.stage3b_claims.models import (
    ClaimBlock,
    DocumentText,
    FunctionResolution,
    PageText,
    SegmenterConfig,
)
from fw_audit.stage3b_claims.resolve import resolve_binary, resolve_function
from fw_audit.stage3b_claims.segmenter import segment
from fw_audit.stage5_verification.candidate_index import load_stage2_summary
from fw_audit.stage5_verification.errors import Stage5InputError

logger = logging.getLogger("fw_audit.stage3b_claims")


class ExtractorModelUnavailableError(RuntimeError):
    """Raised before any block is processed: the extractor model/credential
    couldn't be resolved at all. Mirrors
    `stage3_analysis.agent.orchestrator.AnalystModelUnavailableError`'s
    contract — distinct from a per-claim `ClaimExtractionUnavailableError`
    (which is recorded as a failed `ClaimRecord`, not raised)."""


def _load_cached_pages(path: Path) -> tuple[PageText, ...] | None:
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return tuple(PageText(page_number=p["page_number"], text=p["text"]) for p in raw)
    except (KeyError, TypeError):
        return None


def _write_pages_cache(path: Path, pages: tuple[PageText, ...]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = [{"page_number": p.page_number, "text": p.text} for p in pages]
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.warning("could not write page-text cache %s: %s", path, exc)


async def _process_block(
    block: ClaimBlock,
    *,
    ordinal_start: int,
    doc_stem: str,
    db_subfolder: Path,
    findings_dir_: Path,
    stage2_summary,
    settings: Settings,
    semaphore: asyncio.Semaphore,
) -> tuple[list[ClaimRecord], int]:
    """Process one claim block end to end: extract -> resolve -> emit ->
    write. Returns the `ClaimRecord`s produced (0+, one per claim in the
    block) and the number of ordinals consumed (for the caller's running
    counter — needed even on failure so a later block's chunk_id ordinals
    never collide with an earlier block's).
    """
    async with semaphore:
        with trace_context(stage="3b", global_id=block.block_id), span(
            "stage3b.claim_block",
            run_type="chain",
            inputs={"block_id": block.block_id, "chars": len(block.text)},
        ) as run:
            try:
                batch = await asyncio.wait_for(
                    extract_claims(block, doc_stem=doc_stem, settings=settings),
                    timeout=settings.stage3b_llm_timeout_seconds,
                )
            except TimeoutError:
                if run is not None:
                    run.end(error="timeout")
                logger.warning(
                    "block %s: extractor timed out after %ds",
                    block.block_id,
                    settings.stage3b_llm_timeout_seconds,
                )
                timeout_s = settings.stage3b_llm_timeout_seconds
                return (
                    [
                        ClaimRecord(
                            global_id=f"{block.block_id}::timeout",
                            claim_id="",
                            chunk_id="",
                            bin_id="",
                            status="failed",
                            error=f"extractor timed out after {timeout_s}s",
                        )
                    ],
                    0,
                )
            except ClaimExtractionUnavailableError as exc:
                if run is not None:
                    run.end(error=str(exc))
                logger.warning("block %s: extraction failed: %s", block.block_id, exc)
                return (
                    [
                        ClaimRecord(
                            global_id=f"{block.block_id}::failed",
                            claim_id="",
                            chunk_id="",
                            bin_id="",
                            status="failed",
                            error=str(exc),
                        )
                    ],
                    0,
                )

            if run is not None:
                run.end(outputs={"claim_count": len(batch.claims)})

            if not batch.claims:
                return [], 0

            records: list[ClaimRecord] = []
            findings_dir_.mkdir(parents=True, exist_ok=True)
            for i, claim in enumerate(batch.claims):
                ordinal = ordinal_start + i
                binary_resolution = resolve_binary(claim.binary_hint, stage2_summary=stage2_summary)
                if binary_resolution.bin_id:
                    function_resolution = resolve_function(
                        claim.function_hint,
                        functions=_functions_for(binary_resolution.bin_id, stage2_summary),
                    )
                else:
                    function_resolution = FunctionResolution(function_name=None)
                # Backfill page_numbers if the model omitted them.
                if not claim.page_numbers:
                    claim = claim.model_copy(update={"page_numbers": list(block.page_numbers)})

                try:
                    report = to_analysis_report(
                        claim,
                        doc_stem=doc_stem,
                        ordinal=ordinal,
                        binary_resolution=binary_resolution,
                        function_resolution=function_resolution,
                    )
                except (ValidationError, ValueError) as exc:
                    logger.warning(
                        "block %s claim %s: emission failed: %s",
                        block.block_id,
                        claim.claim_id,
                        exc,
                    )
                    records.append(
                        ClaimRecord(
                            global_id=f"{block.block_id}::{claim.claim_id}",
                            claim_id=claim.claim_id,
                            chunk_id="",
                            bin_id="",
                            status="failed",
                            error=str(exc),
                        )
                    )
                    continue

                emitted = to_emitted_claim(
                    report,
                    global_id=f"{report.chunk_id}::{claim.claim_id}",
                    bin_id=report.chunk_id.rpartition("#")[0],
                    binary_resolved=binary_resolution.bin_id is not None,
                )
                target_path = findings_dir_ / layout.finding_filename(emitted.chunk_id)
                try:
                    await asyncio.to_thread(
                        target_path.write_text, emitted.report_json, encoding="utf-8"
                    )
                except OSError as exc:
                    logger.warning(
                        "block %s claim %s: could not write %s: %s",
                        block.block_id,
                        claim.claim_id,
                        target_path,
                        exc,
                    )
                    records.append(
                        ClaimRecord(
                            global_id=emitted.global_id,
                            claim_id=emitted.claim_id,
                            chunk_id=emitted.chunk_id,
                            bin_id=emitted.bin_id,
                            status="failed",
                            error=str(exc),
                        )
                    )
                    continue

                records.append(
                    ClaimRecord(
                        global_id=emitted.global_id,
                        claim_id=emitted.claim_id,
                        chunk_id=emitted.chunk_id,
                        bin_id=emitted.bin_id,
                        status="emitted",
                        binary_resolved=emitted.binary_resolved,
                        decision=emitted.decision,
                        findings_relpath=str(target_path.relative_to(db_subfolder)),
                    )
                )
            return records, len(batch.claims)


def _functions_for(bin_id: str | None, stage2_summary) -> tuple:
    if bin_id is None:
        return ()
    for binary in stage2_summary.binaries:
        if binary.bin_id == bin_id:
            return tuple(binary.functions)
    return ()


def _write_summary(db_subfolder: Path, summary: ClaimsRunSummary) -> None:
    stage3b_dir_ = layout.stage3b_dir(db_subfolder)
    path = layout.claims_summary_path(stage3b_dir_)
    try:
        stage3b_dir_.mkdir(parents=True, exist_ok=True)
        path.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    except OSError as exc:
        logger.warning("could not write %s: %s", path, exc)


async def ingest_report(
    pdf_path: Path,
    *,
    db_subfolder: Path,
    settings: Settings,
    run_id: str | None = None,
    pages: str | None = None,
    write_debug_blocks: bool = False,
) -> ClaimsRunSummary:
    """Ingest one PDF report end to end: extract, segment, extract claims
    per block (LLM), resolve, emit, write. Always writes
    `stage3b/claims_summary.json` itself (best-effort — see
    `layout.claims_summary_path`'s docstring), same discipline as Stage 3's
    `run_analysis()`.

    Raises `Stage3bInputError` if the PDF can't be read/parsed.
    Raises `ExtractorModelUnavailableError` if the configured extractor
    model can't be resolved at all — checked up front, before segmenting,
    same "fail fast" precedent as Stage 3's `AnalystModelUnavailableError`.
    A missing `stage2/stage2_summary.json` does NOT raise: binary/function
    resolution simply comes back empty for every claim (recorded honestly
    via `missing_context`), since Stage 3b's whole point is to work even
    when Stage 2 hasn't run over a report's binaries yet.
    """
    run_id = run_id or uuid.uuid4().hex[:12]
    started_at = datetime.now(UTC)

    try:
        spec = resolve_usable_spec(AgentRole.STAGE3B_CLAIM_EXTRACTOR, settings=settings)
    except ValueError as exc:
        raise ExtractorModelUnavailableError(str(exc)) from exc
    model_label = f"{spec.provider.value}:{spec.model}"

    stage3b_dir_ = layout.stage3b_dir(db_subfolder)
    source_dir_ = layout.source_dir(stage3b_dir_)

    doc_stem = compute_doc_stem(pdf_path)
    cache_path = layout.pages_cache_path(source_dir_, doc_stem)
    cached_pages = _load_cached_pages(cache_path)
    if cached_pages is not None and pages is None:
        document = DocumentText(
            doc_stem=doc_stem, pages=cached_pages, source_path=pdf_path.resolve()
        )
    else:
        document = extract_document(pdf_path, pages=pages)
        if pages is None:
            _write_pages_cache(cache_path, document.pages)

    blocks = segment(
        document, config=SegmenterConfig(max_block_chars=settings.stage3b_max_block_chars)
    )

    if write_debug_blocks:
        debug_dir_ = layout.debug_dir(stage3b_dir_)
        debug_path = layout.blocks_debug_path(debug_dir_, doc_stem)
        try:
            debug_dir_.mkdir(parents=True, exist_ok=True)
            payload = [
                {"block_id": b.block_id, "page_numbers": list(b.page_numbers), "chars": len(b.text)}
                for b in blocks
            ]
            debug_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError as exc:
            logger.warning("could not write %s: %s", debug_path, exc)

    if not blocks:
        summary = ClaimsRunSummary(
            run_id=run_id,
            status="no_claims",
            db_subfolder=str(db_subfolder),
            source_pdf=str(pdf_path),
            doc_stem=doc_stem,
            model=model_label,
            page_count=len(document.pages),
            block_count=0,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )
        _write_summary(db_subfolder, summary)
        return summary

    stage2_dir = db_subfolder / "stage2"
    try:
        stage2_summary = load_stage2_summary(stage2_dir)
    except Stage5InputError as exc:
        logger.warning(
            "no usable stage2_summary.json at %s (%s) — every claim's binary/function "
            "resolution will come back empty",
            stage2_dir,
            exc,
        )
        stage2_summary = None

    if stage2_summary is None:
        stage2_summary = Stage2Summary(
            run_id="unavailable",
            status=ExtractionStatus.COMPLETED,
            db_subfolder=str(db_subfolder),
            rootfs_dir="",
            stage2_dir=str(stage2_dir),
            ghidra_image="",
            binaries=[],
            started_at=started_at,
        )

    findings_dir_ = layout.findings_dir(stage3b_dir_)
    semaphore = asyncio.Semaphore(settings.stage3b_workers)

    ordinal = 0
    all_records: list[ClaimRecord] = []
    with trace_context(stage="3b", run_id=run_id, model=model_label):
        tasks = []
        for block in blocks:
            tasks.append(
                _process_block(
                    block,
                    ordinal_start=ordinal,
                    doc_stem=doc_stem,
                    db_subfolder=db_subfolder,
                    findings_dir_=findings_dir_,
                    stage2_summary=stage2_summary,
                    settings=settings,
                    semaphore=semaphore,
                )
            )
            # Reserve a generous ordinal window per block up front so
            # concurrent tasks never race over the same chunk_id ordinal —
            # a block yields "a handful" of claims in practice; 100 is a
            # deliberately large safety margin, not a tuned estimate.
            ordinal += 100

        results = await asyncio.gather(*tasks)
        for records, _consumed in results:
            all_records.extend(records)

    total_emitted = sum(1 for r in all_records if r.status == "emitted")
    total_failed = sum(1 for r in all_records if r.status == "failed")
    total_unresolved_binary = sum(
        1 for r in all_records if r.status == "emitted" and not r.binary_resolved
    )

    summary = ClaimsRunSummary(
        run_id=run_id,
        status="completed",
        db_subfolder=str(db_subfolder),
        source_pdf=str(pdf_path),
        doc_stem=doc_stem,
        model=model_label,
        page_count=len(document.pages),
        block_count=len(blocks),
        claims=all_records,
        total_claims=len(all_records),
        total_emitted=total_emitted,
        total_failed=total_failed,
        total_unresolved_binary=total_unresolved_binary,
        started_at=started_at,
        finished_at=datetime.now(UTC),
    )
    _write_summary(db_subfolder, summary)
    return summary
