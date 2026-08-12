"""Step 1 orchestrator: turn Stage 1's whitelist and Stage 2's verified
index into an `IngestionReport` — the list of files Component 1's later
steps (clean, chunk, queue) will actually operate on.

Synchronous — there is no I/O concurrency worth having at this scale (a
handful of JSON reads and file stats per binary); `async` arrives naturally
in Step 4 with the chunk queue, not here.

Failure contract: `ingest()` raises `Stage3InputError` only while loading
Stage 1's/Stage 2's hand-offs and resolving the mirror tree (irrecoverable
— there's nothing to report on without them). Every per-binary problem
past that point becomes a `SkippedTarget`, never a raised exception — a run
where every whitelisted binary is skipped still returns a valid, empty-
targets `IngestionReport`, exactly as `stage2_extraction.resolve` never
fails the whole run over one bad path.

Reason codes recorded in `SkippedTarget.reason`, extending
`whitelist.join_targets`'s `"not_in_stage2"`/`"unresolved_upstream"`:

    not_in_stage2        whitelisted, but absent from both binaries[] and
                          unresolved[] (e.g. Stage 2 ran with --only)
    unresolved_upstream   matched an UnresolvedBinaryRecord; detail = problem
    decompile_failed      DecompiledBinary.status is failed/skipped
    artifact_missing_on_disk   locate_source() found nothing on disk
    empty_source          resolved file exists but is 0 bytes

When `settings.stage3_debug_dump` is true (the CLI's `--debug` flag threads
this through), `ingest()` additionally writes a verbatim copy of every
`Target`'s resolved source under `stage3/debug/<bin_id>.c` — purely for
manual testing/verification that Step 1 picked the right file — and, if
`tree-sitter`/`tree-sitter-c` are installed (the `stage3` extra), Step 2's
function-only extraction of that same source under
`stage3/debug/<bin_id>.cleaned.c`. Both are the ONE exception to "never
writes into stage2/ or the mirror tree" in the sense that they read from
the mirror tree, but the write itself still only ever lands under Stage
3's own `stage3/debug/` directory. Missing the `stage3` extra degrades
gracefully — a single warning is logged and the cleaned dump is skipped;
the raw dump and `ingestion_report.json` are unaffected.

Independently, when `settings.stage3_chunk_debug_dump` is true (the CLI's
`--debug-chunks` flag), `ingest()` chunks every `Target`'s function-only
extraction via `chunk.strategy.chunk_source` and writes one file per
`Chunk` under `stage3/chunks/<chunk_id>.c`. This is a SEPARATE flag from
`stage3_debug_dump` above — either may be set alone or together — since
dumping chunk payloads and dumping raw/cleaned source answer different
questions. Same missing-`stage3`-extra degradation as the cleaned dump.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fw_audit.common.schemas import DecompilationStatus, DecompiledBinary
from fw_audit.config.settings import Settings, get_settings
from fw_audit.stage2_extraction.normalize.context import build_context
from fw_audit.stage2_extraction.stage1_io import load_stage1_summary
from fw_audit.stage3_analysis import discover, layout
from fw_audit.stage3_analysis.chunk.strategy import chunk_source
from fw_audit.stage3_analysis.clean.extract import extract_functions
from fw_audit.stage3_analysis.errors import Stage3InputError
from fw_audit.stage3_analysis.models import IngestionReport, SkippedTarget, Target
from fw_audit.stage3_analysis.stage2_io import (
    load_stage2_summary,
    resolve_decompiled_tree_dir,
    resolve_stage2_summary_path,
)
from fw_audit.stage3_analysis.whitelist import build_whitelist, join_targets

logger = logging.getLogger("fw_audit.stage3_analysis")

#: A binary whose Stage 2 decompilation only partially completed still has
#: usable C for some functions — worth analyzing, unlike FAILED/SKIPPED/
#: TIMED_OUT, which have none.
_USABLE_STATUSES = frozenset({DecompilationStatus.SUCCEEDED, DecompilationStatus.PARTIAL})


def ingest(
    *,
    stage1_summary_path: Path,
    only: tuple[str, ...] = (),
    settings: Settings | None = None,
) -> IngestionReport:
    """Run Step 1 end to end and write `ingestion_report.json`.

    Written by this function itself (not only by the CLI) so a programmatic
    caller — a future Component 2 — invoking `ingest()` directly still gets
    a report, mirroring why `run_extraction()` writes `stage2_summary.json`
    itself rather than leaving that to `runner.py`.
    """
    settings = settings or get_settings()

    stage1 = load_stage1_summary(stage1_summary_path)
    stage2_summary_path = resolve_stage2_summary_path(stage1_summary_path)
    stage2 = load_stage2_summary(stage2_summary_path)

    tree_resolution = resolve_decompiled_tree_dir(stage2)
    tree_dir = tree_resolution.tree_dir
    warnings = list(tree_resolution.warnings)

    whitelist = build_whitelist(stage1, only)
    join_result = join_targets(whitelist, stage2)

    targets: list[Target] = []
    skipped: list[SkippedTarget] = list(join_result.skipped)

    for binary in join_result.matched:
        target, skip = _resolve_target(binary, tree_dir)
        if target is not None:
            targets.append(target)
        else:
            assert skip is not None
            skipped.append(skip)

    claimed = {t.source_path for t in targets}
    all_tree_files = discover.scan_tree(tree_dir)
    orphans = tuple(
        sorted(p.relative_to(tree_dir).as_posix() for p in all_tree_files if p not in claimed)
    )

    db_subfolder = Path(stage1.db_subfolder)
    report = IngestionReport(
        db_subfolder=db_subfolder,
        decompiled_tree_dir=tree_dir,
        targets=tuple(targets),
        skipped=tuple(skipped),
        orphans=orphans,
        warnings=tuple(warnings),
    )

    _write_report(report, settings)
    if settings.stage3_debug_dump:
        _write_debug_sources(report)
        _write_cleaned_debug_sources(report)
    if settings.stage3_chunk_debug_dump:
        _write_chunk_debug_sources(report, settings)
    return report


def _resolve_target(
    binary: DecompiledBinary, tree_dir: Path
) -> tuple[Target | None, SkippedTarget | None]:
    """One matched Stage 2 binary -> `(Target, None)` or `(None, SkippedTarget)`.

    Never raises: any problem here is reported, not propagated, per this
    module's failure contract."""
    if binary.status not in _USABLE_STATUSES:
        return None, SkippedTarget(
            requested_path=binary.requested_path,
            reason="decompile_failed",
            detail=f"status={binary.status.value}",
        )

    source_path = discover.locate_source(binary, tree_dir)
    if source_path is None:
        return None, SkippedTarget(
            requested_path=binary.requested_path,
            reason="artifact_missing_on_disk",
            detail=f"rootfs_path={binary.rootfs_path!r}",
        )

    try:
        size_bytes = source_path.stat().st_size
    except OSError as exc:
        return None, SkippedTarget(
            requested_path=binary.requested_path,
            reason="artifact_missing_on_disk",
            detail=str(exc),
        )

    if size_bytes == 0:
        return None, SkippedTarget(
            requested_path=binary.requested_path,
            reason="empty_source",
            detail=str(source_path),
        )

    target = Target(
        bin_id=binary.bin_id,
        rootfs_path=binary.rootfs_path,
        requested_path=binary.requested_path,
        aliases=tuple(binary.aliases),
        sha256=binary.sha256,
        source_path=source_path,
        source_relpath=source_path.relative_to(tree_dir).as_posix(),
        size_bytes=size_bytes,
        status=binary.status,
        function_count=binary.function_count,
        functions=tuple(binary.functions),
    )
    return target, None


def _write_report(report: IngestionReport, settings: Settings) -> None:
    """Best-effort write of `ingestion_report.json`. Never raises — matching
    `extract.py::_write_normalization_report`'s discipline: a report write
    failure is recoverable (the caller already has the in-memory
    `IngestionReport`), not a reason to fail the whole ingestion."""
    stage3_dir = layout.stage3_dir(report.db_subfolder)
    try:
        stage3_dir.mkdir(parents=True, exist_ok=True)
        layout.ingestion_report_path(stage3_dir).write_text(
            json.dumps(report.to_json_dict(), indent=2), encoding="utf-8"
        )
    except OSError:
        pass


def _write_debug_sources(report: IngestionReport) -> None:
    """`--debug`/`FWA_STAGE3_DEBUG_DUMP` only: write a verbatim copy of
    every `Target`'s resolved source to `stage3/debug/<bin_id>.c`, for
    manual testing/verification that Step 1 located the right file.

    Best-effort per file, matching `_write_report`'s discipline — one
    unreadable/unwritable target doesn't abort the others or fail the run.
    Read-only against the mirror tree: this only ever copies bytes out of
    it, never modifies anything there.
    """
    if not report.targets:
        return
    debug_dir = layout.debug_dir(layout.stage3_dir(report.db_subfolder))
    try:
        debug_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    for target in report.targets:
        dest = layout.debug_source_path(debug_dir, target.bin_id)
        try:
            dest.write_bytes(target.source_path.read_bytes())
        except OSError:
            continue


def _write_cleaned_debug_sources(report: IngestionReport) -> None:
    """`--debug`/`FWA_STAGE3_DEBUG_DUMP` only: write each `Target`'s
    function-only extraction (Step 2's `clean.extract.extract_functions`)
    to `stage3/debug/<bin_id>.cleaned.c` — additive to the raw dump
    `_write_debug_sources` already wrote, never replacing it.

    Degrades gracefully if `tree-sitter`/`tree-sitter-c` (the `stage3`
    extra) aren't installed: `extract_functions` raises `Stage3InputError`
    from `clean.parser.get_parser()` in that case, caught here once per
    call (not once per target — no point re-attempting a known-missing
    import 2,000 times) with a single warning logged. The raw dump and
    `ingestion_report.json` must keep working unconditionally either way.
    """
    if not report.targets:
        return
    debug_dir = layout.debug_dir(layout.stage3_dir(report.db_subfolder))
    try:
        debug_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return

    for target in report.targets:
        try:
            text = target.source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            context = build_context(target.functions)
            result = extract_functions(text, bin_id=target.bin_id, context=context)
        except Stage3InputError as exc:
            logger.warning("cleaned debug dump skipped: %s", exc)
            return
        dest = layout.debug_cleaned_source_path(debug_dir, target.bin_id)
        try:
            dest.write_text(result.to_text(), encoding="utf-8")
        except OSError:
            continue


def _write_chunk_debug_sources(report: IngestionReport, settings: Settings) -> None:
    """`--debug-chunks`/`FWA_STAGE3_CHUNK_DEBUG_DUMP` only: chunk each
    `Target`'s function-only extraction (Step 2's `clean.extract.
    extract_functions`) via `chunk.strategy.chunk_source`, then write one
    file per `Chunk` to `stage3/chunks/<chunk_id>.c` (via `layout.
    chunks_dir()`/`layout.chunk_filename()`).

    Independent of `settings.stage3_debug_dump` — see `Settings.
    stage3_chunk_debug_dump`'s docstring for why these are two separate
    flags. Re-parses/re-extracts each target's source independently of
    `_write_cleaned_debug_sources` rather than sharing its result: both
    functions are best-effort and independently gated, and either may run
    alone or together in the same `ingest()` call depending on which
    flags the caller passed — sharing state between them would couple two
    paths that each need to keep working correctly in isolation. The
    re-parse cost is the same order of magnitude as
    `_write_cleaned_debug_sources`'s own (one `extract_functions` call per
    target), not a new scaling concern.

    Degrades gracefully exactly like `_write_cleaned_debug_sources`:
    `extract_functions` raises `Stage3InputError` once tree-sitter/
    tree-sitter-c aren't installed, caught here once per call (not once
    per target), with a single warning logged. The raw dump, cleaned
    dump, and `ingestion_report.json` must keep working unconditionally
    either way.
    """
    if not report.targets:
        return
    chunks_dir = layout.chunks_dir(layout.stage3_dir(report.db_subfolder))
    try:
        chunks_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return

    for target in report.targets:
        try:
            text = target.source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            context = build_context(target.functions)
            source = extract_functions(text, bin_id=target.bin_id, context=context)
        except Stage3InputError as exc:
            logger.warning("chunk debug dump skipped: %s", exc)
            return
        chunks = chunk_source(
            source,
            bin_id=target.bin_id,
            rootfs_path=target.rootfs_path,
            source_relpath=target.source_relpath,
            chunk_lines=settings.stage3_chunk_lines,
            max_chunk_lines=settings.stage3_max_chunk_lines,
        )
        for chunk in chunks:
            dest = chunks_dir / layout.chunk_filename(chunk.chunk_id)
            try:
                dest.write_text(chunk.to_text(), encoding="utf-8")
            except OSError:
                continue


__all__ = ["ingest"]
