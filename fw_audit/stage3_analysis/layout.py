"""Pure path algebra for Stage 3's own on-disk output.

Same discipline as `stage2_extraction.layout`: every function here takes
paths in, returns paths out — no filesystem I/O, no `mkdir`. Callers create
directories at the point they actually write into them.

Layout, under `<db_subfolder>/stage3/`::

    ingestion_report.json
    stage3_summary.json      (written by chunk_queue.run_queue(), --queue)
    debug/<bin_id>.c              (--debug only; Step 1's raw resolved-source
                                    dump — see debug_dir/debug_source_path)
    debug/<bin_id>.cleaned.c       (--debug only; Step 2's function-only
                                    extraction — see debug_cleaned_source_path)
    chunks/<chunk_id>.c       (Step 3's chunk-payload location — see
                                chunks_dir/chunk_filename)

`debug/` and `chunks/` are deliberately separate: `debug/` holds up to two files
per `Target` (raw + cleaned, answering different questions — see each path
function's docstring), reserved for manual testing/verification. `chunks/`
holds one file per `Chunk`, written from TWO independent sources that land
identical, deterministic content for the same `chunk_id`: `ingest.
_write_chunk_debug_sources` under `--debug-chunks` (manual dump), and
`chunk_queue.ChunkQueue.put()` under `--queue` (Step 4's production
persistence — the queue's own source of truth, never held in memory as a
`Chunk` object once written). Don't conflate `debug/` and `chunks/`.

For everything under `<db_subfolder>/stage2/` and the sibling decompiled
mirror tree, reuse `fw_audit.stage2_extraction.layout` directly rather than
duplicating its path algebra here — see `stage2_io.py` and `discover.py`.
"""

from __future__ import annotations

from pathlib import Path


def stage3_dir(db_subfolder: Path) -> Path:
    return db_subfolder / "stage3"


def ingestion_report_path(stage3_dir_: Path) -> Path:
    return stage3_dir_ / "ingestion_report.json"


def stage3_summary_path(stage3_dir_: Path) -> Path:
    """Written by `chunk_queue.run_queue()` itself (mirroring
    `Stage2Summary`'s own precedent of being written by its orchestrator
    function, not only a CLI wrapper) — see `common.schemas.Stage3Summary`."""
    return stage3_dir_ / "stage3_summary.json"


def debug_dir(stage3_dir_: Path) -> Path:
    """`--debug`-only dump location for Step 1's resolved-source verbatim
    copies (one `.c` per `Target`, written by `ingest.py` when
    `Settings.stage3_debug_dump` is true). Purely for manual testing/
    verification — never read back by any later step."""
    return stage3_dir_ / "debug"


def debug_source_path(debug_dir_: Path, bin_id: str) -> Path:
    """`bin_id` is already filesystem-safe (`_SAFE_NAME_RE`-sanitized by
    `stage2_extraction.layout.bin_id`), so no further escaping is needed.
    The RAW verbatim copy of `Target.source_path` — verifies Step 1's file
    resolution. See `debug_cleaned_source_path` for Step 2's counterpart."""
    return debug_dir_ / f"{bin_id}.c"


def debug_cleaned_source_path(debug_dir_: Path, bin_id: str) -> Path:
    """Step 2's function-only `ExtractedSource.to_text()` dump — verifies
    extraction, not file resolution (see `debug_source_path`). Additive:
    both files coexist for the same `bin_id`, answering different
    questions side by side."""
    return debug_dir_ / f"{bin_id}.cleaned.c"


def chunks_dir(stage3_dir_: Path) -> Path:
    """Chunk-payload directory, written from two independent call sites —
    see this module's docstring: `ingest._write_chunk_debug_sources`
    (`--debug-chunks`, manual testing/verification only) and
    `chunk_queue.ChunkQueue.put()` (`--queue`, Step 4's actual production
    persistence — every `ChunkHandle` a consumer receives points here via
    `ChunkHandle.chunk_path`, since the queue itself never holds a
    `Chunk`'s text in memory). Both write identical, deterministic content
    for the same `chunk_id`, so running both flags together never
    conflicts. Unrelated to `debug_dir` above, which is Step 1/2's own
    per-target debug dump, not a per-chunk one."""
    return stage3_dir_ / "chunks"


def chunk_filename(chunk_id: str) -> str:
    """`chunk_id` (produced by `chunk.strategy.chunk_source`, format
    `<bin_id>#<ordinal:04d>`) is already filesystem-safe by construction
    (`bin_id` is itself `_SAFE_NAME_RE`-sanitized by
    `stage2_extraction.layout.bin_id`), so this only needs to swap the `#`
    Step 3 uses as a human-readable separator for something that isn't
    awkward in a Windows filename."""
    return f"{chunk_id.replace('#', '__')}.c"
