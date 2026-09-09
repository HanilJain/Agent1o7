"""Pure path algebra for Stage 3b's own on-disk output.

Same discipline as `stage3_analysis.layout`: every function here takes
paths in, returns paths out — no filesystem I/O, no `mkdir`. Callers create
directories at the point they actually write into them.

Layout, under `<db_subfolder>/stage3b/`::

    claims_summary.json            (written by driver.ingest_report() —
                                     common.claims.ClaimsRunSummary)
    findings/<chunk_id>.json       (one common.findings.AnalysisReport per
                                     claim — the Stage 4/5 input; see
                                     findings_dir/finding_filename)
    source/<doc_stem>.pages.json   (cached deterministic page-text
                                     extraction — re-running ingest against
                                     the same PDF re-uses this instead of
                                     re-parsing)
    debug/<doc_stem>.blocks.json   (--debug only; segmenter.segment()'s
                                     output, for manual inspection)

`findings_dir`/`finding_filename` intentionally reuse
`stage3_analysis.layout`'s exact `#` -> `__` substitution convention (see
`finding_filename`'s own docstring) — this is what lets
`stage4_rag.sink_index.discover_sink_candidates` and
`stage5_verification.candidate_index.discover_candidates` read a
Stage 3b-produced `findings/` directory with the SAME filename ->
`chunk_id` inversion logic they already use for Stage 3's own.
"""

from __future__ import annotations

from pathlib import Path


def stage3b_dir(db_subfolder: Path) -> Path:
    return db_subfolder / "stage3b"


def claims_summary_path(stage3b_dir_: Path) -> Path:
    """Written by `driver.ingest_report()` itself, best-effort
    (`except OSError: pass`) — same discipline as Stage 3's
    `analysis_summary.json`. Never read back by any later step; Stage 4/5
    depend only on `findings_dir`'s contents, exactly as they do for
    Stage 3's own best-effort summaries."""
    return stage3b_dir_ / "claims_summary.json"


def findings_dir(stage3b_dir_: Path) -> Path:
    """Per-claim `AnalysisReport` JSON directory — the actual Stage 4/5
    input. Structurally identical to `stage3_analysis.layout.findings_dir`,
    a SEPARATE directory (never the same one — Stage 3b never writes into
    `stage3/`)."""
    return stage3b_dir_ / "findings"


def finding_filename(chunk_id: str) -> str:
    """Identical `#` -> `__` substitution to
    `stage3_analysis.layout.finding_filename` — load-bearing: Stage 4/5's
    existing `_chunk_id_from_findings_filename` inverts this exact
    substitution, and must keep working unmodified against a Stage 3b
    `findings/` directory."""
    return f"{chunk_id.replace('#', '__')}.json"


def source_dir(stage3b_dir_: Path) -> Path:
    """Cached deterministic page-text extraction — re-running `ingest()`
    against the same PDF path re-uses this rather than re-parsing (parsing
    is cheap but not free on a large report)."""
    return stage3b_dir_ / "source"


def pages_cache_path(source_dir_: Path, doc_stem: str) -> Path:
    return source_dir_ / f"{doc_stem}.pages.json"


def debug_dir(stage3b_dir_: Path) -> Path:
    """`--debug`-only dump location, purely for manual testing/
    verification — never read back by any later step. Mirrors
    `stage3_analysis.layout.debug_dir`'s same discipline."""
    return stage3b_dir_ / "debug"


def blocks_debug_path(debug_dir_: Path, doc_stem: str) -> Path:
    return debug_dir_ / f"{doc_stem}.blocks.json"
