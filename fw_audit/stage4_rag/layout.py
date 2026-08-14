"""Pure path algebra for Stage 4's own on-disk output.

Same discipline as `stage3_analysis.layout`: every function here takes paths
in, returns paths out — no filesystem I/O, no `mkdir`. Callers create
directories at the point they actually write into them.

Layout, under `<db_subfolder>/stage4/`::

    chroma/                    (C1+C2 — persisted Chroma collection)
    corpus_report.json         (C1+C2 — files/chunks/embedding-model summary)
    queries/<gid>.json         (C3 — MultiQueryPlan per finding)
    retrieval/<gid>.json       (C4 — RetrievalBundle per finding)
    taint/<gid>.json           (C5 — TaintPathReport per finding)
    stage4_summary.json        (C6 — driver run summary)

`<gid>` is the global finding id `f"{chunk_id}::{finding_id}"` (Stage 3's
`Finding.finding_id` is unique only within its chunk — see `sink_index.py`).
Sanitized to `__` for filenames the same way Stage 3's `layout.py` sanitizes
`chunk_id`'s `#` separator; `::` is kept in the in-memory id itself.
"""

from __future__ import annotations

from pathlib import Path


def stage4_dir(db_subfolder: Path) -> Path:
    return db_subfolder / "stage4"


def chroma_dir(stage4_dir_: Path) -> Path:
    """The persisted Chroma collection directory — written by `corpus_build.py`
    (C1+C2), read by `retrieval/store.py` (C4)."""
    return stage4_dir_ / "chroma"


def corpus_report_path(stage4_dir_: Path) -> Path:
    return stage4_dir_ / "corpus_report.json"


def queries_dir(stage4_dir_: Path) -> Path:
    return stage4_dir_ / "queries"


def retrieval_dir(stage4_dir_: Path) -> Path:
    return stage4_dir_ / "retrieval"


def taint_dir(stage4_dir_: Path) -> Path:
    return stage4_dir_ / "taint"


def debug_dir(stage4_dir_: Path) -> Path:
    """`debug.py`'s own scratch output (e.g. ad-hoc dumps) — never read back
    by the driver or any other component. Distinct from the per-gid
    `queries/`/`retrieval/`/`taint/` directories above, which ARE read back
    (or would be, if a future step needed to resume)."""
    return stage4_dir_ / "debug"


def _sanitize_gid(global_id: str) -> str:
    """`global_id` is `<chunk_id>::<finding_id>`; `chunk_id` itself is
    already filesystem-safe (see `stage3_analysis.layout.chunk_filename`'s
    docstring) — this only needs to swap `::` for something Windows-safe."""
    return global_id.replace("::", "__")


def query_plan_filename(global_id: str) -> str:
    return f"{_sanitize_gid(global_id)}.json"


def retrieval_filename(global_id: str) -> str:
    return f"{_sanitize_gid(global_id)}.json"


def taint_filename(global_id: str) -> str:
    return f"{_sanitize_gid(global_id)}.json"


def stage4_summary_path(stage4_dir_: Path) -> Path:
    """Written by `driver.run_queue()` itself, mirroring
    `stage3_analysis.layout.analysis_summary_path`'s precedent — see
    `common.taint.Stage4RunSummary`."""
    return stage4_dir_ / "stage4_summary.json"
