"""Pure path algebra for Stage 5's own on-disk output.

Same discipline as `stage4_rag.layout`: every function here takes paths in,
returns paths out — no filesystem I/O, no `mkdir`. Callers create
directories at the point they actually write into them.

Layout, under `<db_subfolder>/stage5/`::

    verifications/<gid>.json   (the standard JSON report — common.verification.VerificationReport)
    reports/<gid>.md           (human-readable Markdown — report_writer.py)
    workspace/<gid>/           (per-candidate scratch: whole.c copy, cpg.bin,
                                 query_NNN.sc, joern stdout/stderr dumps — kept
                                 after a run only if Settings.stage5_keep_workspace)
    debug/                     (debug.py's own scratch — never read back)
    stage5_summary.json        (run-level summary, written by driver.run_queue)

`<gid>` is the global finding id `f"{chunk_id}::{finding_id}"` — same format
and same `::` -> `__` filename sanitization as `stage4_rag.layout`.
"""

from __future__ import annotations

from pathlib import Path


def stage5_dir(db_subfolder: Path) -> Path:
    return db_subfolder / "stage5"


def verifications_dir(stage5_dir_: Path) -> Path:
    return stage5_dir_ / "verifications"


def reports_dir(stage5_dir_: Path) -> Path:
    return stage5_dir_ / "reports"


def workspace_root(stage5_dir_: Path) -> Path:
    return stage5_dir_ / "workspace"


def debug_dir(stage5_dir_: Path) -> Path:
    """`debug.py`'s own scratch output — never read back by the driver or
    any other component. Distinct from `verifications/`/`reports/`, which
    ARE read back (or would be, if a future step needed to resume)."""
    return stage5_dir_ / "debug"


def _sanitize_gid(global_id: str) -> str:
    """`global_id` is `<chunk_id>::<finding_id>`; `chunk_id` itself is
    already filesystem-safe — this only needs to swap `::` for something
    Windows-safe, same as `stage4_rag.layout._sanitize_gid`."""
    return global_id.replace("::", "__")


def verification_filename(global_id: str) -> str:
    return f"{_sanitize_gid(global_id)}.json"


def report_filename(global_id: str) -> str:
    return f"{_sanitize_gid(global_id)}.md"


def workspace_dir(stage5_dir_: Path, global_id: str) -> Path:
    return workspace_root(stage5_dir_) / _sanitize_gid(global_id)


def cpg_path(workspace_dir_: Path) -> Path:
    return workspace_dir_ / "cpg.bin"


def source_path(workspace_dir_: Path) -> Path:
    """The copy of the binary's `normalized/joern/whole.c` this candidate's
    CPG is built from — copied into the workspace so the container only
    ever needs one bind mount (the workspace itself)."""
    return workspace_dir_ / "whole.c"


def script_path(workspace_dir_: Path, attempt_index: int) -> Path:
    return workspace_dir_ / f"query_{attempt_index:03d}.sc"


def stage5_summary_path(stage5_dir_: Path) -> Path:
    """Written by `driver.run_queue()` itself, mirroring
    `stage4_rag.layout.stage4_summary_path`'s precedent — see
    `common.verification.VerificationRunSummary`."""
    return stage5_dir_ / "stage5_summary.json"
