"""Tests for `fw_audit.stage3_analysis.layout` (pure functions — no I/O),
mirroring `tests/test_stage2_layout.py`'s style.
"""

from __future__ import annotations

from pathlib import Path

from fw_audit.stage3_analysis.layout import (
    chunk_filename,
    chunks_dir,
    debug_dir,
    debug_source_path,
    ingestion_report_path,
    stage3_dir,
    stage3_summary_path,
)


def test_stage3_dir_is_child_of_db_subfolder(tmp_path):
    db_subfolder = tmp_path / "db" / "fw"

    result = stage3_dir(db_subfolder)

    assert result == db_subfolder / "stage3"


def test_ingestion_report_path(tmp_path):
    stage3 = tmp_path / "stage3"

    assert ingestion_report_path(stage3) == stage3 / "ingestion_report.json"


def test_stage3_summary_path(tmp_path):
    stage3 = tmp_path / "stage3"

    assert stage3_summary_path(stage3) == stage3 / "stage3_summary.json"


def test_chunks_dir(tmp_path):
    stage3 = tmp_path / "stage3"

    assert chunks_dir(stage3) == stage3 / "chunks"


def test_debug_dir(tmp_path):
    stage3 = tmp_path / "stage3"

    assert debug_dir(stage3) == stage3 / "debug"


def test_debug_source_path_appends_c():
    debug = Path("stage3") / "debug"

    result = debug_source_path(debug, "sbin_wpasupp__b86e5cadc3c9")

    assert result == debug / "sbin_wpasupp__b86e5cadc3c9.c"


def test_debug_dir_is_distinct_from_chunks_dir(tmp_path):
    # debug/ (Step 1's per-target dump) and chunks/ (Step 4's future
    # per-chunk dump) must never collide on disk.
    stage3 = tmp_path / "stage3"

    assert debug_dir(stage3) != chunks_dir(stage3)


def test_chunk_filename_replaces_hash_separator():
    # "#" is a fine human-readable separator in an in-memory chunk_id, but
    # awkward in a Windows filename (not illegal, but avoided here since
    # Step 4's debug-dump path is meant to be trivially browsable).
    result = chunk_filename("sbin_wpasupp__b86e5cadc3c9#0007")

    assert result == "sbin_wpasupp__b86e5cadc3c9__0007.c"
    assert "#" not in result
