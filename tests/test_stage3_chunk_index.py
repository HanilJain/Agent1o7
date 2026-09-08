"""Tests for `fw_audit.stage3_analysis.chunk_index`: the editable manifest
(`write_chunk_index`) and its `--chunks-file` input resolution
(`load_chunk_selection`, `resolve_chunk_handles`).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fw_audit.common.schemas import DecompilationStatus
from fw_audit.stage3_analysis.chunk_index import (
    ChunkSelection,
    load_chunk_selection,
    resolve_chunk_handles,
    write_chunk_index,
)
from fw_audit.stage3_analysis.errors import Stage3InputError
from fw_audit.stage3_analysis.models import IngestionReport, Target

# --- write_chunk_index ---


def test_write_chunk_index_round_trip(tmp_path: Path):
    stage3_dir = tmp_path / "stage3"
    entries = [
        {"chunk_id": "bin_a__0000", "rootfs_path": "bin/a", "approx_tokens": 10},
        {"chunk_id": "bin_a__0001", "rootfs_path": "bin/a", "approx_tokens": 20},
    ]

    write_chunk_index(stage3_dir, entries)

    index_path = stage3_dir / "chunk_index.json"
    written = json.loads(index_path.read_text(encoding="utf-8"))
    assert written == {"chunks": entries}


def test_write_chunk_index_empty_entries_leaves_existing_file_intact(tmp_path: Path):
    stage3_dir = tmp_path / "stage3"
    stage3_dir.mkdir(parents=True)
    index_path = stage3_dir / "chunk_index.json"
    index_path.write_text(json.dumps({"chunks": [{"chunk_id": "keep_me"}]}), encoding="utf-8")

    write_chunk_index(stage3_dir, [])

    assert json.loads(index_path.read_text(encoding="utf-8")) == {
        "chunks": [{"chunk_id": "keep_me"}]
    }


def test_write_chunk_index_best_effort_on_oserror(tmp_path: Path, monkeypatch):
    stage3_dir = tmp_path / "stage3"

    def _raise_mkdir(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(Path, "mkdir", _raise_mkdir)

    # Must not raise.
    write_chunk_index(stage3_dir, [{"chunk_id": "x"}])


# --- load_chunk_selection ---


def test_load_chunk_selection_bare_array_of_ids(tmp_path: Path):
    path = tmp_path / "selected.json"
    path.write_text(json.dumps(["bin_a#0000", "bin_a#0001"]), encoding="utf-8")

    result = load_chunk_selection(path)

    assert [s.chunk_id for s in result] == ["bin_a#0000", "bin_a#0001"]


def test_load_chunk_selection_chunks_object_of_ids(tmp_path: Path):
    path = tmp_path / "selected.json"
    path.write_text(json.dumps({"chunks": ["bin_a#0000"]}), encoding="utf-8")

    result = load_chunk_selection(path)

    assert [s.chunk_id for s in result] == ["bin_a#0000"]


def test_load_chunk_selection_unedited_chunk_index_json_verbatim(tmp_path: Path):
    # The exact shape write_chunk_index produces.
    path = tmp_path / "chunk_index.json"
    path.write_text(
        json.dumps(
            {
                "chunks": [
                    {
                        "chunk_id": "sbin_hostapd__5d85c80abc0a#0021",
                        "bin_id": "sbin_hostapd__5d85c80abc0a",
                        "rootfs_path": "sbin/hostapd",
                        "source_relpath": "sbin/hostapd.c",
                        "start_line": 100,
                        "end_line": 200,
                        "approx_tokens": 500,
                        "function_names": ["hostapd_config_read"],
                        "oversized": False,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = load_chunk_selection(path)

    assert len(result) == 1
    sel = result[0]
    assert sel.chunk_id == "sbin_hostapd__5d85c80abc0a#0021"
    assert sel.rootfs_path == "sbin/hostapd"
    assert sel.source_relpath == "sbin/hostapd.c"
    assert sel.start_line == 100
    assert sel.end_line == 200
    assert sel.oversized is False


def test_load_chunk_selection_unedited_stage3_summary_json_verbatim(tmp_path: Path):
    # Stage3Summary.chunks (ChunkRecord) shape — carries chunk_id, bin_id,
    # rootfs_path, source_relpath, chunk_path, start_line, end_line,
    # approx_tokens, oversized, status, attempts.
    path = tmp_path / "stage3_summary.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": "r",
                "status": "completed",
                "db_subfolder": "db/fw",
                "chunks": [
                    {
                        "chunk_id": "bin_a#0000",
                        "bin_id": "bin_a",
                        "rootfs_path": "bin/a",
                        "source_relpath": "bin/a.c",
                        "chunk_path": "stage3/chunks/bin_a__0000.c",
                        "start_line": 1,
                        "end_line": 10,
                        "approx_tokens": 30,
                        "oversized": False,
                        "status": "acked",
                        "attempts": 1,
                    }
                ],
                "total_chunks": 1,
                "total_acked": 1,
                "total_failed": 0,
                "total_tokens": 30,
                "warnings": [],
                "started_at": "2026-01-01T00:00:00Z",
                "finished_at": "2026-01-01T00:00:01Z",
            }
        ),
        encoding="utf-8",
    )

    result = load_chunk_selection(path)

    assert len(result) == 1
    assert result[0].chunk_id == "bin_a#0000"
    assert result[0].rootfs_path == "bin/a"


def test_load_chunk_selection_normalizes_filename_form_with_double_underscore_bin_id():
    # The regression case this whole feature exists for: bin_id itself
    # contains "__", so the LAST "__" (not the first, not a blind replace)
    # must be the split point.
    from fw_audit.stage3_analysis.chunk_index import _normalize_chunk_id

    result = _normalize_chunk_id("sbin_hostapd__5d85c80abc0a__0021")

    assert result == "sbin_hostapd__5d85c80abc0a#0021"
    assert result != "sbin_hostapd#5d85c80abc0a#0021"


def test_load_chunk_selection_strips_dot_c_and_dot_json_suffixes():
    from fw_audit.stage3_analysis.chunk_index import _normalize_chunk_id

    assert _normalize_chunk_id("sbin_hostapd__5d85c80abc0a__0021.c") == (
        "sbin_hostapd__5d85c80abc0a#0021"
    )
    assert _normalize_chunk_id("sbin_hostapd__5d85c80abc0a__0021.json") == (
        "sbin_hostapd__5d85c80abc0a#0021"
    )


def test_load_chunk_selection_dedupes_preserving_first_seen_order(tmp_path: Path):
    path = tmp_path / "selected.json"
    path.write_text(json.dumps(["bin_a#0000", "bin_a#0001", "bin_a#0000"]), encoding="utf-8")

    result = load_chunk_selection(path)

    assert [s.chunk_id for s in result] == ["bin_a#0000", "bin_a#0001"]


def test_load_chunk_selection_rejects_path_traversal_id(tmp_path: Path):
    path = tmp_path / "selected.json"
    path.write_text(json.dumps(["../../etc/passwd"]), encoding="utf-8")

    with pytest.raises(Stage3InputError):
        load_chunk_selection(path)


def test_load_chunk_selection_missing_file_raises(tmp_path: Path):
    with pytest.raises(Stage3InputError, match="not found"):
        load_chunk_selection(tmp_path / "missing.json")


def test_load_chunk_selection_malformed_json_raises(tmp_path: Path):
    path = tmp_path / "selected.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(Stage3InputError, match="Could not read/parse"):
        load_chunk_selection(path)


def test_load_chunk_selection_wrong_shape_raises(tmp_path: Path):
    path = tmp_path / "selected.json"
    path.write_text(json.dumps({"not_chunks": []}), encoding="utf-8")

    with pytest.raises(Stage3InputError):
        load_chunk_selection(path)


def test_load_chunk_selection_empty_raises(tmp_path: Path):
    path = tmp_path / "selected.json"
    path.write_text(json.dumps([]), encoding="utf-8")

    with pytest.raises(Stage3InputError, match="names no chunks"):
        load_chunk_selection(path)


# --- resolve_chunk_handles ---


def _report_with_target(
    db_subfolder: Path, *, bin_id: str = "bin_a", rootfs_path: str = "bin/a"
) -> IngestionReport:
    target = Target(
        bin_id=bin_id,
        rootfs_path=rootfs_path,
        requested_path=rootfs_path,
        aliases=(),
        sha256="0" * 64,
        source_path=db_subfolder / "mirror" / f"{rootfs_path}.c",
        source_relpath=f"{rootfs_path}.c",
        size_bytes=10,
        status=DecompilationStatus.SUCCEEDED,
        function_count=1,
    )
    return IngestionReport(
        db_subfolder=db_subfolder,
        decompiled_tree_dir=db_subfolder.parent / "fw_decompiled",
        targets=(target,),
    )


def test_resolve_chunk_handles_builds_handle_from_persisted_file(tmp_path: Path):
    db_subfolder = tmp_path / "db" / "fw"
    chunks_dir = db_subfolder / "stage3" / "chunks"
    chunks_dir.mkdir(parents=True)
    (chunks_dir / "bin_a__0000.c").write_text("void f(void) {}", encoding="utf-8")
    report = _report_with_target(db_subfolder)
    selections = [ChunkSelection(chunk_id="bin_a#0000")]

    handles, warnings = resolve_chunk_handles(selections, report=report)

    assert warnings == []
    assert len(handles) == 1
    handle = handles[0]
    assert handle.chunk_id == "bin_a#0000"
    assert handle.bin_id == "bin_a"
    assert handle.rootfs_path == "bin/a"  # from report.targets, authoritative
    assert handle.approx_tokens == len("void f(void) {}") // 4


def test_resolve_chunk_handles_falls_back_to_selection_metadata(tmp_path: Path):
    db_subfolder = tmp_path / "db" / "fw"
    chunks_dir = db_subfolder / "stage3" / "chunks"
    chunks_dir.mkdir(parents=True)
    (chunks_dir / "bin_gone__0000.c").write_text("void f(void) {}", encoding="utf-8")
    # report has no matching target for bin_gone
    report = _report_with_target(db_subfolder, bin_id="bin_a")
    selections = [
        ChunkSelection(
            chunk_id="bin_gone#0000", rootfs_path="bin/gone", source_relpath="bin/gone.c"
        )
    ]

    handles, warnings = resolve_chunk_handles(selections, report=report)

    assert warnings == []
    assert handles[0].rootfs_path == "bin/gone"
    assert handles[0].source_relpath == "bin/gone.c"


def test_resolve_chunk_handles_falls_back_to_bin_id_with_warning(tmp_path: Path):
    db_subfolder = tmp_path / "db" / "fw"
    chunks_dir = db_subfolder / "stage3" / "chunks"
    chunks_dir.mkdir(parents=True)
    (chunks_dir / "bin_gone__0000.c").write_text("void f(void) {}", encoding="utf-8")
    report = _report_with_target(db_subfolder, bin_id="bin_a")
    selections = [ChunkSelection(chunk_id="bin_gone#0000")]

    handles, warnings = resolve_chunk_handles(selections, report=report)

    assert len(warnings) == 1
    assert handles[0].rootfs_path == "bin_gone"
    assert handles[0].source_relpath == "bin_gone"


def test_resolve_chunk_handles_two_missing_ids_named_in_one_error(tmp_path: Path):
    db_subfolder = tmp_path / "db" / "fw"
    (db_subfolder / "stage3" / "chunks").mkdir(parents=True)
    report = _report_with_target(db_subfolder)
    selections = [
        ChunkSelection(chunk_id="bin_a#9998"),
        ChunkSelection(chunk_id="bin_a#9999"),
    ]

    with pytest.raises(Stage3InputError) as exc_info:
        resolve_chunk_handles(selections, report=report)

    message = str(exc_info.value)
    assert "bin_a#9998" in message
    assert "bin_a#9999" in message


def test_resolve_chunk_handles_missing_file_reported_not_silently_skipped(tmp_path: Path):
    db_subfolder = tmp_path / "db" / "fw"
    (db_subfolder / "stage3" / "chunks").mkdir(parents=True)
    report = _report_with_target(db_subfolder)
    # _normalize_chunk_id already rejects "/", "\\", ".." at load time
    # (test_load_chunk_selection_rejects_path_traversal_id above), so the
    # containment assertion in resolve_chunk_handles is defense in depth —
    # what's actually reachable here is a chunk_id with no file on disk,
    # which must fail loudly rather than be dropped silently.
    selections = [ChunkSelection(chunk_id="bin_a#0000")]

    with pytest.raises(Stage3InputError, match="no chunk file"):
        resolve_chunk_handles(selections, report=report)
