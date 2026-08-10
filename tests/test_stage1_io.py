"""Tests for fw_audit.stage2_extraction.stage1_io.

Covers the three traps stage1_summary.json presents to a downstream
consumer: the status enum-repr serialization, and the missing/stale
rootfs_dir fallback chain (rootfs_dir -> tree.txt line 1 -> <db>/tree.txt
-> hard fail).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fw_audit.stage2_extraction.stage1_io import (
    Stage2InputError,
    load_stage1_summary,
    resolve_rootfs_dir,
)


def _write_summary(path: Path, **overrides) -> Path:
    payload = {
        "status": "completed",
        "db_subfolder": str(path.parent),
        "tree_txt_path": str(path.parent / "tree.txt"),
        "rootfs_dir": None,
        "identified_binaries": [],
        **overrides,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_load_stage1_summary_missing_file_raises_actionable_error(tmp_path: Path):
    with pytest.raises(Stage2InputError, match="fw-ingest"):
        load_stage1_summary(tmp_path / "stage1_summary.json")


def test_load_stage1_summary_malformed_json_raises(tmp_path: Path):
    bad = tmp_path / "stage1_summary.json"
    bad.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(Stage2InputError):
        load_stage1_summary(bad)


def test_load_stage1_summary_parses_both_status_forms(tmp_path: Path):
    current = _write_summary(tmp_path / "current.json", status="completed")
    legacy = _write_summary(tmp_path / "legacy.json", status="IngestionStatus.COMPLETED")

    assert load_stage1_summary(current).status == "completed"
    assert load_stage1_summary(legacy).status == "completed"


def test_resolve_rootfs_dir_uses_published_field(tmp_path: Path):
    rootfs = tmp_path / "squashfs-root"
    rootfs.mkdir()
    summary_path = _write_summary(tmp_path / "s.json", rootfs_dir=str(rootfs))
    summary = load_stage1_summary(summary_path)

    result = resolve_rootfs_dir(summary)

    assert result.rootfs_dir == rootfs
    assert result.warnings == ()


def test_resolve_rootfs_dir_falls_back_to_tree_txt_first_line(tmp_path: Path):
    rootfs = tmp_path / "squashfs-root"
    rootfs.mkdir()
    tree_txt = tmp_path / "tree.txt"
    tree_txt.write_text(f"{rootfs}\n├── bin/\n", encoding="utf-8")
    summary_path = _write_summary(
        tmp_path / "s.json", rootfs_dir=None, tree_txt_path=str(tree_txt)
    )
    summary = load_stage1_summary(summary_path)

    result = resolve_rootfs_dir(summary)

    assert result.rootfs_dir == rootfs
    assert len(result.warnings) == 1
    assert "no rootfs_dir" in result.warnings[0]


def test_resolve_rootfs_dir_falls_back_to_db_subfolder_tree_txt(tmp_path: Path):
    """tree_txt_path itself is stale (e.g. Database copied from another
    machine) but <db_subfolder>/tree.txt still exists and is usable."""
    rootfs = tmp_path / "squashfs-root"
    rootfs.mkdir()
    (tmp_path / "tree.txt").write_text(f"{rootfs}\n", encoding="utf-8")
    summary_path = _write_summary(
        tmp_path / "s.json", rootfs_dir=None, tree_txt_path="Z:\\nonexistent\\tree.txt"
    )
    summary = load_stage1_summary(summary_path)

    result = resolve_rootfs_dir(summary)

    assert result.rootfs_dir == rootfs


def test_resolve_rootfs_dir_hard_fails_with_actionable_message(tmp_path: Path):
    summary_path = _write_summary(
        tmp_path / "s.json", rootfs_dir=None, tree_txt_path=str(tmp_path / "missing_tree.txt")
    )
    summary = load_stage1_summary(summary_path)

    with pytest.raises(Stage2InputError, match="fw-ingest"):
        resolve_rootfs_dir(summary)


def test_resolve_rootfs_dir_rejects_tree_txt_line_pointing_at_nonexistent_dir(tmp_path: Path):
    tree_txt = tmp_path / "tree.txt"
    tree_txt.write_text(f"{tmp_path / 'does_not_exist'}\n", encoding="utf-8")
    summary_path = _write_summary(tmp_path / "s.json", rootfs_dir=None, tree_txt_path=str(tree_txt))
    summary = load_stage1_summary(summary_path)

    with pytest.raises(Stage2InputError):
        resolve_rootfs_dir(summary)
