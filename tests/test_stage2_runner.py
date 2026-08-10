"""Tests for the `fw-extract` CLI (fw_audit.stage2_extraction.runner)."""

from __future__ import annotations

import json
from pathlib import Path

from fw_audit.stage2_extraction.runner import _parse_args, main


def test_parse_args_defaults():
    args = _parse_args(["stage1_summary.json"])
    assert args.stage1_summary_path == "stage1_summary.json"
    assert args.only == []
    assert args.dry_run is False
    assert args.run_id is None


def test_parse_args_only_is_repeatable():
    args = _parse_args(["s.json", "--only", "bin/a", "--only", "bin/b"])
    assert args.only == ["bin/a", "bin/b"]


def test_parse_args_dry_run_flag():
    args = _parse_args(["s.json", "--dry-run"])
    assert args.dry_run is True


def test_main_exit_code_2_on_missing_input(tmp_path: Path, capsys):
    missing = tmp_path / "does_not_exist.json"
    code = main([str(missing)])
    assert code == 2
    captured = capsys.readouterr()
    assert "does not exist" in captured.err


def test_main_exit_code_2_on_stage2_input_error(tmp_path: Path, monkeypatch, capsys):
    """An unreadable/malformed stage1_summary.json surfaces as exit 2, via
    the real (unpatched) run_extraction -> Stage2InputError path."""
    bad_summary = tmp_path / "stage1_summary.json"
    bad_summary.write_text("{not valid json", encoding="utf-8")

    code = main([str(bad_summary)])

    assert code == 2
    captured = capsys.readouterr()
    assert "error:" in captured.err


def test_main_exit_code_0_on_completed(tmp_path: Path, monkeypatch, capsys):
    summary_path = tmp_path / "stage1_summary.json"
    db_subfolder = tmp_path / "db"
    rootfs = db_subfolder / "rootfs"
    rootfs.mkdir(parents=True)
    summary_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "rootfs_dir": str(rootfs),
                "identified_binaries": [],
            }
        ),
        encoding="utf-8",
    )

    code = main([str(summary_path)])

    assert code == 0
    captured = capsys.readouterr()
    assert "Status: completed" in captured.out
