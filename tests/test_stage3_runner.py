"""Tests for the `fw-analyze` CLI (fw_audit.stage3_analysis.runner).

Mirrors `tests/test_stage2_runner.py`'s structure/idiom.
"""

from __future__ import annotations

import json
from pathlib import Path

from fw_audit.stage3_analysis.runner import _parse_args, main


def _setup_single_target_run(tmp_path: Path, *, source_text: str) -> Path:
    """One whitelisted, resolved target (`bin/busybox`) whose mirror-tree
    file holds `source_text`. Returns the stage1_summary.json path."""
    db_subfolder = tmp_path / "db" / "fw"
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True)
    tree_dir = tmp_path / "db" / "fw_decompiled"
    (tree_dir / "bin").mkdir(parents=True)
    (tree_dir / "bin" / "busybox.c").write_text(source_text, encoding="utf-8")

    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "identified_binaries": [{"path": "bin/busybox"}],
            }
        ),
        encoding="utf-8",
    )
    (stage2_dir / "stage2_summary.json").write_text(
        json.dumps(
            {
                "run_id": "r",
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "rootfs_dir": str(db_subfolder / "rootfs"),
                "stage2_dir": str(stage2_dir),
                "decompiled_tree_dir": "fw_decompiled",
                "ghidra_image": "fw-audit-ghidra:latest",
                "binaries": [
                    {
                        "bin_id": "bin_busybox",
                        "rootfs_path": "bin/busybox",
                        "requested_path": "bin/busybox",
                        "sha256": "0" * 64,
                        "size_bytes": len(source_text.encode("utf-8")),
                        "status": "succeeded",
                        "function_count": 1,
                        "artifacts": {"decompiled_tree_c": "bin/busybox.c"},
                    }
                ],
                "started_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return summary_path


def test_parse_args_defaults():
    args = _parse_args(["stage1_summary.json"])
    assert args.stage1_summary_path == "stage1_summary.json"
    assert args.only == []
    assert args.debug is False
    assert args.chunk_lines is None
    assert args.run_id is None


def test_parse_args_only_is_repeatable():
    args = _parse_args(["s.json", "--only", "bin/a", "--only", "bin/b"])
    assert args.only == ["bin/a", "bin/b"]


def test_parse_args_debug_flag():
    args = _parse_args(["s.json", "--debug"])
    assert args.debug is True


def test_parse_args_chunk_lines():
    args = _parse_args(["s.json", "--chunk-lines", "500"])
    assert args.chunk_lines == 500


def test_main_without_debug_writes_no_debug_dump(tmp_path: Path, capsys):
    summary_path = _setup_single_target_run(tmp_path, source_text="int main(void) { return 0; }\n")

    code = main([str(summary_path)])

    assert code == 0
    debug_dir = tmp_path / "db" / "fw" / "stage3" / "debug"
    assert not debug_dir.exists()
    captured = capsys.readouterr()
    assert "Debug source dump" not in captured.out


def test_main_debug_writes_verbatim_copy_to_disk(tmp_path: Path, capsys):
    source = "int main(void)\n{\n  return 0;\n}\n"
    summary_path = _setup_single_target_run(tmp_path, source_text=source)

    code = main([str(summary_path), "--debug"])

    assert code == 0
    dumped = tmp_path / "db" / "fw" / "stage3" / "debug" / "bin_busybox.c"
    assert dumped.is_file()
    assert dumped.read_text(encoding="utf-8") == source  # byte-for-byte, not a preview
    captured = capsys.readouterr()
    assert "Debug source dump" in captured.out
    assert str(dumped.parent) in captured.out


def test_main_debug_dump_untruncated_for_large_source(tmp_path: Path):
    lines = [f"/* line {i} */" for i in range(500)]
    source = "\n".join(lines) + "\n"
    summary_path = _setup_single_target_run(tmp_path, source_text=source)

    main([str(summary_path), "--debug"])

    dumped = tmp_path / "db" / "fw" / "stage3" / "debug" / "bin_busybox.c"
    written = dumped.read_text(encoding="utf-8")
    assert written == source  # full content, never head/tail-truncated
    assert "line 250" in written  # a middle line specifically, to rule out truncation


def test_main_debug_never_modifies_stage2_or_mirror_tree(tmp_path: Path, capsys):
    summary_path = _setup_single_target_run(tmp_path, source_text="int main(void) { return 0; }\n")
    db_subfolder = tmp_path / "db" / "fw"
    stage2_dir = db_subfolder / "stage2"
    tree_dir = tmp_path / "db" / "fw_decompiled"

    def _snapshot() -> set[str]:
        return {
            str(p)
            for root in (stage2_dir, tree_dir)
            for p in root.rglob("*")
            if p.is_file()
        }

    before = _snapshot()
    main([str(summary_path), "--debug"])
    after = _snapshot()

    # --debug writes into stage3/debug/ only -- stage2/ and the mirror tree
    # (both snapshotted here) must be unaffected.
    assert after == before


def test_main_exit_code_2_on_missing_input(tmp_path: Path, capsys):
    missing = tmp_path / "does_not_exist.json"
    code = main([str(missing)])
    assert code == 2
    captured = capsys.readouterr()
    assert "does not exist" in captured.err


def test_main_exit_code_2_on_stage3_input_error(tmp_path: Path, capsys):
    """A stage1_summary.json with no matching stage2_summary.json surfaces
    as exit 2, via the real (unpatched) ingest() -> Stage3InputError path."""
    db_subfolder = tmp_path / "db" / "fw"
    db_subfolder.mkdir(parents=True)
    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "identified_binaries": [],
            }
        ),
        encoding="utf-8",
    )

    code = main([str(summary_path)])

    assert code == 2
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert "fw-extract" in captured.err


def test_main_exit_code_0_and_prints_targets_skipped_aliases(tmp_path: Path, capsys):
    """Exercises `_print_report`'s target/alias/skipped/orphan branches
    together, against a real (unpatched) `ingest()` run."""
    db_subfolder = tmp_path / "db" / "fw"
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True)
    tree_dir = tmp_path / "db" / "fw_decompiled"
    tree_dir.mkdir(parents=True)
    (tree_dir / "bin").mkdir()
    (tree_dir / "bin" / "busybox.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (tree_dir / "lib").mkdir()
    (tree_dir / "lib" / "orphan.so.c").write_text("int f(void) { return 0; }\n", encoding="utf-8")

    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "identified_binaries": [{"path": "bin/ls"}, {"path": "bin/missing"}],
            }
        ),
        encoding="utf-8",
    )
    (stage2_dir / "stage2_summary.json").write_text(
        json.dumps(
            {
                "run_id": "r",
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "rootfs_dir": str(db_subfolder / "rootfs"),
                "stage2_dir": str(stage2_dir),
                "decompiled_tree_dir": "fw_decompiled",
                "ghidra_image": "fw-audit-ghidra:latest",
                "binaries": [
                    {
                        "bin_id": "bin_busybox",
                        "rootfs_path": "bin/busybox",
                        "requested_path": "bin/busybox",
                        "aliases": ["bin/ls", "bin/cat"],
                        "sha256": "0" * 64,
                        "size_bytes": 1024,
                        "status": "succeeded",
                        "function_count": 3,
                        "artifacts": {"decompiled_tree_c": "bin/busybox.c"},
                    }
                ],
                "unresolved": [{"requested_path": "bin/missing", "problem": "not_found"}],
                "started_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    code = main([str(summary_path)])

    assert code == 0
    captured = capsys.readouterr()
    assert "Targets (1):" in captured.out
    assert "bin/busybox" in captured.out
    assert "aliases: bin/ls, bin/cat" in captured.out
    assert "Skipped (1):" in captured.out
    assert "bin/missing" in captured.out
    assert "Orphans" in captured.out
    assert "lib/orphan.so.c" in captured.out


def test_main_debug_and_chunk_lines_flags_accepted(tmp_path: Path, capsys):
    """--debug/--chunk-lines are parsed and threaded into Settings even
    though Steps 3/4 don't consume them yet -- confirms the CLI surface
    doesn't error out on them."""
    db_subfolder = tmp_path / "db" / "fw"
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True)
    (tmp_path / "db" / "fw_decompiled").mkdir(parents=True)
    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(
        json.dumps(
            {"status": "completed", "db_subfolder": str(db_subfolder), "identified_binaries": []}
        ),
        encoding="utf-8",
    )
    (stage2_dir / "stage2_summary.json").write_text(
        json.dumps(
            {
                "run_id": "r",
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "rootfs_dir": str(db_subfolder / "rootfs"),
                "stage2_dir": str(stage2_dir),
                "decompiled_tree_dir": "fw_decompiled",
                "ghidra_image": "fw-audit-ghidra:latest",
                "binaries": [],
                "started_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    code = main([str(summary_path), "--debug", "--chunk-lines", "500"])

    assert code == 1  # zero targets, but flags themselves didn't error


def test_main_exit_code_1_on_zero_targets(tmp_path: Path, capsys):
    db_subfolder = tmp_path / "db" / "fw"
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True)
    (tmp_path / "db" / "fw_decompiled").mkdir(parents=True)

    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "identified_binaries": [],
            }
        ),
        encoding="utf-8",
    )
    (stage2_dir / "stage2_summary.json").write_text(
        json.dumps(
            {
                "run_id": "r",
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "rootfs_dir": str(db_subfolder / "rootfs"),
                "stage2_dir": str(stage2_dir),
                "decompiled_tree_dir": "fw_decompiled",
                "ghidra_image": "fw-audit-ghidra:latest",
                "binaries": [],
                "started_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    code = main([str(summary_path)])

    assert code == 1
    captured = capsys.readouterr()
    assert "Machine-readable report:" in captured.out
