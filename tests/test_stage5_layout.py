"""Tests for `fw_audit.stage5_verification.layout` — pure path algebra."""

from __future__ import annotations

from pathlib import Path

from fw_audit.stage5_verification import layout


def test_verification_filename_sanitizes_double_colon():
    assert layout.verification_filename("bin#0000::c1") == "bin#0000__c1.json"


def test_report_filename_sanitizes_double_colon():
    assert layout.report_filename("bin#0000::c1") == "bin#0000__c1.md"


def test_workspace_dir_uses_sanitized_gid():
    stage5_dir_ = Path("/db/stage5")
    result = layout.workspace_dir(stage5_dir_, "bin#0000::c1")
    assert result == Path("/db/stage5/workspace/bin#0000__c1")


def test_cpg_and_source_paths_relative_to_workspace():
    workspace = Path("/db/stage5/workspace/bin#0000__c1")
    assert layout.cpg_path(workspace) == workspace / "cpg.bin"
    assert layout.source_path(workspace) == workspace / "whole.c"


def test_script_path_zero_padded():
    workspace = Path("/db/stage5/workspace/x")
    assert layout.script_path(workspace, 0) == workspace / "query_000.sc"
    assert layout.script_path(workspace, 12) == workspace / "query_012.sc"


def test_top_level_dirs_under_stage5():
    db_subfolder = Path("/db")
    stage5_dir_ = layout.stage5_dir(db_subfolder)
    assert stage5_dir_ == Path("/db/stage5")
    assert layout.verifications_dir(stage5_dir_) == Path("/db/stage5/verifications")
    assert layout.reports_dir(stage5_dir_) == Path("/db/stage5/reports")
    assert layout.workspace_root(stage5_dir_) == Path("/db/stage5/workspace")
    assert layout.debug_dir(stage5_dir_) == Path("/db/stage5/debug")
    assert layout.stage5_summary_path(stage5_dir_) == Path("/db/stage5/stage5_summary.json")


# ---------------------------------------------------------------------- #
# FVVW v3 fork-join layout — deliberately separate subtree
# ---------------------------------------------------------------------- #


def test_fvvw_dir_is_separate_subtree_of_stage5():
    stage5_dir_ = layout.stage5_dir(Path("/db"))
    fvvw_dir_ = layout.fvvw_dir(stage5_dir_)
    assert fvvw_dir_ == Path("/db/stage5/fvvw")
    assert layout.fvvw_reports_dir(fvvw_dir_) == Path("/db/stage5/fvvw/reports")
    assert layout.fvvw_dynamic_workspace_root(fvvw_dir_) == Path(
        "/db/stage5/fvvw/dynamic_workspace"
    )


def test_fvvw_dynamic_workspace_dir_uses_sanitized_gid():
    fvvw_dir_ = Path("/db/stage5/fvvw")
    result = layout.fvvw_dynamic_workspace_dir(fvvw_dir_, "bin#0000::c1")
    assert result == Path("/db/stage5/fvvw/dynamic_workspace/bin#0000__c1")


def test_fvvw_report_filenames_sanitize_double_colon():
    assert layout.fvvw_report_json_filename("bin#0000::c1") == "bin#0000__c1.json"
    assert layout.fvvw_report_markdown_filename("bin#0000::c1") == "bin#0000__c1.md"


def test_fvvw_summary_path_separate_from_stage5_summary_path():
    stage5_dir_ = layout.stage5_dir(Path("/db"))
    fvvw_summary = layout.fvvw_summary_path(stage5_dir_)
    stage5_summary = layout.stage5_summary_path(stage5_dir_)
    assert fvvw_summary == Path("/db/stage5/fvvw_summary.json")
    assert fvvw_summary != stage5_summary
