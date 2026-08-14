"""Tests for `fw_audit.stage4_rag.layout` — pure path algebra, no I/O."""

from __future__ import annotations

from pathlib import Path

from fw_audit.stage4_rag import layout


def test_stage4_dir_appends_stage4():
    assert layout.stage4_dir(Path("/db/fw")) == Path("/db/fw/stage4")


def test_chroma_and_report_paths():
    s4 = Path("/db/fw/stage4")
    assert layout.chroma_dir(s4) == Path("/db/fw/stage4/chroma")
    assert layout.corpus_report_path(s4) == Path("/db/fw/stage4/corpus_report.json")


def test_per_gid_dirs():
    s4 = Path("/db/fw/stage4")
    assert layout.queries_dir(s4) == Path("/db/fw/stage4/queries")
    assert layout.retrieval_dir(s4) == Path("/db/fw/stage4/retrieval")
    assert layout.taint_dir(s4) == Path("/db/fw/stage4/taint")
    assert layout.debug_dir(s4) == Path("/db/fw/stage4/debug")


def test_gid_filenames_sanitize_double_colon():
    gid = "sbin_httpd__abc123#0000::candidate_001"
    expected = "sbin_httpd__abc123#0000__candidate_001.json"
    assert layout.query_plan_filename(gid) == expected
    assert layout.retrieval_filename(gid) == expected
    assert layout.taint_filename(gid) == expected


def test_stage4_summary_path():
    s4 = Path("/db/fw/stage4")
    assert layout.stage4_summary_path(s4) == Path("/db/fw/stage4/stage4_summary.json")
