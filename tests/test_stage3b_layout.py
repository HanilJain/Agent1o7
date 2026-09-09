"""Tests for `fw_audit.stage3b_claims.layout` — pure path algebra."""

from __future__ import annotations

from pathlib import Path

from fw_audit.stage3b_claims import layout


def test_stage3b_dir():
    assert layout.stage3b_dir(Path("/db")) == Path("/db/stage3b")


def test_claims_summary_path():
    assert layout.claims_summary_path(Path("/db/stage3b")) == Path(
        "/db/stage3b/claims_summary.json"
    )


def test_findings_dir():
    assert layout.findings_dir(Path("/db/stage3b")) == Path("/db/stage3b/findings")


def test_finding_filename_hash_to_double_underscore_round_trip():
    chunk_id = "usr_sbin_httpd__a1b2c3#9000"
    filename = layout.finding_filename(chunk_id)
    assert filename == "usr_sbin_httpd__a1b2c3__9000.json"
    # Same inversion Stage 4/5's discovery logic performs.
    recovered = Path(filename).stem.replace("__", "#")
    # NOTE: bin_id itself may legitimately contain "__" (Stage 2's
    # sanitized names commonly do), so a literal round trip on THIS
    # specific id isn't guaranteed to reconstruct precisely — the load-
    # bearing property is that the LAST "#" survives to rpartition()
    # correctly, which the downstream contract test asserts on a real
    # emitted report instead.
    assert recovered.rsplit("#", 1)[-1] == "9000"


def test_finding_filename_matches_stage3_analysis_convention():
    from fw_audit.stage3_analysis import layout as stage3_layout

    chunk_id = "some_bin_id#0007"
    assert layout.finding_filename(chunk_id) == stage3_layout.finding_filename(chunk_id)


def test_source_dir_and_pages_cache_path():
    source_dir = layout.source_dir(Path("/db/stage3b"))
    assert source_dir == Path("/db/stage3b/source")
    assert layout.pages_cache_path(source_dir, "report") == Path(
        "/db/stage3b/source/report.pages.json"
    )


def test_debug_dir_and_blocks_debug_path():
    debug_dir = layout.debug_dir(Path("/db/stage3b"))
    assert debug_dir == Path("/db/stage3b/debug")
    assert layout.blocks_debug_path(debug_dir, "report") == Path(
        "/db/stage3b/debug/report.blocks.json"
    )
