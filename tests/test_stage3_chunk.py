"""Tests for `fw_audit.stage3_analysis.chunk.strategy.chunk_source`.

Unlike every other stage3 test file, this one needs NO `pytest.importorskip
("tree_sitter_c")` gate — `chunk_source` never re-parses; it only reads the
`start_line`/`end_line`/`text` already computed by a prior `extract_functions`
call, so `ExtractedFunction` literals are built directly here rather than
going through a real parse (mirrors this suite's `_`-prefixed local-builder
convention; no shared fixtures live in `tests/conftest.py` for stage3).
"""

from __future__ import annotations

import pytest

from fw_audit.stage3_analysis.chunk.strategy import chunk_source
from fw_audit.stage3_analysis.models import ExtractedFunction, ExtractedSource


def _function(
    name: str, start_line: int, end_line: int, text: str | None = None
) -> ExtractedFunction:
    """Build an `ExtractedFunction` literal directly. `chunk_source`'s line-
    span math only reads `start_line`/`end_line` (never re-derives them from
    `text`), so a placeholder body is fine; `text` defaults to a one-liner
    naming the function, useful for asserting on `Chunk.to_text()`'s
    content."""
    return ExtractedFunction(
        name=name,
        start_line=start_line,
        end_line=end_line,
        text=text if text is not None else f"void {name}(void) {{ /* body */ }}",
    )


def _source(*functions: ExtractedFunction, bin_id: str = "test_bin") -> ExtractedSource:
    total = sum(f.end_line - f.start_line + 1 for f in functions)
    return ExtractedSource(
        bin_id=bin_id, functions=functions, total_lines=total, dropped_line_count=0
    )


def _chunk_source(source: ExtractedSource, *, chunk_lines: int, max_chunk_lines: int = 4000):
    return chunk_source(
        source,
        bin_id=source.bin_id,
        rootfs_path="bin/test",
        source_relpath="bin/test.c",
        chunk_lines=chunk_lines,
        max_chunk_lines=max_chunk_lines,
    )


def test_chunk_source_empty_functions_returns_empty_tuple():
    source = _source()
    chunks = _chunk_source(source, chunk_lines=100)
    assert chunks == ()


def test_chunk_source_single_small_function_returns_one_chunk():
    f = _function("small", 1, 10)
    chunks = _chunk_source(_source(f), chunk_lines=100)
    assert len(chunks) == 1
    assert chunks[0].functions == (f,)
    assert chunks[0].oversized is False


def test_chunk_source_accumulates_multiple_small_functions_before_closing():
    # Four 40-line functions, chunk_lines=100: first three sum to 120 (>=100)
    # and close together; the fourth is flushed alone at the end.
    funcs = [
        _function("f1", 1, 40),
        _function("f2", 41, 80),
        _function("f3", 81, 120),
        _function("f4", 121, 160),
    ]
    chunks = _chunk_source(_source(*funcs), chunk_lines=100)
    assert len(chunks) == 2
    assert [f.name for f in chunks[0].functions] == ["f1", "f2", "f3"]
    assert [f.name for f in chunks[1].functions] == ["f4"]


def test_chunk_source_closing_function_stays_in_the_chunk_it_crossed():
    funcs = [
        _function("f1", 1, 40),
        _function("f2", 41, 80),
        _function("f3", 81, 120),
    ]
    chunks = _chunk_source(_source(*funcs), chunk_lines=100)
    # f3 is the function that pushes the running total (120) over chunk_lines
    # (100) -- it must be present in the SAME chunk, not deferred to a next one.
    assert len(chunks) == 1
    assert [f.name for f in chunks[0].functions] == ["f1", "f2", "f3"]


def test_chunk_source_function_exceeding_hard_cap_becomes_own_oversized_chunk():
    huge = _function("huge", 1, 5000)  # span 5000 > max_chunk_lines 4000
    chunks = _chunk_source(_source(huge), chunk_lines=1000, max_chunk_lines=4000)
    assert len(chunks) == 1
    assert chunks[0].oversized is True
    assert chunks[0].functions == (huge,)


def test_chunk_source_oversized_function_flushes_pending_chunk_first():
    small1 = _function("small1", 1, 10)
    huge = _function("huge", 11, 5010)  # span 5000 > max_chunk_lines 4000
    small2 = _function("small2", 5011, 5020)
    chunks = _chunk_source(
        _source(small1, huge, small2), chunk_lines=1000, max_chunk_lines=4000
    )
    assert len(chunks) == 3
    assert chunks[0].functions == (small1,)
    assert chunks[0].oversized is False
    assert chunks[1].functions == (huge,)
    assert chunks[1].oversized is True
    assert chunks[2].functions == (small2,)
    assert chunks[2].oversized is False


def test_chunk_source_function_between_soft_and_hard_limit_is_not_oversized():
    mid = _function("mid", 1, 2000)  # chunk_lines=1000 <= span=2000 <= max=4000
    chunks = _chunk_source(_source(mid), chunk_lines=1000, max_chunk_lines=4000)
    assert len(chunks) == 1
    assert chunks[0].oversized is False
    assert chunks[0].functions == (mid,)


def test_chunk_source_between_limit_function_merges_when_room_under_hard_cap():
    small = _function("small", 1, 100)  # span 100
    mid = _function("mid", 101, 2100)  # span 2000; 100+2000=2100 <= max 4000
    chunks = _chunk_source(_source(small, mid), chunk_lines=1000, max_chunk_lines=4000)
    assert len(chunks) == 1
    assert [f.name for f in chunks[0].functions] == ["small", "mid"]
    assert chunks[0].oversized is False


def test_chunk_source_between_limit_function_flushes_pending_when_it_would_exceed_hard_cap():
    big_pending = _function("big_pending", 1, 3000)  # span 3000, below chunk_lines? no,
    # chunk_lines default here will be set higher than 3000 so it stays pending
    mid = _function("mid", 3001, 5000)  # span 2000; 3000+2000=5000 > max 4000
    chunks = _chunk_source(
        _source(big_pending, mid), chunk_lines=3500, max_chunk_lines=4000
    )
    # big_pending alone (3000 lines) is below chunk_lines (3500), so it stays
    # pending after being added. Adding mid (2000) would push total to 5000,
    # over max_chunk_lines (4000) -- pending must flush BEFORE merging.
    assert len(chunks) == 2
    assert chunks[0].functions == (big_pending,)
    assert chunks[0].oversized is False
    assert chunks[1].functions == (mid,)
    assert chunks[1].oversized is False


def test_chunk_source_never_splits_a_function_flattened_functions_equal_input():
    funcs = [
        _function("f1", 1, 5),
        _function("f2", 6, 400),
        _function("f3", 401, 401),
        _function("f4", 402, 4500),  # oversized
        _function("f5", 4501, 4600),
        _function("f6", 4601, 5200),
    ]
    source = _source(*funcs)
    chunks = _chunk_source(source, chunk_lines=300, max_chunk_lines=4000)
    flattened = [f for chunk in chunks for f in chunk.functions]
    assert flattened == list(source.functions)


def test_chunk_source_preserves_original_function_order_across_chunk_boundaries():
    funcs = [_function(f"f{i}", i * 10 + 1, i * 10 + 10) for i in range(20)]
    source = _source(*funcs)
    chunks = _chunk_source(source, chunk_lines=50, max_chunk_lines=4000)
    flattened_names = [f.name for chunk in chunks for f in chunk.functions]
    assert flattened_names == [f.name for f in funcs]


def test_chunk_source_chunk_ids_are_bin_id_prefixed_and_zero_padded():
    funcs = [_function(f"f{i}", i * 10 + 1, i * 10 + 10) for i in range(3)]
    source = _source(*funcs, bin_id="sbin_wpasupp__abc123")
    chunks = _chunk_source(source, chunk_lines=5, max_chunk_lines=4000)
    assert chunks[0].chunk_id == "sbin_wpasupp__abc123#0000"
    assert chunks[1].chunk_id == "sbin_wpasupp__abc123#0001"
    assert chunks[2].chunk_id == "sbin_wpasupp__abc123#0002"


def test_chunk_source_start_end_line_span_first_and_last_function():
    funcs = [
        _function("f1", 10, 20),
        _function("f2", 21, 35),
    ]
    chunks = _chunk_source(_source(*funcs), chunk_lines=100)
    assert len(chunks) == 1
    assert chunks[0].start_line == 10
    assert chunks[0].end_line == 35


def test_chunk_source_approx_tokens_equals_text_length_over_four():
    f = _function("f1", 1, 5, text="void f1(void) { return; }")
    chunks = _chunk_source(_source(f), chunk_lines=100)
    assert chunks[0].approx_tokens == len(chunks[0].to_text()) // 4


def test_chunk_source_to_text_joins_function_texts_with_blank_line_separator():
    f1 = _function("f1", 1, 2, text="void f1(void) {}")
    f2 = _function("f2", 3, 4, text="void f2(void) {}")
    chunks = _chunk_source(_source(f1, f2), chunk_lines=100)
    assert chunks[0].to_text() == "void f1(void) {}\n\nvoid f2(void) {}"


def test_chunk_to_json_dict_excludes_functions_includes_function_names():
    f1 = _function("f1", 1, 5)
    f2 = _function("f2", 6, 10)
    chunks = _chunk_source(_source(f1, f2), chunk_lines=100)
    d = chunks[0].to_json_dict()
    assert set(d.keys()) == {
        "chunk_id",
        "bin_id",
        "rootfs_path",
        "source_relpath",
        "start_line",
        "end_line",
        "approx_tokens",
        "function_names",
        "oversized",
    }
    assert "functions" not in d
    assert d["function_names"] == ["f1", "f2"]


def test_chunk_source_rootfs_path_and_source_relpath_propagate_to_every_chunk():
    funcs = [_function(f"f{i}", i * 10 + 1, i * 10 + 10) for i in range(5)]
    chunks = chunk_source(
        _source(*funcs),
        bin_id="test_bin",
        rootfs_path="sbin/wpasupp",
        source_relpath="sbin/wpasupp.c",
        chunk_lines=15,
        max_chunk_lines=4000,
    )
    assert len(chunks) > 1
    for c in chunks:
        assert c.rootfs_path == "sbin/wpasupp"
        assert c.source_relpath == "sbin/wpasupp.c"


def test_chunk_source_bin_id_param_independent_of_source_bin_id():
    f = _function("f1", 1, 10)
    source = _source(f, bin_id="source_bin_id")
    chunks = chunk_source(
        source,
        bin_id="param_bin_id",
        rootfs_path="bin/test",
        source_relpath="bin/test.c",
        chunk_lines=100,
        max_chunk_lines=4000,
    )
    assert chunks[0].bin_id == "param_bin_id"
    assert chunks[0].chunk_id == "param_bin_id#0000"


def test_chunk_source_chunk_lines_greater_than_max_chunk_lines_raises_value_error():
    f = _function("f1", 1, 10)
    with pytest.raises(ValueError, match="must not exceed"):
        _chunk_source(_source(f), chunk_lines=5000, max_chunk_lines=4000)
