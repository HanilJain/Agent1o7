"""Tests for `fw_audit.stage2_extraction.clean.extract` (`extract_functions`,
`respan_for_concatenated_text`), `clean.parser.get_parser`, and
`clean.index` (`to_index_json_dict`/`source_from_index_and_text`).

`tree-sitter`/`tree-sitter-c` are an optional extra (`stage2`, aliased
`stage3` for backward compatibility) -- tests that need them are gated
with `pytest.importorskip("tree_sitter_c")` so the rest of the suite stays
green without it installed; the `get_parser()`-raises test instead forces
the ImportError to exercise that degrade path directly.

Unlike the old `stage3_analysis.clean.extract_functions` this replaced,
`extract_functions` no longer repairs its input itself -- repair (thunk
stubs, register vars) now happens upstream via `normalize.pipeline.
build_clean_pipeline()`, exactly as `extract.py::_clean_whole_c` composes
them in production. Tests that need repaired input run the real pipeline
first, rather than re-implementing repair inline.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from fw_audit.stage2_extraction.normalize.context import BinaryContext

pytest.importorskip("tree_sitter_c")

from fw_audit.stage2_extraction.clean.errors import CleanUnavailableError  # noqa: E402
from fw_audit.stage2_extraction.clean.extract import (  # noqa: E402
    extract_functions,
    respan_for_concatenated_text,
)
from fw_audit.stage2_extraction.clean.index import (  # noqa: E402
    source_from_index_and_text,
    to_index_json_dict,
)
from fw_audit.stage2_extraction.normalize.pipeline import (  # noqa: E402
    build_clean_pipeline,
    normalize,
)

# The REAL shape Ghidra emits for a self-forwarding thunk/PLT stub —
# confirmed against `lib/libnvram.so.c` in this repo's real committed data
# (`void * calloc(size_t __nmemb,size_t __size) { void *pvVar1; pvVar1 =
# calloc(__nmemb,__size); return pvVar1; }`). NOT `return calloc(a, b);`
# directly — `passes._STUB_BODY_RE` requires the call assigned to a local
# first, with an optional trailing `return <that local>;`.
_THUNK_STUB = """void * calloc(size_t __nmemb,size_t __size)

{
  void *pvVar1;

  pvVar1 = calloc(__nmemb,__size);
  return pvVar1;
}
"""

_SYNTHETIC_SOURCE = f"""typedef unsigned char undefined1;

struct foo {{ int a; }};

extern void bar(void);

{_THUNK_STUB}
int add(int a, int b)
{{
  local_reg = in_r2;
  return a + b + local_reg;
}}

#define X 1
"""


def _context() -> BinaryContext:
    return BinaryContext(
        thunk_names=frozenset({"calloc"}),
        known_function_names=frozenset({"calloc", "add"}),
    )


def _repaired(text: str, context: BinaryContext) -> str:
    """Run the real production repair pipeline — `extract.py::
    _clean_whole_c` always calls this before `extract_functions`."""
    return normalize(text, build_clean_pipeline(context)).text


def test_extract_functions_keeps_only_the_real_function():
    repaired = _repaired(_SYNTHETIC_SOURCE, _context())
    result = extract_functions(repaired, bin_id="test_bin")

    names = [f.name for f in result.functions]
    assert names == ["add"]


def test_extract_functions_drops_typedef_struct_extern_and_macro():
    repaired = _repaired(_SYNTHETIC_SOURCE, _context())
    result = extract_functions(repaired, bin_id="test_bin")

    text = result.to_text()
    assert "typedef unsigned char undefined1" not in text
    assert "struct foo" not in text
    assert "extern void bar" not in text
    assert "#define X" not in text


def test_extract_functions_excludes_self_forwarding_thunk_stub():
    # The thunk stub is syntactically a function_definition (it has a body)
    # -- only replace_thunk_bodies's semantic check tells it apart from
    # real logic, so this specifically confirms that repair pass ran
    # before the tree-sitter filter, not just that the filter works.
    repaired = _repaired(_SYNTHETIC_SOURCE, _context())
    result = extract_functions(repaired, bin_id="test_bin")

    text = result.to_text()
    assert "pvVar1 = calloc" not in text
    assert "calloc" not in [f.name for f in result.functions]


def test_extract_functions_declares_undeclared_register_var():
    repaired = _repaired(_SYNTHETIC_SOURCE, _context())
    result = extract_functions(repaired, bin_id="test_bin")

    add_fn = next(f for f in result.functions if f.name == "add")
    assert "in_r2" in add_fn.text
    # declare_register_vars synthesizes a declaration, not just a bare use.
    assert "uintptr_t in_r2" in add_fn.text


def test_to_text_preserves_source_order_and_is_verbatim():
    source = """int first(void)
{
  return 1;
}

int second(void)
{
  return 2;
}
"""
    result = extract_functions(source, bin_id="test_bin")

    assert [f.name for f in result.functions] == ["first", "second"]
    text = result.to_text()
    assert text.index("first") < text.index("second")
    assert "int first(void)\n{\n  return 1;\n}" in text


def test_extract_functions_empty_input_no_functions():
    result = extract_functions("", bin_id="test_bin")

    assert result.functions == ()
    assert result.dropped_line_count == result.total_lines


def test_extract_functions_no_functions_at_all():
    source = "typedef int myint;\nstruct s { int x; };\n"
    result = extract_functions(source, bin_id="test_bin")

    assert result.functions == ()
    assert result.dropped_line_count == result.total_lines


def test_extract_functions_tolerates_broken_syntax_elsewhere():
    # tree-sitter is error-tolerant by design (built for editor use on
    # incomplete code) -- a real function elsewhere in a syntactically
    # broken file should still be recognized.
    source = "this is not valid C at all !!! ###\n\nint good_func(int x)\n{\n  return x + 1;\n}\n"

    result = extract_functions(source, bin_id="test_bin")

    assert [f.name for f in result.functions] == ["good_func"]


def test_extract_functions_line_numbers_are_self_consistent():
    source = "int f(void)\n{\n  int a;\n  a = 1;\n  return a;\n}\n"

    result = extract_functions(source, bin_id="test_bin")

    f = result.functions[0]
    assert f.start_line == 1
    # end_line derived from the extracted text's own newline count, so this
    # is self-consistent by construction -- verify it matches manual counting.
    assert f.end_line == f.start_line + f.text.count("\n")
    assert f.text.count("\n") == 5  # 6 lines, 5 newlines, no trailing \n


def test_get_parser_raises_actionable_error_when_tree_sitter_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "tree_sitter", None)
    monkeypatch.setitem(sys.modules, "tree_sitter_c", None)
    from fw_audit.stage2_extraction.clean import parser as parser_module

    parser_module.get_parser.cache_clear()
    try:
        with pytest.raises(CleanUnavailableError, match=r'pip install -e ".\[stage2\]"'):
            parser_module.get_parser()
    finally:
        parser_module.get_parser.cache_clear()


# --- respan_for_concatenated_text: the critical gotcha this design must not get wrong ---


def test_respan_matches_actual_concatenated_output():
    """The whole point of `respan_for_concatenated_text`: every entry's
    `[start_line, end_line]` slice of `"\\n\\n".join(...)` must equal that
    function's own `.text` exactly -- this is what `cleaned_io.
    load_cleaned_source` relies on to reconstruct functions from disk."""
    source = "int first(void)\n{\n  return 1;\n}\nint second(void)\n{\n  return 2;\n}\n"
    result = extract_functions(source, bin_id="test_bin")
    assert len(result.functions) == 2

    respanned = respan_for_concatenated_text(result.functions)
    whole = "\n\n".join(f.text for f in result.functions)
    lines = whole.split("\n")

    for entry in respanned:
        sliced = "\n".join(lines[entry.start_line - 1 : entry.end_line])
        assert sliced == entry.text

    # Spans must be non-overlapping and strictly increasing.
    assert respanned[0].start_line == 1
    assert respanned[1].start_line > respanned[0].end_line


def test_respan_single_function_starts_at_line_one():
    source = "int only(void)\n{\n  return 0;\n}\n"
    result = extract_functions(source, bin_id="test_bin")
    respanned = respan_for_concatenated_text(result.functions)

    assert len(respanned) == 1
    assert respanned[0].start_line == 1
    assert respanned[0].end_line == respanned[0].text.count("\n") + 1


def test_respan_empty_functions_returns_empty():
    assert respan_for_concatenated_text(()) == ()


# --- clean.index: JSON round-trip ---


def test_index_round_trip_reconstructs_identical_source():
    source = "int a(void)\n{\n  return 1;\n}\nint b(void)\n{\n  return 2;\n}\n"
    result = extract_functions(source, bin_id="test_bin")
    respanned = respan_for_concatenated_text(result.functions)
    result = result.model_copy(update={"functions": respanned})

    index = to_index_json_dict(result)
    whole_text = result.to_text()
    reconstructed = source_from_index_and_text(index, whole_text)

    assert reconstructed.bin_id == result.bin_id
    assert reconstructed.total_lines == result.total_lines
    assert reconstructed.dropped_line_count == result.dropped_line_count
    assert [(f.name, f.text) for f in reconstructed.functions] == [
        (f.name, f.text) for f in result.functions
    ]


def test_index_json_dict_never_includes_function_text():
    """The index is metadata-only (`name`/`start_line`/`end_line`) -- the
    text lives in `cleaned/whole.c`, not duplicated into the JSON index."""
    source = "int a(void)\n{\n  return 1;\n}\n"
    result = extract_functions(source, bin_id="test_bin")
    respanned = respan_for_concatenated_text(result.functions)
    result = result.model_copy(update={"functions": respanned})

    index = to_index_json_dict(result)
    for entry in index["functions"]:
        assert set(entry.keys()) == {"name", "start_line", "end_line"}


@pytest.mark.integration
def test_clean_pipeline_against_real_committed_wpasupp():
    """End-to-end against the real committed `raw/decompiled/whole.c` --
    confirms the concrete finding that motivated this feature: the file's
    boilerplate head block (prelude + type decls + thunk-wall externs) is
    fully excluded, leaving only real functions. Runs the exact production
    composition `extract.py::_clean_whole_c` uses: `build_clean_pipeline`
    -> `normalize` -> `extract_functions` -> `respan_for_concatenated_text`.

    Uses the REAL BinaryContext built from stage2_summary.json's function
    metadata (matching `extract.py`'s actual production usage) rather than
    EMPTY_CONTEXT -- see the (now-deleted) Stage 3 version of this test's
    original docstring for why that matters for `replace_thunk_bodies`'s
    performance against a ~120KB real function body.
    """
    project_root = Path(__file__).parent.parent
    raw_source = (
        project_root
        / "data"
        / "db"
        / "GT-AXE16000_9.0.0.6_102_37487-gccf2eb6_491-gc7ec3_nand_squashfs"
        / "stage2"
        / "binaries"
        / "sbin_wpasupp__b86e5cadc3c9"
        / "raw"
        / "decompiled"
        / "whole.c"
    )
    summary_path = (
        project_root
        / "data"
        / "db"
        / "GT-AXE16000_9.0.0.6_102_37487-gccf2eb6_491-gc7ec3_nand_squashfs"
        / "stage2"
        / "stage2_summary.json"
    )
    if not raw_source.is_file() or not summary_path.is_file():
        pytest.skip("real committed raw decompiled source/summary not present")

    import json

    from fw_audit.common.schemas import GhidraFunction
    from fw_audit.stage2_extraction.normalize.context import build_context

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    binary = next(b for b in summary["binaries"] if b["bin_id"] == "sbin_wpasupp__b86e5cadc3c9")
    context = build_context(GhidraFunction(**f) for f in binary["functions"])

    raw_text = raw_source.read_text(encoding="utf-8", errors="replace")
    repaired = normalize(raw_text, build_clean_pipeline(context)).text
    result = extract_functions(repaired, bin_id="sbin_wpasupp")
    respanned = respan_for_concatenated_text(result.functions)
    result = result.model_copy(update={"functions": respanned})

    # Range checks, not hardcoded exact counts -- these shift if Stage 2's
    # output changes, but should stay in this ballpark.
    assert 1900 <= len(result.functions) <= 2200
    assert result.dropped_line_count > 5000

    output = result.to_text()
    assert "fw-audit: Ghidra thunk/PLT stub" not in output
    assert "typedef unsigned char undefined" not in output
    assert "FW_AUDIT_GHIDRA_TYPES_H" not in output
