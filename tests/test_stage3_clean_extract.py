"""Tests for `fw_audit.stage3_analysis.clean.extract.extract_functions` and
`clean.parser.get_parser`.

`tree-sitter`/`tree-sitter-c` are an optional extra (`stage3`) — tests that
need them are gated with `pytest.importorskip("tree_sitter_c")` so the rest
of the suite stays green without it installed; the `get_parser()`-raises
test instead forces the ImportError to exercise that degrade path directly.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from fw_audit.stage2_extraction.normalize.context import BinaryContext
from fw_audit.stage3_analysis.errors import Stage3InputError

pytest.importorskip("tree_sitter_c")

from fw_audit.stage3_analysis.clean.extract import extract_functions  # noqa: E402

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


def test_extract_functions_keeps_only_the_real_function():
    result = extract_functions(_SYNTHETIC_SOURCE, bin_id="test_bin", context=_context())

    names = [f.name for f in result.functions]
    assert names == ["add"]


def test_extract_functions_drops_typedef_struct_extern_and_macro():
    result = extract_functions(_SYNTHETIC_SOURCE, bin_id="test_bin", context=_context())

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
    result = extract_functions(_SYNTHETIC_SOURCE, bin_id="test_bin", context=_context())

    text = result.to_text()
    assert "pvVar1 = calloc" not in text
    assert "calloc" not in [f.name for f in result.functions]


def test_extract_functions_declares_undeclared_register_var():
    result = extract_functions(_SYNTHETIC_SOURCE, bin_id="test_bin", context=_context())

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
    result = extract_functions(source, bin_id="test_bin", context=BinaryContext())

    assert [f.name for f in result.functions] == ["first", "second"]
    text = result.to_text()
    assert text.index("first") < text.index("second")
    assert "int first(void)\n{\n  return 1;\n}" in text


def test_extract_functions_empty_input_no_functions():
    result = extract_functions("", bin_id="test_bin", context=BinaryContext())

    assert result.functions == ()
    # collapse_blank_lines guarantees a trailing newline even for empty
    # input, so total_lines is 1-2, not 0 -- what matters is that with no
    # functions kept, every line counts as dropped.
    assert result.dropped_line_count == result.total_lines


def test_extract_functions_no_functions_at_all():
    source = "typedef int myint;\nstruct s { int x; };\n"
    result = extract_functions(source, bin_id="test_bin", context=BinaryContext())

    assert result.functions == ()
    assert result.dropped_line_count == result.total_lines


def test_extract_functions_tolerates_broken_syntax_elsewhere():
    # tree-sitter is error-tolerant by design (built for editor use on
    # incomplete code) -- a real function elsewhere in a syntactically
    # broken file should still be recognized.
    source = "this is not valid C at all !!! ###\n\nint good_func(int x)\n{\n  return x + 1;\n}\n"

    result = extract_functions(source, bin_id="test_bin", context=BinaryContext())

    assert [f.name for f in result.functions] == ["good_func"]


def test_extract_functions_line_numbers_are_self_consistent():
    source = "int f(void)\n{\n  int a;\n  a = 1;\n  return a;\n}\n"

    result = extract_functions(source, bin_id="test_bin", context=BinaryContext())

    f = result.functions[0]
    assert f.start_line == 1
    # end_line derived from the extracted text's own newline count, so this
    # is self-consistent by construction -- verify it matches manual counting.
    assert f.end_line == f.start_line + f.text.count("\n")
    assert f.text.count("\n") == 5  # 6 lines, 5 newlines, no trailing \n


def test_get_parser_raises_actionable_error_when_tree_sitter_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "tree_sitter", None)
    monkeypatch.setitem(sys.modules, "tree_sitter_c", None)
    from fw_audit.stage3_analysis.clean import parser as parser_module

    parser_module.get_parser.cache_clear()
    try:
        with pytest.raises(Stage3InputError, match=r'pip install -e ".\[stage3\]"'):
            parser_module.get_parser()
    finally:
        parser_module.get_parser.cache_clear()


@pytest.mark.integration
def test_extract_functions_against_real_committed_wpasupp():
    """End-to-end against the real committed mirror-tree source in this
    repo -- confirms the concrete finding that motivated this session:
    the file's ~15,000-line boilerplate head block (prelude + type decls +
    thunk-wall externs) is fully excluded, leaving only real functions.

    Uses the REAL BinaryContext built from stage2_summary.json's function
    metadata (matching ingest.py's actual production usage) rather than
    EMPTY_CONTEXT: this file has real function bodies up to ~120KB, and
    `passes._is_self_forwarding_stub`'s regex is checked against every
    body's text when `may_stub()` doesn't veto it away first -- with an
    empty context every body gets checked (may_stub is unconditionally
    True), and that regex suffers catastrophic backtracking against a
    genuinely large non-matching body (confirmed: multi-minute hang with
    EMPTY_CONTEXT on this exact file). The real context vetoes the ~2,000
    known-name bodies via `known_function_names` before the regex ever
    runs on them, which is also what makes the real `--debug` path fast
    (~8s end to end) -- this is a pre-existing characteristic of reused
    `stage2_extraction` code, not something introduced here, and doesn't
    affect production usage since `ingest.py` always builds a real
    context."""
    project_root = Path(__file__).parent.parent
    real_source = (
        project_root
        / "data"
        / "db"
        / "GT-AXE16000_9.0.0.6_102_37487-gccf2eb6_491-gc7ec3_nand_squashfs_decompiled"
        / "sbin"
        / "wpasupp.c"
    )
    summary_path = (
        project_root
        / "data"
        / "db"
        / "GT-AXE16000_9.0.0.6_102_37487-gccf2eb6_491-gc7ec3_nand_squashfs"
        / "stage2"
        / "stage2_summary.json"
    )
    if not real_source.is_file() or not summary_path.is_file():
        pytest.skip("real committed mirror-tree source/summary not present")

    import json

    from fw_audit.common.schemas import GhidraFunction
    from fw_audit.stage2_extraction.normalize.context import build_context

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    binary = next(b for b in summary["binaries"] if b["bin_id"] == "sbin_wpasupp__b86e5cadc3c9")
    context = build_context(GhidraFunction(**f) for f in binary["functions"])

    text = real_source.read_text(encoding="utf-8", errors="replace")
    result = extract_functions(text, bin_id="sbin_wpasupp", context=context)

    # Range checks, not hardcoded exact counts -- these shift if Stage 2's
    # output changes, but should stay in this ballpark.
    assert 1900 <= len(result.functions) <= 2200
    assert result.dropped_line_count > 5000

    output = result.to_text()
    assert "fw-audit: Ghidra thunk/PLT stub" not in output
    assert "typedef unsigned char undefined" not in output
    assert "FW_AUDIT_GHIDRA_TYPES_H" not in output
