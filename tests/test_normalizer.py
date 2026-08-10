"""Tests for fw_audit.stage2_extraction.normalize.

Two styles deliberately: inline before/after strings per pass (the diffs
are 1-3 lines, so inline is self-documenting) plus a golden fixture
exercising pass *interaction* that inline tests can't catch on their own.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from fw_audit.stage2_extraction.normalize import passes
from fw_audit.stage2_extraction.normalize.pipeline import (
    JOERN_PIPELINE,
    LLM_PIPELINE,
    normalize,
)
from fw_audit.stage2_extraction.normalize.prelude import PRELUDE_HEADER
from fw_audit.stage2_extraction.normalize.spans import SpanKind, apply_to_code, tokenize

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "ghidra"

# --------------------------------------------------------------------- #
# Import purity — mirrors tests/test_identifier_agent.py::test_import_purity_*
# --------------------------------------------------------------------- #


def test_normalize_import_purity_no_executor_no_os_no_subprocess():
    """Run in a FRESH interpreter (not this process's sys.modules, which
    other test modules may have already polluted) — the only reliable way
    to observe normalize's own transitive import set in isolation."""
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import fw_audit.stage2_extraction.normalize.pipeline, sys; "
            "leaked = {'fw_audit.executors', 'subprocess'} & set(sys.modules); "
            "assert not leaked, f'normalize transitively imported: {leaked}'",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr


# --------------------------------------------------------------------- #
# spans.py
# --------------------------------------------------------------------- #


def test_tokenize_reassembles_exactly():
    text = 'int x = 1; // a comment\nchar *s = "a \\"quoted\\" /* not a comment */ string";\n'
    spans = tokenize(text)
    assert "".join(s.text for s in spans) == text


def test_spans_protect_string_literals():
    text = 'char *s = "__fastcall undefined4";\n'
    result = apply_to_code(text, lambda code: code.replace("undefined4", "uint32_t"))
    assert result == text  # untouched — the match was inside a STRING span


def test_spans_classify_block_comment():
    spans = tokenize("/* a comment */")
    assert len(spans) == 1
    assert spans[0].kind == SpanKind.COMMENT


# --------------------------------------------------------------------- #
# Individual passes (inline before/after)
# --------------------------------------------------------------------- #


def test_p04_strips_calling_conventions():
    before = "int __fastcall FUN_00401234(int p1)\n{\n  return p1;\n}\n"
    after = passes.strip_calling_conventions(before)
    assert "__fastcall" not in after
    assert "int FUN_00401234(int p1)" in after


def test_p08_rewrites_double_colon_switch_labels():
    before = "  goto switchD_00401234::caseD_5;\nswitchD_00401234::caseD_5:\n"
    after = passes.fix_illegal_switch_labels(before)
    assert "::" not in after
    assert "switchD_00401234_caseD_5" in after


def test_p08_rewrites_double_colon_default_switch_label():
    """Confirmed against real Ghidra output (decompiling /bin/ls): a
    switch's default case is emitted as switchD_<addr>::default, not a
    caseD_* label — the fix must not be scoped to caseD_ only."""
    before = "  goto switchD_00112f76::default;\nswitchD_00112f76::default:\n"
    after = passes.fix_illegal_switch_labels(before)
    assert "::" not in after
    assert "switchD_00112f76_default" in after


def test_p08b_halt_baddata_joern_becomes_declared_noop_call():
    after = passes.rewrite_halt_baddata_for_joern("  halt_baddata();\n")
    assert after.strip() == "__fw_audit_unreachable();"


def test_p08b_halt_baddata_llm_becomes_comment():
    after = passes.rewrite_halt_baddata_for_llm("  halt_baddata();\n")
    assert "halt_baddata" not in after
    assert "/* ghidra:" in after


def test_p09_declares_in_fs_offset_inside_the_function():
    before = (
        "void FUN_00401234(void)\n"
        "{\n"
        "  int iVar1;\n"
        "  iVar1 = *(int *)(in_FS_OFFSET + 0x14);\n"
        "}\n"
    )
    after = passes.declare_register_vars(before)
    assert "uintptr_t in_FS_OFFSET;" in after
    # declared before first use
    assert after.index("uintptr_t in_FS_OFFSET;") < after.index("iVar1 = *(int *)(in_FS_OFFSET")


def test_p09_does_not_declare_unused_register_vars():
    before = "void FUN_00401234(void)\n{\n  return;\n}\n"
    after = passes.declare_register_vars(before)
    assert after == before


def test_p09_declares_each_name_once_even_if_used_twice():
    before = (
        "void FUN_00401234(void)\n"
        "{\n"
        "  int a = unaff_EBX;\n"
        "  int b = unaff_EBX;\n"
        "}\n"
    )
    after = passes.declare_register_vars(before)
    assert after.count("uintptr_t unaff_EBX;") == 1


def test_p10_collapses_exact_duplicate_casts():
    before = "uVar1 = (uint)(uint)x;\n"
    after = passes.collapse_redundant_casts(before)
    assert after.strip() == "uVar1 = (uint)x;"


def test_p10_does_not_collapse_real_sign_extension():
    before = "iVar1 = (int)(char)x;\n"
    after = passes.collapse_redundant_casts(before)
    assert after == before


def test_p10_does_not_touch_pointer_arithmetic():
    before = "iVar1 = *(int *)(param_1 + 0x10);\n"
    after = passes.collapse_redundant_casts(before)
    assert after == before


def test_p10_drops_void_zero_statement():
    after = passes.collapse_redundant_casts("  (void)0;\n")
    assert "(void)0" not in after


def test_p12_dedupes_duplicate_typedef():
    before = "typedef unsigned int foo;\ntypedef unsigned int foo;\n"
    after = passes.dedupe_type_definitions(before)
    # The second occurrence is commented out (its original text still
    # appears, inside the explanatory comment) — assert on ACTIVE lines.
    active = [line for line in after.splitlines() if line.strip() == "typedef unsigned int foo;"]
    assert len(active) == 1
    assert "duplicate definition removed" in after


def test_p12_keeps_distinct_typedefs():
    before = "typedef unsigned int foo;\ntypedef unsigned int bar;\n"
    after = passes.dedupe_type_definitions(before)
    assert after == before


def test_p13_removes_conflicting_sigaction_declaration():
    before = "typedef unsigned int sigaction;\n"
    after = passes.drop_conflicting_builtin_decls(before)
    active = [
        line for line in after.splitlines() if line.strip() == "typedef unsigned int sigaction;"
    ]
    assert active == []
    assert "conflicting builtin declaration" in after


def test_p13_does_not_touch_indented_call_site():
    """Only column-0 declarations are targeted — an indented call inside a
    function body is a real statement, not one of Ghidra's bogus decls."""
    before = "void FUN_1(void)\n{\n  sigaction(1, 0, 0);\n}\n"
    after = passes.drop_conflicting_builtin_decls(before)
    assert after == before


def test_p14_collapses_blank_lines():
    before = "a;\n\n\n\n\nb;\n"
    after = passes.collapse_blank_lines(before)
    assert after == "a;\n\nb;\n"


def test_warning_comment_stripped_for_joern():
    before = "/* WARNING: something odd */\nint x;\n"
    after = passes.strip_all_ghidra_warnings(before)
    assert "WARNING" not in after
    assert "int x;" in after


def test_semantic_warning_comment_kept_for_llm():
    before = "/* WARNING: Subroutine does not return */\nint x;\n"
    after = passes.strip_non_semantic_ghidra_warnings(before)
    assert "Subroutine does not return" in after


def test_non_semantic_warning_comment_stripped_for_llm():
    before = "/* WARNING: some unrelated note */\nint x;\n"
    after = passes.strip_non_semantic_ghidra_warnings(before)
    assert "WARNING" not in after


# --------------------------------------------------------------------- #
# Full pipeline, golden fixture (pass INTERACTION coverage)
# --------------------------------------------------------------------- #


def _load_fixture() -> str:
    return (FIXTURES_DIR / "sample_mips_httpd.c").read_text(encoding="utf-8")


def test_joern_pipeline_output_has_no_double_colon():
    result = normalize(_load_fixture(), JOERN_PIPELINE)
    assert "::" not in result.text


def test_joern_pipeline_inlines_prelude():
    result = normalize(_load_fixture(), JOERN_PIPELINE)
    assert "typedef uint32_t undefined4;" in result.text
    assert result.text.index("typedef uint32_t undefined4;") < result.text.index("FUN_00401234")


def test_llm_pipeline_includes_prelude_header():
    result = normalize(_load_fixture(), LLM_PIPELINE)
    assert '#include "ghidra_types.h"' in result.text
    assert "typedef uint32_t undefined4;" not in result.text  # not inlined for LLM


def test_joern_pipeline_removes_bare_halt_baddata_call():
    result = normalize(_load_fixture(), JOERN_PIPELINE)
    assert "halt_baddata()" not in result.text
    assert "__fw_audit_unreachable();" in result.text


def test_joern_pipeline_strips_calling_convention():
    result = normalize(_load_fixture(), JOERN_PIPELINE)
    assert "__fastcall" not in result.text


def test_joern_pipeline_dedupes_duplicate_sigaction_typedef_and_flags_conflict():
    result = normalize(_load_fixture(), JOERN_PIPELINE)
    assert "duplicate definition removed" in result.text
    assert "conflicting builtin declaration" in result.text


def test_pipeline_result_records_source_hash_and_stats():
    fixture = _load_fixture()
    result = normalize(fixture, JOERN_PIPELINE)
    assert len(result.source_sha256) == 64
    assert len(result.stats) == len(JOERN_PIPELINE)
    assert all(stat.chars_before >= 0 for stat in result.stats)


# --------------------------------------------------------------------- #
# Idempotence — the single highest-value property test for a rewriting
# pipeline: it catches almost every ordering/over-matching bug.
# --------------------------------------------------------------------- #


def test_joern_pipeline_is_idempotent():
    once = normalize(_load_fixture(), JOERN_PIPELINE).text
    twice = normalize(once, JOERN_PIPELINE).text
    assert once == twice


def test_llm_pipeline_is_idempotent():
    once = normalize(_load_fixture(), LLM_PIPELINE).text
    twice = normalize(once, LLM_PIPELINE).text
    assert once == twice


def test_pipelines_are_idempotent_on_plain_c_with_no_distortions():
    plain = "int add(int a, int b)\n{\n  return a + b;\n}\n"
    for pipeline in (JOERN_PIPELINE, LLM_PIPELINE):
        once = normalize(plain, pipeline).text
        twice = normalize(once, pipeline).text
        assert once == twice


# --------------------------------------------------------------------- #
# Prelude coverage — self-maintaining: fails if a new Ghidra type shows up
# in a fixture without a corresponding typedef in the generated header.
# --------------------------------------------------------------------- #


def test_prelude_covers_every_type_family_referenced_in_fixtures():
    import re

    type_family_re = re.compile(
        r"\b(undefined\d*|uint|ulong|ushort|byte|sbyte|word|dword|qword|code)\b"
    )
    fixture_text = _load_fixture()
    referenced = {m.group(1) for m in type_family_re.finditer(fixture_text)}
    for name in referenced:
        assert re.search(rf"\b{re.escape(name)}\b", PRELUDE_HEADER), (
            f"{name!r} appears in a fixture but has no declaration in ghidra_types.h"
        )
