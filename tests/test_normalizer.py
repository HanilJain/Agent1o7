"""Tests for fw_audit.stage2_extraction.normalize.

Two styles deliberately: inline before/after strings per pass (the diffs
are 1-3 lines, so inline is self-documenting) plus a golden fixture
exercising pass *interaction* that inline tests can't catch on their own.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from fw_audit.stage2_extraction.normalize import passes
from fw_audit.stage2_extraction.normalize.context import EMPTY_CONTEXT, BinaryContext, build_context
from fw_audit.stage2_extraction.normalize.pipeline import (
    CLEAN_PIPELINE,
    JOERN_PIPELINE,
    build_clean_pipeline,
    build_joern_pipeline,
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


def test_never_writes_into_raw():
    """`normalize/` must never perform filesystem writes at all — grep its
    own source for the write-capable Path methods rather than trying to
    exhaustively simulate every call path. If this ever needs a real
    `Path.write_text`/`write_bytes` call, it belongs in `extract.py`
    (which writes `normalized/`, never `raw/`), not in this package."""
    package_dir = Path(__file__).parent.parent / "fw_audit" / "stage2_extraction" / "normalize"
    offending: list[str] = []
    for py_file in package_dir.glob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        if ".write_text(" in text or ".write_bytes(" in text or "open(" in text:
            offending.append(py_file.name)
    assert not offending, f"normalize/ files perform filesystem writes: {offending}"


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


def test_mask_non_code_preserves_length_and_newlines():
    from fw_audit.stage2_extraction.normalize.spans import mask_non_code

    text = 'int x; /* c\no */\nchar *s = "a\nb";\nint y;\n'
    masked = mask_non_code(text)
    assert len(masked) == len(text)
    assert masked.count("\n") == text.count("\n")
    assert "int x;" in masked and "int y;" in masked
    assert "c" not in masked.split("\n")[1]  # comment body blanked


# --------------------------------------------------------------------- #
# Individual passes (inline before/after)
# --------------------------------------------------------------------- #


def test_p04_strips_calling_conventions():
    before = "int __fastcall FUN_00401234(int p1)\n{\n  return p1;\n}\n"
    after = passes.strip_calling_conventions(before)
    assert "__fastcall" not in after
    assert "int FUN_00401234(int p1)" in after


def test_p05_fixes_illegal_array_declaration():
    before = "undefined1[1372] mapInfo;\n"
    after = passes.fix_illegal_array_declarations(before)
    assert after.strip() == "undefined1 mapInfo[1372];"


def test_p05_fixes_illegal_array_declaration_with_named_type():
    before = "Elf32_Sym[1106] __DT_SYMTAB;\n"
    after = passes.fix_illegal_array_declarations(before)
    assert after.strip() == "Elf32_Sym __DT_SYMTAB[1106];"


def test_p05_does_not_touch_valid_local_array_declaration():
    before = "undefined1 auStack_10 [16];\n"
    after = passes.fix_illegal_array_declarations(before)
    assert after == before


def test_p05_is_idempotent():
    before = "undefined1[1372] mapInfo;\n"
    once = passes.fix_illegal_array_declarations(before)
    twice = passes.fix_illegal_array_declarations(once)
    assert once == twice


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


def test_p09_does_not_double_declare_a_name_ghidra_already_declared():
    """The headline regression: Ghidra itself declares roughly a third of
    these references in practice (`int extraout_r2;`), just never all of
    them in one body — injecting a second, differently-typed declaration
    next to Ghidra's own is a hard C error the OLD guard (which only
    recognized its own `uintptr_t NAME;` format) would create."""
    before = (
        "void FUN_1(void)\n"
        "{\n"
        "  int iVar1;\n"
        "  int extraout_r2;\n"
        "  iVar1 = extraout_r2;\n"
        "}\n"
    )
    after = passes.declare_register_vars(before)
    assert "uintptr_t extraout_r2;" not in after
    assert after.count("extraout_r2;") == 2  # the one Ghidra decl + the one use


def test_p09_uses_structure_module_and_handles_multiline_signature():
    before = (
        "bool wlcsm_mngr_resume_restart\n"
        "               (undefined4 param_1,undefined4 param_2)\n"
        "\n"
        "{\n"
        "  return unaff_r4 != 0;\n"
        "}\n"
    )
    after = passes.declare_register_vars(before)
    assert "uintptr_t unaff_r4;" in after


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
    # The second occurrence is deleted outright, no explanatory comment
    # left behind (that audit trail lives in normalization_report.json).
    active = [line for line in after.splitlines() if line.strip() == "typedef unsigned int foo;"]
    assert len(active) == 1
    assert "duplicate definition removed" not in after


def test_p12_keeps_distinct_typedefs():
    before = "typedef unsigned int foo;\ntypedef unsigned int bar;\n"
    after = passes.dedupe_type_definitions(before)
    assert after == before


# --------------------------------------------------------------------- #
# p12b — dedupe_global_declarations (context-bound)
# --------------------------------------------------------------------- #


def test_dedupe_global_declarations_removes_duplicate():
    before = "undefined4 DAT_1;\nint DAT_1;\n"
    after = passes.dedupe_global_declarations(EMPTY_CONTEXT, before)
    assert "undefined4 DAT_1;" in after
    # Deleted outright, no explanatory comment left behind.
    assert "duplicate global declaration removed" not in after
    active = [line for line in after.splitlines() if line.strip() == "int DAT_1;"]
    assert active == []


def test_dedupe_global_declarations_keeps_distinct_names():
    before = "undefined4 DAT_1;\nundefined4 DAT_2;\n"
    after = passes.dedupe_global_declarations(EMPTY_CONTEXT, before)
    assert after == before


def test_dedupe_global_declarations_does_not_touch_typedef_struct_or_fndecl():
    before = "typedef unsigned int foo;\nstruct bar { int x; };\nvoid FUN_1(int a);\n"
    after = passes.dedupe_global_declarations(EMPTY_CONTEXT, before)
    assert after == before


def test_dedupe_global_declarations_does_not_touch_indented_body_statement():
    before = "void FUN_1(void)\n{\n  int local;\n  local = 1;\n}\n"
    after = passes.dedupe_global_declarations(EMPTY_CONTEXT, before)
    assert after == before


def test_dedupe_global_declarations_removes_function_shadowing_decl_with_context():
    ctx = BinaryContext(known_function_names=frozenset({"FUN_x"}))
    before = "undefined FUN_x;\n"
    after = passes.dedupe_global_declarations(ctx, before)
    active = [line for line in after.splitlines() if line.strip() == "undefined FUN_x;"]
    assert active == []


def test_dedupe_global_declarations_keeps_shadowing_decl_under_empty_context():
    """Without metadata confirming `FUN_x` is a function, this pass has no
    way to know the declaration is wrong — it should not guess."""
    before = "undefined FUN_x;\n"
    after = passes.dedupe_global_declarations(EMPTY_CONTEXT, before)
    assert after == before


def test_p13_removes_conflicting_sigaction_declaration():
    before = "typedef unsigned int sigaction;\n"
    after = passes.drop_conflicting_builtin_decls(before)
    active = [
        line for line in after.splitlines() if line.strip() == "typedef unsigned int sigaction;"
    ]
    assert active == []
    # Deleted outright, no explanatory comment left behind.
    assert "conflicting builtin declaration" not in after


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


def test_line_comment_warning_stripped_for_joern():
    """The regression this whole pass exists to fix: Ghidra's CppExporter
    emits `// WARNING: ...` LINE comments in practice, not only the
    `/* WARNING: */` block form the old pattern matched exclusively."""
    before = "// WARNING: Unknown calling convention -- yet parameter storage is locked\nint x;\n"
    after = passes.strip_all_ghidra_warnings(before)
    assert "WARNING" not in after
    assert "int x;" in after


def test_whole_line_warning_comment_leaves_no_orphan_blank_line():
    before = "int a;\n\n// WARNING: something\n\nint b;\n"
    after = passes.strip_all_ghidra_warnings(before)
    assert after == "int a;\n\n\nint b;\n"


def test_trailing_warning_comment_on_code_line_keeps_the_code():
    before = "x = 1; // WARNING: something\ny = 2;\n"
    after = passes.strip_all_ghidra_warnings(before)
    assert "WARNING" not in after
    assert "x = 1;" in after
    assert "y = 2;" in after


def test_warning_text_inside_string_literal_is_untouched():
    before = 'char *s = "// WARNING: not a real comment";\n'
    after = passes.strip_all_ghidra_warnings(before)
    assert after == before


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


def test_joern_pipeline_removes_bare_halt_baddata_call():
    result = normalize(_load_fixture(), JOERN_PIPELINE)
    assert "halt_baddata()" not in result.text
    assert "__fw_audit_unreachable();" in result.text


def test_joern_pipeline_strips_calling_convention():
    result = normalize(_load_fixture(), JOERN_PIPELINE)
    assert "__fastcall" not in result.text


def test_joern_pipeline_dedupes_duplicate_sigaction_typedef_and_flags_conflict():
    result = normalize(_load_fixture(), JOERN_PIPELINE)
    # The fixture's SECOND `typedef unsigned int sigaction;` (duplicate) and
    # its top-level `sigaction` declarations (conflicting builtin) must both
    # be gone — deleted outright now, not commented out, so assert on
    # ACTIVE occurrence counts rather than an explanatory-comment string.
    active_sigaction_typedefs = [
        line
        for line in result.text.splitlines()
        if line.strip() == "typedef unsigned int sigaction;"
    ]
    assert len(active_sigaction_typedefs) <= 1
    assert "conflicting builtin declaration" not in result.text
    assert "duplicate definition removed" not in result.text


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


def test_pipelines_are_idempotent_on_plain_c_with_no_distortions():
    plain = "int add(int a, int b)\n{\n  return a + b;\n}\n"
    for pipeline in (JOERN_PIPELINE,):
        once = normalize(plain, pipeline).text
        twice = normalize(once, pipeline).text
        assert once == twice


def _fixture_context() -> BinaryContext:
    """The `BinaryContext` a real Stage 2 run would build for the golden
    fixture, from its companion metadata fixture (deliberately missing one
    thunk, exercising the truncation/veto path)."""

    class _FuncFacts:
        def __init__(self, d: dict) -> None:
            self.name = d["name"]
            self.is_thunk = d.get("is_thunk", False)
            self.is_external = d.get("is_external", False)

    metadata = json.loads(
        (FIXTURES_DIR / "sample_mips_httpd_metadata.json").read_text(encoding="utf-8")
    )
    return build_context(_FuncFacts(d) for d in metadata["functions"])


@pytest.mark.parametrize("build_pipeline", [build_joern_pipeline])
@pytest.mark.parametrize("context", [EMPTY_CONTEXT, None], ids=["empty_context", "real_context"])
def test_pipeline_is_idempotent_with_and_without_context(build_pipeline, context):
    """Generalizes the pipeline-idempotence test above to also cover the
    context-bound passes (`replace_thunk_bodies`,
    `dedupe_global_declarations`) under both a real `BinaryContext` and
    `EMPTY_CONTEXT`. Every new pass is designed so its own output falls
    outside its own input language (a spliced-out thunk body can't be
    re-found, a fixed array declarator no longer matches, edits become
    protected comments), so this should hold by construction."""
    ctx = context if context is not None else _fixture_context()
    pipeline = build_pipeline(ctx)
    once = normalize(_load_fixture(), pipeline).text
    twice = normalize(once, pipeline).text
    assert once == twice


def test_pipeline_constants_match_factory_defaults():
    """`JOERN_PIPELINE` is documented as `build_joern_pipeline()` (i.e. the
    `EMPTY_CONTEXT` case) — this pins that relationship so it can never
    silently drift apart."""
    assert [p.name for p in JOERN_PIPELINE] == [p.name for p in build_joern_pipeline()]


def test_clean_pipeline_constant_matches_factory_default():
    """`CLEAN_PIPELINE` is the LLM-target sibling of `JOERN_PIPELINE`,
    same guard against drifting from `build_clean_pipeline()`'s own
    default."""
    assert [p.name for p in CLEAN_PIPELINE] == [p.name for p in build_clean_pipeline()]


def test_clean_pipeline_shares_head_and_body_passes_with_joern():
    """`build_clean_pipeline` reuses `_head_passes`/`_body_passes`/
    `_tail_passes` verbatim (see `pipeline.py`'s module docstring) —
    the two pipelines must differ ONLY in their three target-specific
    passes (warnings/prelude/halt), never in the shared ones, and must
    stay the same LENGTH (one warnings + one prelude + one halt pass
    each)."""
    joern_names = [p.name for p in build_joern_pipeline()]
    clean_names = [p.name for p in build_clean_pipeline()]
    assert len(joern_names) == len(clean_names)

    shared = {
        "normalize_line_endings",
        "strip_calling_conventions",
        "fix_illegal_array_declarations",
        "fix_illegal_switch_labels",
        "replace_thunk_bodies",
        "declare_register_vars",
        "collapse_redundant_casts",
        "dedupe_type_definitions",
        "dedupe_global_declarations",
        "drop_conflicting_builtin_decls",
        "collapse_blank_lines",
    }
    assert shared <= set(joern_names)
    assert shared <= set(clean_names)


def test_clean_pipeline_does_not_inline_prelude_or_rewrite_halt_baddata():
    """The clean pipeline's whole reason for a no-op prelude/halt pass:
    an LLM reader needs neither `ghidra_types.h` inlined (the function-only
    filter downstream discards it anyway) nor the Joern-specific
    `halt_baddata()` rewrite."""
    text = "void f(void)\n{\n  halt_baddata();\n}\n"
    result = normalize(text, build_clean_pipeline())
    assert "FW_AUDIT_GHIDRA_TYPES_H" not in result.text
    assert "halt_baddata()" in result.text


# --------------------------------------------------------------------- #
# Prelude coverage — self-maintaining: fails if a new Ghidra type shows up
# in a fixture without a corresponding typedef in the generated header.
# --------------------------------------------------------------------- #


def test_prelude_covers_every_type_family_referenced_in_fixtures():
    import re

    type_family_re = re.compile(
        r"\b(undefined\d*|uint|ulong|ushort|byte|sbyte|word|dword|qword|code"
        r"|bool|pointer|ulonglong|longlong|string)\b"
    )
    fixture_text = _load_fixture()
    referenced = {m.group(1) for m in type_family_re.finditer(fixture_text)}
    for name in referenced:
        assert re.search(rf"\b{re.escape(name)}\b", PRELUDE_HEADER), (
            f"{name!r} appears in a fixture but has no declaration in ghidra_types.h"
        )
