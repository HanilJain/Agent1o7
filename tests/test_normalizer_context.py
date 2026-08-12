"""Tests for the context-bound passes: `replace_thunk_bodies` and
`dedupe_global_declarations`, plus `normalize.context` itself.

Separated from `tests/test_normalizer.py` because these all need a
`BinaryContext` argument, unlike every other (plain `(str) -> str`) pass.
"""

from __future__ import annotations

from fw_audit.stage2_extraction.normalize import passes
from fw_audit.stage2_extraction.normalize.context import (
    EMPTY_CONTEXT,
    BinaryContext,
    build_context,
)

# --------------------------------------------------------------------- #
# normalize.context
# --------------------------------------------------------------------- #


class _F:
    def __init__(self, name: str, is_thunk: bool = False, is_external: bool = False) -> None:
        self.name = name
        self.is_thunk = is_thunk
        self.is_external = is_external


def test_build_context_tolerates_missing_thunk_external_fields():
    """`_write_metadata` in tests/test_stage2_extract.py emits function
    records with no `is_thunk`/`is_external` key at all — Pydantic's
    `GhidraFunction` defaults both to `False`, so `build_context` must
    accept that shape without raising."""

    class _Bare:
        def __init__(self, name: str) -> None:
            self.name = name
            self.is_thunk = False
            self.is_external = False

    ctx = build_context([_Bare("main")])
    assert ctx.known_function_names == frozenset({"main"})
    assert ctx.thunk_names == frozenset()


def test_may_stub_true_for_thunk():
    ctx = build_context([_F("calloc", is_thunk=True)])
    assert ctx.may_stub("calloc")


def test_may_stub_true_for_external():
    ctx = build_context([_F("printf", is_external=True)])
    assert ctx.may_stub("printf")


def test_may_stub_false_for_explicit_non_thunk():
    ctx = build_context([_F("main", is_thunk=False)])
    assert not ctx.may_stub("main")


def test_may_stub_true_for_unknown_name_truncation_case():
    """`metadata.json`'s function list is capped while the whole-program C
    export is not — an unlisted name means metadata has no opinion, not
    that it's confirmed non-thunk."""
    ctx = build_context([_F("main", is_thunk=False)])
    assert ctx.may_stub("some_function_metadata_never_recorded")


def test_is_function_symbol():
    ctx = build_context([_F("main")])
    assert ctx.is_function_symbol("main")
    assert not ctx.is_function_symbol("DAT_1")


def test_empty_context_may_stub_always_true():
    assert EMPTY_CONTEXT.may_stub("anything")


def test_empty_context_is_function_symbol_always_false():
    assert not EMPTY_CONTEXT.is_function_symbol("anything")


# --------------------------------------------------------------------- #
# passes.replace_thunk_bodies
# --------------------------------------------------------------------- #


def test_replaces_self_forwarding_thunk_with_extern():
    before = (
        "__sighandler_t signal(int __sig,__sighandler_t __handler)\n"
        "{\n"
        "  __sighandler_t p_Var1;\n"
        "  p_Var1 = signal(__sig,__handler);\n"
        "  return p_Var1;\n"
        "}\n"
    )
    after = passes.replace_thunk_bodies(EMPTY_CONTEXT, before)
    assert "extern __sighandler_t signal(int __sig,__sighandler_t __handler);" in after
    assert "p_Var1 = signal" not in after


def test_thunk_with_real_definition_elsewhere_is_deleted_not_declared():
    """Two bodies can legitimately share a name in one whole-program
    export: a thunk record and the real definition it forwards to. The
    stub must be deleted, not turned into an `extern` that would conflict
    with the real definition."""
    before = (
        "void wlcsm_nvram_commit_update(void)\n"
        "{\n"
        "  wlcsm_nvram_commit_update();\n"
        "  return;\n"
        "}\n"
        "\n"
        "void wlcsm_nvram_commit_update(void)\n"
        "{\n"
        "  int x;\n"
        "  x = 1;\n"
        "}\n"
    )
    after = passes.replace_thunk_bodies(EMPTY_CONTEXT, before)
    assert "extern void wlcsm_nvram_commit_update" not in after
    assert after.count("void wlcsm_nvram_commit_update(void)\n{") == 1
    assert "wlcsm_nvram_commit_update();" not in after  # the stub's self-call is gone
    assert "x = 1;" in after  # the real definition survives intact


def test_duplicate_thunk_records_collapse_to_one_extern():
    before = (
        "int strcmp(char *__s1,char *__s2)\n"
        "{\n"
        "  int iVar1;\n"
        "  iVar1 = strcmp(__s1,__s2);\n"
        "  return iVar1;\n"
        "}\n"
        "\n"
        "int strcmp(char *__s1,char *__s2)\n"
        "{\n"
        "  int iVar1;\n"
        "  iVar1 = strcmp(__s1,__s2);\n"
        "  return iVar1;\n"
        "}\n"
    )
    after = passes.replace_thunk_bodies(EMPTY_CONTEXT, before)
    assert after.count("extern int strcmp") == 1
    assert "iVar1 = strcmp(__s1,__s2);" not in after  # both self-forwarding bodies are gone


def test_genuine_recursion_is_never_touched_even_under_empty_context():
    """The load-bearing safety property: a thunk forwards its OWN
    parameters verbatim and does nothing else, so `fact(n - 1)` — not a
    bare identifier, and not `n` either — can never match. This must hold
    with no metadata at all, since metadata is truncated in practice."""
    before = (
        "int fact(int n)\n"
        "{\n"
        "  int r;\n"
        "  if (n <= 1) return 1;\n"
        "  r = fact(n - 1);\n"
        "  return r * n;\n"
        "}\n"
    )
    after = passes.replace_thunk_bodies(EMPTY_CONTEXT, before)
    assert after == before


def test_genuine_delegator_with_reordered_args_is_not_touched():
    """A one-line delegator that does NOT forward its own parameters
    verbatim, in order, must not be mistaken for a thunk."""
    before = (
        "int swap_call(int a,int b)\n"
        "{\n"
        "  int r;\n"
        "  r = swap_call(b,a);\n"
        "  return r;\n"
        "}\n"
    )
    after = passes.replace_thunk_bodies(EMPTY_CONTEXT, before)
    assert after == before


def test_metadata_explicit_non_thunk_vetoes_even_a_stub_shaped_body():
    ctx = BinaryContext(known_function_names=frozenset({"wrapper"}))
    before = "int wrapper(int a)\n{\n  int r;\n  r = wrapper(a);\n  return r;\n}\n"
    after = passes.replace_thunk_bodies(ctx, before)
    assert after == before


def test_metadata_confirmed_thunk_is_replaced():
    ctx = BinaryContext(thunk_names=frozenset({"signal"}))
    before = (
        "int signal(int a)\n"
        "{\n"
        "  int r;\n"
        "  r = signal(a);\n"
        "  return r;\n"
        "}\n"
    )
    after = passes.replace_thunk_bodies(ctx, before)
    assert "extern int signal(int a);" in after


def test_multiline_signature_thunk_is_handled():
    before = (
        "int wlcsm_mngr_get\n"
        "          (int a,int b)\n"
        "\n"
        "{\n"
        "  int r;\n"
        "  r = wlcsm_mngr_get(a,b);\n"
        "  return r;\n"
        "}\n"
    )
    after = passes.replace_thunk_bodies(EMPTY_CONTEXT, before)
    assert "extern int wlcsm_mngr_get(int a,int b);" in after


def test_replace_thunk_bodies_is_idempotent():
    before = (
        "int strcmp(char *__s1,char *__s2)\n"
        "{\n"
        "  int iVar1;\n"
        "  iVar1 = strcmp(__s1,__s2);\n"
        "  return iVar1;\n"
        "}\n"
    )
    once = passes.replace_thunk_bodies(EMPTY_CONTEXT, before)
    twice = passes.replace_thunk_bodies(EMPTY_CONTEXT, once)
    assert once == twice


def test_replace_thunk_bodies_noop_on_text_with_no_functions():
    before = "int x;\nint y;\n"
    after = passes.replace_thunk_bodies(EMPTY_CONTEXT, before)
    assert after == before


# --------------------------------------------------------------------- #
# passes.dedupe_global_declarations
# --------------------------------------------------------------------- #


def test_dedupe_global_declarations_is_idempotent():
    before = "undefined4 DAT_1;\nint DAT_1;\n"
    once = passes.dedupe_global_declarations(EMPTY_CONTEXT, before)
    twice = passes.dedupe_global_declarations(EMPTY_CONTEXT, once)
    assert once == twice
