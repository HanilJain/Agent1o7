"""Tests for `normalize.structure`: function-body finding and splicing.

Covers the three bugs the module docstring documents as fixed relative to
the earlier per-pass implementation this replaced: quadratic runtime,
comment-blind header matching, and missed multi-line signatures — plus
`splice`'s edit-application contract.
"""

from __future__ import annotations

import time

from fw_audit.stage2_extraction.normalize import structure


def test_finds_simple_function_body():
    text = "void f(int a)\n{\n  return;\n}\n"
    bodies = structure.find_function_bodies(text)
    assert len(bodies) == 1
    assert bodies[0].name == "f"
    assert bodies[0].params == ("a",)
    assert text[bodies[0].body_start : bodies[0].body_end] == "\n  return;\n"


def test_finds_multiple_bodies_in_order():
    text = "void a(void)\n{\n}\n\nvoid b(void)\n{\n}\n"
    bodies = structure.find_function_bodies(text)
    assert [b.name for b in bodies] == ["a", "b"]


def test_finds_multiline_signature():
    text = (
        "bool wlcsm_mngr_resume_restart\n"
        "               (undefined4 param_1,undefined4 param_2)\n"
        "{\n  return true;\n}\n"
    )
    bodies = structure.find_function_bodies(text)
    assert len(bodies) == 1
    assert bodies[0].name == "wlcsm_mngr_resume_restart"
    assert bodies[0].params == ("param_1", "param_2")


def test_does_not_match_header_shaped_text_inside_a_comment():
    text = (
        "/* Unable to decompile 'FUN_0007783c(int param_1)\n"
        "Cause: something bad */\n"
        "\n"
        "void real_fn(void)\n"
        "{\n"
        "  return;\n"
        "}\n"
    )
    bodies = structure.find_function_bodies(text)
    assert [b.name for b in bodies] == ["real_fn"]


def test_braces_inside_string_literals_do_not_confuse_matching():
    text = 'void f(void)\n{\n  char *s = "{ not a brace }";\n  return;\n}\n'
    bodies = structure.find_function_bodies(text)
    assert len(bodies) == 1
    assert "{ not a brace }" in text[bodies[0].body_start : bodies[0].body_end]


def test_nested_braces_counted_correctly():
    text = "void f(void)\n{\n  if (1) {\n    if (2) {\n      x = 1;\n    }\n  }\n}\n"
    bodies = structure.find_function_bodies(text)
    assert len(bodies) == 1
    assert text[bodies[0].body_end] == "}"
    # body_end must be the OUTERMOST closing brace, not an inner one.
    assert text[bodies[0].body_start : bodies[0].body_end].count("{") == 2


def test_void_params_yield_no_param_names():
    text = "void f(void)\n{\n}\n"
    bodies = structure.find_function_bodies(text)
    assert bodies[0].params == ()


def test_no_functions_returns_empty_tuple():
    assert structure.find_function_bodies("int x;\nint y;\n") == ()


def test_splice_applies_multiple_non_overlapping_edits():
    text = "aaa bbb ccc"
    result = structure.splice(text, [(0, 3, "XXX"), (8, 11, "ZZZ")])
    assert result == "XXX bbb ZZZ"


def test_splice_accepts_edits_in_any_order():
    text = "aaa bbb ccc"
    result = structure.splice(text, [(8, 11, "ZZZ"), (0, 3, "XXX")])
    assert result == "XXX bbb ZZZ"


def test_splice_no_edits_returns_text_unchanged():
    text = "unchanged"
    assert structure.splice(text, []) == text


# --------------------------------------------------------------------- #
# Performance — the fix's actual payoff. Deterministic CPU work, no
# external dependency, so this should never flake.
# --------------------------------------------------------------------- #


def test_find_function_bodies_is_not_quadratic():
    """~500 synthetic functions / ~250 KB: the fixed (single-tokenize,
    offset-indexed) implementation handles this in a small fraction of a
    second; the quadratic implementation this replaced (re-tokenizing the
    remaining file per function header) scales with (file size *
    function count), so it would already show clear superlinear slowdown
    at this size. A 2-second budget leaves a wide margin while still
    catching a real regression back to O(n^2)."""
    parts = []
    for i in range(500):
        body = "  int x;\n" * 50
        parts.append(f"void FUN_{i:08x}(int param_1)\n{{\n{body}}}\n\n")
    text = "".join(parts)
    assert len(text) > 200_000

    start = time.time()
    bodies = structure.find_function_bodies(text)
    elapsed = time.time() - start

    assert len(bodies) == 500
    assert elapsed < 2.0, f"find_function_bodies took {elapsed:.2f}s — regressed to quadratic?"
