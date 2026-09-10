"""Tests for fw_audit.stage2_extraction.validate — the pipeline validation
gate the Stage 2 Normalization Hardening Spec calls for.

Structure mirrors the seven defect classes: one Layer A check per class
(plus the general structural checks), `apply_policy`'s three-way truth
table, `ValidationResult`/`ValidationIssue` round-tripping, and Layer B
(`gcc`, `integration`-marked and skipped when no compiler is on PATH —
same discipline as `test_normalizer_gcc.py`).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from fw_audit.stage2_extraction.normalize.pipeline import JOERN_PIPELINE, normalize
from fw_audit.stage2_extraction.validate import structural, syntax, validate_file, validate_text
from fw_audit.stage2_extraction.validate.policy import apply_policy
from fw_audit.stage2_extraction.validate.result import Severity, ValidationIssue, ValidationResult

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "ghidra"


def _issue(check: str, severity: Severity = Severity.ERROR) -> ValidationIssue:
    return ValidationIssue(check=check, defect_class=0, severity=severity, message="x")


# --------------------------------------------------------------------- #
# Layer A — one check per defect class (unit-scoped, no fixtures needed)
# --------------------------------------------------------------------- #


def test_span_sync_detects_a_multiline_string_span():
    # Two quotes on one line, unbalanced (the third pairs with a much
    # later quote) — the exact real-firmware shape (see `passes.py`'s
    # module docstring for the measured impact).
    text = 'x = "a" "b\ny = "c";\n'
    issues = structural.run(text)
    assert any(i.check == "span_sync" and i.severity is Severity.ERROR for i in issues)


def test_span_sync_finds_nothing_on_balanced_strings():
    text = 'x = "a";\ny = "b";\n'
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "span_sync"]


def test_illegal_identifier_detects_a_residual_symbol():
    text = 'undefined *PTR_s_<not_sanitized>_1000abcd;\n'
    issues = structural.run(text)
    assert any(i.check == "illegal_identifier" for i in issues)


def test_illegal_identifier_finds_nothing_on_clean_symbols():
    text = "undefined *PTR_s_clean_1000abcd;\n"
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "illegal_identifier"]


def test_double_colon_detects_a_real_switch_label():
    text = "  switchD_0040593c::caseD_5:\n"
    issues = structural.run(text)
    assert any(i.check == "double_colon" for i in issues)


def test_double_colon_ignores_a_string_literal():
    """Confirmed real: `puts("mgmt::beacon")` on real firmware — `::`
    inside a string literal is legal C and must never be flagged."""
    text = 'puts("mgmt::beacon");\n'
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "double_colon"]


def test_undefined_intrinsic_detects_a_macro_used_but_not_defined():
    text = "x = CONCAT21(a, b);\n"
    issues = structural.run(text)
    assert any(i.check == "undefined_intrinsic" and "CONCAT21" in i.detail for i in issues)


def test_undefined_intrinsic_finds_nothing_when_defined():
    text = "#define CONCAT21(hi, lo) (hi)\nx = CONCAT21(a, b);\n"
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "undefined_intrinsic"]


def test_undefined_intrinsic_detects_a_phantom_type():
    """Direct regression for the `uint24_t`-poison defect."""
    text = "#define CONCAT13(hi, lo) ((uint24_t)(lo))\n"
    issues = structural.run(text)
    assert any(
        i.check == "undefined_intrinsic" and "uint24_t" in i.detail for i in issues
    )


def test_undefined_intrinsic_ignores_a_phantom_type_mentioned_only_in_a_comment():
    """A phantom-type NAME appearing in prose (explaining the historical
    bug, say) must not be flagged — only a live reference in CODE."""
    text = "/* an old bug referenced uint24_t here */\nint x;\n"
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "undefined_intrinsic"]


def test_anonymous_enumerator_detects_a_value_only_member():
    text = "typedef enum X {\n    A=1,\n    =1879048203,\n} X;\n"
    issues = structural.run(text)
    assert any(i.check == "anonymous_enumerator" for i in issues)


def test_anonymous_enumerator_finds_nothing_on_named_members():
    text = "typedef enum X {\n    A=1,\n    B=2,\n} X;\n"
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "anonymous_enumerator"]


def test_duplicate_global_detects_conflicting_types():
    text = "int *DAT_1000;\nvoid *DAT_1000;\n"
    issues = structural.run(text)
    assert any(i.check == "duplicate_global" for i in issues)


def test_duplicate_global_ignores_identical_redeclaration():
    """`dedupe_global_declarations` handles the identical-type case; this
    check is scoped to CONFLICTING types only."""
    text = "int *DAT_1000;\nint *DAT_1000;\n"
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "duplicate_global"]


def test_void_value_use_detects_a_survivor():
    text = "void FUN_1(void)\n{\n  return;\n}\nint caller(void)\n{\n  int a;\n  a = FUN_1();\n}\n"
    issues = structural.run(text)
    hits = [i for i in issues if i.check == "void_value_use"]
    assert hits and hits[0].severity is Severity.WARNING


def test_void_value_use_finds_nothing_when_already_promoted():
    text = "int FUN_1(void)\n{\n  return 0;\n}\nint caller(void)\n{\n  int a;\n  a = FUN_1();\n}\n"
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "void_value_use"]


def test_missing_prototype_detects_a_call_before_definition():
    text = "int a(void)\n{\n  return b();\n}\nint b(void)\n{\n  return 0;\n}\n"
    issues = structural.run(text)
    hits = [i for i in issues if i.check == "missing_prototype"]
    assert hits and hits[0].severity is Severity.WARNING


def test_missing_prototype_recognizes_a_multiline_definition_header():
    """Direct regression: an earlier version of this check seeded its
    "already declared" set from a hand-rolled regex requiring `(...)` and
    `{` on ONE line, which silently failed to recognize a multi-line-
    signature DEFINITION as a declaration at all — the same class of bug
    this check exists to catch, not reproduce. `bool wlcsm_mngr_resume_
    restart\\n     (params)\\n{` is `structure.py`'s own documented real
    shape (confirmed on real firmware). Here the multi-line-signature
    function is called only AFTER its own definition, so it must produce
    NO issue — a version seeding from the broken regex would still flag
    it as "called before any declaration"."""
    text = (
        "bool b\n            (void)\n{\n  return 1;\n}\n\n"
        "int a(void)\n{\n  return b();\n}\n"
    )
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "missing_prototype" and i.detail == "b"]


def test_missing_prototype_finds_nothing_when_hoisted():
    text = "int b(void);\nint a(void)\n{\n  return b();\n}\nint b(void)\n{\n  return 0;\n}\n"
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "missing_prototype"]


def test_unresolved_include_detects_any_include():
    text = "#include <stdint.h>\nint x;\n"
    issues = structural.run(text)
    assert any(i.check == "unresolved_include" for i in issues)


def test_unresolved_include_finds_nothing_without_one():
    text = "int x;\n"
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "unresolved_include"]


def test_brace_balance_detects_unmatched_closing_brace():
    text = "int f(void)\n{\n  return 0;\n}\n}\n"
    issues = structural.run(text)
    assert any(i.check == "brace_balance" for i in issues)


def test_brace_balance_detects_unclosed_brace():
    text = "int f(void)\n{\n  return 0;\n"
    issues = structural.run(text)
    assert any(i.check == "brace_balance" for i in issues)


def test_halt_baddata_detects_a_residual_call():
    text = "void f(void)\n{\n  halt_baddata();\n}\n"
    issues = structural.run(text)
    assert any(i.check == "halt_baddata" for i in issues)


def test_halt_baddata_finds_nothing_after_rewrite():
    text = "void f(void)\n{\n  __fw_audit_unreachable();\n}\n"
    issues = structural.run(text)
    assert not [i for i in issues if i.check == "halt_baddata"]


def test_a_clean_file_yields_zero_issues():
    text = "int add(int a, int b)\n{\n  return a + b;\n}\n"
    assert structural.run(text) == ()


# --------------------------------------------------------------------- #
# Every fixture triggers exactly its own defect class(es) and nothing else
# --------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "fixture_name,expected_checks",
    [
        ("defect_anonymous_enumerator.c", {"anonymous_enumerator"}),
        # `duplicate_global` (the DAT_10000db0 triplet) does NOT appear
        # yet here — it sits INSIDE the fixture's own bogus multi-line
        # STRING span (`span_sync`), so `mask_non_code` blanks it out
        # along with everything else in that span. This is exactly the
        # real-firmware behaviour the fixture demonstrates: Class 2
        # mostly self-resolves once Class 3 heals the span, which is why
        # `duplicate_global` shows up in the AFTER-normalization test
        # below instead of here.
        ("defect_illegal_identifiers.c", {"illegal_identifier", "span_sync"}),
        ("defect_intrinsic_macros.c", {"undefined_intrinsic"}),
        ("defect_void_function_result.c", {"void_value_use"}),
        ("defect_missing_prototypes.c", {"missing_prototype"}),
        ("defect_stdint_free.c", set()),
    ],
)
def test_fixture_triggers_only_its_own_defect_class_before_normalization(
    fixture_name, expected_checks
):
    """Each fixture, read RAW (before any pass runs) — proves the fixture
    genuinely demonstrates the defect it's named for and nothing beyond
    what that defect class implies."""
    text = (FIXTURES_DIR / fixture_name).read_text(encoding="utf-8")
    issues = structural.run(text)
    checks = {i.check for i in issues}
    assert expected_checks <= checks, (
        f"{fixture_name}: expected {expected_checks} subset of {checks}"
    )


def test_illegal_identifiers_fixture_reveals_duplicate_global_once_span_desync_is_healed():
    """The companion to the test above: AFTER `canonicalize_ghidra_
    symbols` runs (healing the span desync), the DAT_10000db0 triplet
    that was hidden inside the bogus STRING span becomes visible to
    `duplicate_global` — proving Class 3 unblocked Class 2, exactly as
    happened on real firmware."""
    from fw_audit.stage2_extraction.normalize import passes

    text = (FIXTURES_DIR / "defect_illegal_identifiers.c").read_text(encoding="utf-8")
    healed = passes.canonicalize_ghidra_symbols(text)
    issues = structural.run(healed)
    checks = {i.check for i in issues}
    assert "duplicate_global" in checks
    assert "span_sync" not in checks


@pytest.mark.parametrize(
    "fixture_name",
    [
        "defect_anonymous_enumerator.c",
        "defect_illegal_identifiers.c",
        "defect_intrinsic_macros.c",
        "defect_void_function_result.c",
        "defect_missing_prototypes.c",
        "defect_stdint_free.c",
    ],
)
def test_fixture_has_zero_error_severity_issues_after_the_full_pipeline(fixture_name):
    text = (FIXTURES_DIR / fixture_name).read_text(encoding="utf-8")
    result = normalize(text, JOERN_PIPELINE)
    issues = structural.run(result.text)
    errors = [i for i in issues if i.severity is Severity.ERROR]
    assert not errors, f"{fixture_name}: {[(e.check, e.message) for e in errors]}"


# --------------------------------------------------------------------- #
# apply_policy — the three-way truth table
# --------------------------------------------------------------------- #


def test_policy_off_never_fails_regardless_of_issues():
    results = (
        ValidationResult(target="x", layer="structural", checked_sha256="a", issues=(_issue("x"),)),
    )
    should_fail, messages = apply_policy(results, "off")
    assert should_fail is False
    assert messages == []


def test_policy_warn_never_fails_but_records_a_message():
    results = (
        ValidationResult(target="x", layer="structural", checked_sha256="a", issues=(_issue("x"),)),
    )
    should_fail, messages = apply_policy(results, "warn")
    assert should_fail is False
    assert len(messages) == 1
    assert "1 error(s)" in messages[0]


def test_policy_warn_produces_no_message_when_there_are_no_issues():
    results = (ValidationResult(target="x", layer="structural", checked_sha256="a", issues=()),)
    should_fail, messages = apply_policy(results, "warn")
    assert should_fail is False
    assert messages == []


def test_policy_fail_fails_on_any_error_severity_issue():
    results = (
        ValidationResult(target="x", layer="structural", checked_sha256="a", issues=(_issue("x"),)),
    )
    should_fail, _ = apply_policy(results, "fail")
    assert should_fail is True


def test_policy_fail_does_not_fail_on_warning_only_issues():
    results = (
        ValidationResult(
            target="x",
            layer="structural",
            checked_sha256="a",
            issues=(_issue("x", Severity.WARNING),),
        ),
    )
    should_fail, _ = apply_policy(results, "fail")
    assert should_fail is False


def test_policy_rejects_an_unknown_value():
    with pytest.raises(ValueError):
        apply_policy((), "bogus")


def test_policy_summary_caps_at_the_top_n_most_frequent_checks():
    issues = tuple(_issue(f"check_{i}") for i in range(3)) + (_issue("check_0"),)
    results = (
        ValidationResult(target="x", layer="structural", checked_sha256="a", issues=issues),
    )
    _, messages = apply_policy(results, "warn")
    # 4 total issues, capped detail shows at most 3 distinct check ids.
    assert messages[0].count(" x") <= 3 + 1  # tolerate "4 error(s)" itself containing "x"-free text


# --------------------------------------------------------------------- #
# ValidationResult / ValidationIssue shape
# --------------------------------------------------------------------- #


def test_validation_issue_to_json_dict_round_trips_every_field():
    issue = ValidationIssue(
        check="span_sync",
        defect_class=3,
        severity=Severity.ERROR,
        message="a message",
        line=42,
        end_line=45,
        detail="some text",
    )
    d = issue.to_json_dict()
    assert d == {
        "check": "span_sync",
        "defect_class": 3,
        "severity": "error",
        "message": "a message",
        "line": 42,
        "end_line": 45,
        "detail": "some text",
    }


def test_validation_result_ok_is_true_with_only_warnings():
    result = ValidationResult(
        target="x",
        layer="structural",
        checked_sha256="a",
        issues=(_issue("x", Severity.WARNING),),
    )
    assert result.ok is True
    assert result.errors == ()


def test_validation_result_ok_is_false_with_an_error():
    result = ValidationResult(
        target="x", layer="structural", checked_sha256="a", issues=(_issue("x"),)
    )
    assert result.ok is False
    assert len(result.errors) == 1


def test_validation_result_to_json_dict_is_additive_and_stable_shape():
    result = ValidationResult(
        target="joern_whole_c",
        layer="structural",
        checked_sha256="deadbeef",
        issues=(_issue("x"),),
    )
    d = result.to_json_dict()
    assert d["target"] == "joern_whole_c"
    assert d["layer"] == "structural"
    assert d["checked_sha256"] == "deadbeef"
    assert d["issue_count"] == 1
    assert d["error_count"] == 1
    assert d["tool_available"] is True
    assert len(d["issues"]) == 1


# --------------------------------------------------------------------- #
# validate_text / validate_file — the public API
# --------------------------------------------------------------------- #


def test_validate_text_runs_only_layer_a_by_default():
    results = validate_text("int x;\n")
    assert len(results) == 1
    assert results[0].layer == "structural"


def test_validate_text_checked_sha256_matches_the_actual_text():
    import hashlib

    text = "int x;\n"
    results = validate_text(text)
    assert results[0].checked_sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_validate_file_reads_and_validates(tmp_path):
    path = tmp_path / "whole.c"
    path.write_text("int x;\n", encoding="utf-8")
    results = validate_file(path)
    assert len(results) == 1
    assert results[0].ok


def test_validate_file_tolerates_undecodable_bytes(tmp_path):
    """Same `errors='replace'` discipline `extract.py` uses for every raw/
    normalized C file read — a validation run must never crash on bytes
    the rest of Stage 2 already tolerates."""
    path = tmp_path / "whole.c"
    path.write_bytes(b"int x = \xff\xfe;\n")
    results = validate_file(path)  # must not raise
    assert len(results) == 1


# --------------------------------------------------------------------- #
# Layer B (gcc) — integration-marked, skipped without a compiler on PATH
# --------------------------------------------------------------------- #

pytestmark_gcc = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not on PATH"),
]


@pytest.mark.integration
def test_syntax_run_reports_tool_unavailable_for_a_nonexistent_compiler():
    result = syntax.run("int x;\n", target="t", compiler="fw-audit-definitely-not-a-real-compiler")
    assert result.tool_available is False
    assert result.issues == ()
    assert result.tool_exit_code is None


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not on PATH")
def test_syntax_run_reports_zero_exit_code_on_clean_c():
    result = syntax.run("int add(int a, int b)\n{\n  return a + b;\n}\n", target="t")
    assert result.tool_available is True
    assert result.tool_exit_code == 0
    assert result.ok


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not on PATH")
def test_syntax_run_reports_nonzero_exit_code_and_parses_diagnostics_on_broken_c():
    result = syntax.run("int f(void)\n{\n  return \n", target="t")
    assert result.tool_available is True
    assert result.tool_exit_code != 0
    assert any(i.severity is Severity.ERROR for i in result.issues)


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not on PATH")
def test_validate_text_with_run_gcc_produces_two_results():
    results = validate_text("int x;\n", run_gcc=True)
    assert len(results) == 2
    assert {r.layer for r in results} == {"structural", "gcc"}
