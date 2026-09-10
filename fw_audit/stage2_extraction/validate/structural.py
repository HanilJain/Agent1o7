"""Layer A: dependency-free structural checks over a normalized C file.

Deliberately lives OUTSIDE `stage2_extraction.normalize` (never imported by
it, never imports it back into a cycle) even though it reuses `normalize.
spans`/`normalize.structure` read-only — `normalize/` has its own import-
purity test (`tests/test_normalizer.py::test_normalize_import_purity_...`)
that a module in this package would satisfy trivially on its own but must
never be asked to satisfy FOR this package too; keeping the two separate is
what keeps that guarantee legible. Every function here is pure `(str) ->
tuple[ValidationIssue, ...]`, no I/O, no subprocess — the counterpart to
this, `syntax.py`, is the one module in this package allowed to import
`subprocess`.

Each `_check_*` function is one independent pass over the text; `run`
concatenates their output. A check that finds nothing returns `()` — same
"no match, no exception" discipline `normalize.passes` uses throughout.
"""

from __future__ import annotations

import re

from fw_audit.stage2_extraction.normalize import structure
from fw_audit.stage2_extraction.normalize.spans import SpanKind, mask_non_code, tokenize
from fw_audit.stage2_extraction.validate.result import Severity, ValidationIssue


def _line_of(text: str, offset: int) -> int:
    """1-indexed line number containing `offset` into `text`."""
    return text.count("\n", 0, offset) + 1


def _check_span_sync(text: str) -> tuple[ValidationIssue, ...]:
    """Class 3 root cause: a STRING/CHAR span that crosses a newline means
    an unbalanced quote somewhere desynced `spans.tokenize`, silently
    disabling every `apply_to_code`-guarded pass across the swallowed
    region. This is THE highest-value check in this module — it is the
    exact invariant whose violation caused every other measured defect on
    real firmware (91 such spans, 4,680 swallowed lines, before Class 3's
    `canonicalize_ghidra_symbols` pass existed).

    The bound is 0 crossed newlines, not "fewer than N": C has no raw
    newline inside a string or char literal, ever, so any nonzero count is
    a hard defect, never a false positive to tune around."""
    issues = []
    offset = 0
    for span in tokenize(text):
        if span.kind in (SpanKind.STRING, SpanKind.CHAR) and "\n" in span.text:
            issues.append(
                ValidationIssue(
                    check="span_sync",
                    defect_class=3,
                    severity=Severity.ERROR,
                    message=(
                        f"a {span.kind.value} literal spans "
                        f"{span.text.count(chr(10))} newline(s) — an unbalanced "
                        "quote desynced the tokenizer here"
                    ),
                    line=_line_of(text, offset),
                    end_line=_line_of(text, offset + len(span.text)),
                    detail=span.text[:120],
                )
            )
        offset += len(span.text)
    return tuple(issues)


_ILLEGAL_SYMBOL_RE = re.compile(
    r"\b(?:PTR_|DAT_|OFF_|UNK_|FUN_|LAB_|SUB_|s_|u_|e_)"
    r"[^\s,;()\[\]{}]*_[0-9A-Fa-f]{4,16}\b"
)
_ILLEGAL_CHAR_RE = re.compile(r"[^A-Za-z0-9_]")


def _check_illegal_identifier(text: str) -> tuple[ValidationIssue, ...]:
    """Class 3: a Ghidra symbol whose sanitized form still differs from
    itself — `canonicalize_ghidra_symbols`'s whitelist-gated rewrite
    deliberately leaves a candidate untouched unless it matches a known
    declaration or contains a quote (see that pass's docstring), so a
    residual can legitimately remain; this check surfaces it rather than
    letting it reach `joern-parse` silently."""
    issues = []
    for match in _ILLEGAL_SYMBOL_RE.finditer(text):
        raw = match.group()
        if _ILLEGAL_CHAR_RE.sub("_", raw) == raw:
            continue
        issues.append(
            ValidationIssue(
                check="illegal_identifier",
                defect_class=3,
                severity=Severity.ERROR,
                message="Ghidra symbol contains characters illegal in a C identifier",
                line=_line_of(text, match.start()),
                detail=raw[:120],
            )
        )
    return tuple(issues)


def _check_double_colon(text: str) -> tuple[ValidationIssue, ...]:
    """Class 3: `::` is a C++ token and a hard parse error for Joern's
    Eclipse-CDT-based C frontend. Checked against CODE spans only — `::`
    inside a string literal (e.g. `puts("mgmt::beacon")`, confirmed
    present on real firmware) is legal and must not be flagged."""
    issues = []
    offset = 0
    for span in tokenize(text):
        if span.kind == SpanKind.CODE:
            local = 0
            while True:
                idx = span.text.find("::", local)
                if idx == -1:
                    break
                pos = offset + idx
                issues.append(
                    ValidationIssue(
                        check="double_colon",
                        defect_class=3,
                        severity=Severity.ERROR,
                        message="'::' is a C++ token — a hard parse error in C",
                        line=_line_of(text, pos),
                        detail=text[max(0, pos - 20) : pos + 20],
                    )
                )
                local = idx + 2
        offset += len(span.text)
    return tuple(issues)


_INTRINSIC_USE_RE = re.compile(r"\b((?:CONCAT|SUB|ZEXT|SEXT)\d{2,4})\s*\(")
_INTRINSIC_DEFINE_RE = re.compile(r"#define\s+((?:CONCAT|SUB|ZEXT|SEXT)\d{2,4})\b")
_PHANTOM_TYPE_RE = re.compile(r"\buint(24|40|48|56)_t\b")


def _check_undefined_intrinsic(text: str) -> tuple[ValidationIssue, ...]:
    """Class 7: every `CONCAT`/`SUB`/`ZEXT`/`SEXT` token actually CALLED
    must have a corresponding `#define` reachable from this file (the
    inlined prelude) — an undefined one survives as a phantom method-call
    node in the CPG (`cpg.method.name.l`) rather than a compile error,
    which is exactly the silent-corruption failure mode the whole
    validation gate exists to stop trusting to luck.

    Also flags a `uintNN_t` for NN outside {8,16,32,64} anywhere in the
    file — the direct regression check for the `uint24_t`/`uint40_t`/
    `uint48_t`/`uint56_t` poison an earlier `prelude._concat_macros` shipped
    (see that function's current docstring): those types never exist, so a
    macro expansion referencing one is a hard compile error waiting to
    happen the moment it's used."""
    issues = []
    masked = mask_non_code(text)
    # `_INTRINSIC_DEFINE_RE` deliberately still scans the ORIGINAL text,
    # not `masked`: a `#define` directive is never inside a comment/string
    # in valid input, but `mask_non_code` only blanks comment/string/char
    # SPANS — the `#define CONCATxy(...)` line's own body text is CODE and
    # survives masking unchanged either way, so scanning `text` here is
    # simplest and exactly equivalent.
    used = {m.group(1) for m in _INTRINSIC_USE_RE.finditer(masked)}
    defined = {m.group(1) for m in _INTRINSIC_DEFINE_RE.finditer(text)}
    for name in sorted(used - defined):
        specific = re.search(rf"\b{re.escape(name)}\s*\(", masked)
        issues.append(
            ValidationIssue(
                check="undefined_intrinsic",
                defect_class=7,
                severity=Severity.ERROR,
                message=f"{name} is called but never #define'd",
                line=_line_of(text, specific.start()) if specific else None,
                detail=name,
            )
        )
    for match in _PHANTOM_TYPE_RE.finditer(masked):
        issues.append(
            ValidationIssue(
                check="undefined_intrinsic",
                defect_class=7,
                severity=Severity.ERROR,
                message=f"'{match.group()}' does not exist as a real C type",
                line=_line_of(text, match.start()),
                detail=match.group(),
            )
        )
    return tuple(issues)


_ANON_ENUMERATOR_RE = re.compile(
    r"^[ \t]*=[ \t]*-?(?:0[xX][0-9A-Fa-f]+|[0-9]+)[ \t]*,?[ \t]*$", re.MULTILINE
)


def _check_anonymous_enumerator(text: str) -> tuple[ValidationIssue, ...]:
    """Class 1: a value-only enumerator (`    =1879048203,`) inside an
    enum body — `name_anonymous_enumerators` should have already repaired
    every one of these; this check exists so a future prelude/pass change
    that regresses it is caught here rather than by `gcc` erroring out
    somewhere downstream in production."""
    issues = []
    for body in structure.find_enum_bodies(text):
        body_text = text[body.body_start : body.body_end]
        for match in _ANON_ENUMERATOR_RE.finditer(body_text):
            offset = body.body_start + match.start()
            issues.append(
                ValidationIssue(
                    check="anonymous_enumerator",
                    defect_class=1,
                    severity=Severity.ERROR,
                    message="enumerator has a value but no name",
                    line=_line_of(text, offset),
                    detail=match.group().strip(),
                )
            )
    return tuple(issues)


_GLOBAL_DECL_RE = re.compile(
    r"^(?!\s)(?!(?:typedef|struct|union|enum|extern|static|const|volatile)\b)"
    r"(?P<type>[A-Za-z_]\w*(?:[ \t]+[A-Za-z_]\w*)*[ \t]+\**[ \t]*)"
    r"(?P<name>[A-Za-z_]\w*)[ \t]*(?:\[[0-9]*\])?[ \t]*;",
    re.MULTILINE,
)


def _check_duplicate_global(text: str) -> tuple[ValidationIssue, ...]:
    """Class 2: the same symbol declared at column 0 more than once with a
    DIFFERENT type string — `dedupe_global_declarations` should already
    have collapsed this to one declaration; a survivor here means either
    the type-unification refinement flagged it for manual review (working
    as intended — this check is how that gets surfaced) or a genuine
    regression."""
    issues = []
    first_type: dict[str, tuple[str, int]] = {}
    for match in _GLOBAL_DECL_RE.finditer(mask_non_code(text)):
        name = match.group("name")
        decl_type = match.group("type").strip()
        if name not in first_type:
            first_type[name] = (decl_type, match.start())
            continue
        prior_type, _prior_pos = first_type[name]
        if decl_type != prior_type:
            issues.append(
                ValidationIssue(
                    check="duplicate_global",
                    defect_class=2,
                    severity=Severity.ERROR,
                    message=(
                        f"'{name}' redeclared with a different type "
                        f"('{prior_type}' then '{decl_type}')"
                    ),
                    line=_line_of(text, match.start()),
                    detail=name,
                )
            )
    return tuple(issues)


_VOID_HEADER_RE = re.compile(r"^void\s+(\w+)\s*\(", re.MULTILINE)
_VALUE_USE_RE = re.compile(
    r"(?:(?<![=!<>+\-*/%&|^])=[ \t]*|\breturn[ \t]+)(?P<callee>[A-Za-z_]\w*)[ \t\n]*\("
)


def _check_void_value_use(text: str) -> tuple[ValidationIssue, ...]:
    """Class 5: a function still declared `void` whose result is used as a
    value somewhere in the file — `repair_void_function_results` should
    already have promoted every such case to `int`; a survivor is a
    WARNING (not ERROR) here because it's a real gcc diagnostic
    ("invalid use of void expression") but not a Joern-CDT parse
    failure — CDT doesn't type-check, so this defect class is a compile-
    correctness concern, not a CPG-availability one, unlike the other
    six."""
    void_defined = {m.group(1) for m in _VOID_HEADER_RE.finditer(mask_non_code(text))}
    if not void_defined:
        return ()
    masked = mask_non_code(text)
    issues = []
    seen: set[str] = set()
    for match in _VALUE_USE_RE.finditer(masked):
        name = match.group("callee")
        if name in void_defined and name not in seen:
            seen.add(name)
            issues.append(
                ValidationIssue(
                    check="void_value_use",
                    defect_class=5,
                    severity=Severity.WARNING,
                    message=f"'{name}' is declared void but its result is used",
                    line=_line_of(text, match.start()),
                    detail=name,
                )
            )
    return tuple(issues)


_CALL_SITE_RE = re.compile(r"\b(?P<callee>[A-Za-z_]\w*)[ \t]*\(")


_STANDALONE_DECL_RE = re.compile(
    r"^(?:extern[ \t]+)?[A-Za-z_][\w \t*]*?\b([A-Za-z_]\w*)[ \t]*\([^;{}]*\)[ \t]*;",
    re.MULTILINE,
)


def _check_missing_prototype(text: str) -> tuple[ValidationIssue, ...]:
    """Class 6: a function called before any declaration of it (its own
    definition's header included) appears in the file — `hoist_function_
    prototypes` should already forward-declare every such case it can
    safely handle; a survivor is a WARNING (implicit-int, not a Joern-CDT
    parse failure — same rationale as `_check_void_value_use`) and is what
    lets the pass's deliberately narrow, evidence-driven scope (see that
    function's docstring) actually grow on evidence rather than
    guesswork.

    A function's own DEFINITION counts as its earliest declaration —
    seeded directly from `structure.find_function_bodies`'s `decl_start`,
    NOT from a hand-rolled regex requiring the header's `(...)` and `{` on
    one line: Ghidra wraps a long signature across lines exactly like it
    wraps a long call site (`_extern_declarator`'s docstring documents the
    header case; `passes._VOID_VALUE_USE_RE`'s docstring documents the
    call-site case) — a regex requiring same-line `){` silently fails to
    recognize a multi-line-signature definition as a declaration at all,
    which is precisely the class of bug this check exists to catch, not
    reproduce. `_STANDALONE_DECL_RE` (`;`-terminated, no `{`) supplements
    this ONLY for prototype-only lines that aren't full definitions —
    those genuinely have no brace to span lines around."""
    bodies = structure.find_function_bodies(text)
    if not bodies:
        return ()
    masked = mask_non_code(text)
    body_by_name = {b.name: b for b in bodies}
    declared_before: dict[str, int] = {b.name: b.decl_start for b in bodies}
    for match in _STANDALONE_DECL_RE.finditer(masked):
        name = match.group(1)
        if name not in declared_before or match.start() < declared_before[name]:
            declared_before[name] = match.start()

    issues = []
    seen: set[str] = set()
    for match in _CALL_SITE_RE.finditer(masked):
        name = match.group("callee")
        if name not in body_by_name or name in seen:
            continue
        first_decl = declared_before.get(name)
        if first_decl is not None and first_decl <= match.start():
            continue
        seen.add(name)
        issues.append(
            ValidationIssue(
                check="missing_prototype",
                defect_class=6,
                severity=Severity.WARNING,
                message=f"'{name}' is called before any declaration of it",
                line=_line_of(text, match.start()),
                detail=name,
            )
        )
    return tuple(issues)


_INCLUDE_RE = re.compile(r"^[ \t]*#[ \t]*include\b", re.MULTILINE)


def _check_unresolved_include(text: str) -> tuple[ValidationIssue, ...]:
    """Class 4: ANY `#include` directive at all — `joern-parse` (Eclipse
    CDT) resolves against no system include path, so an include is never
    followed; it's not merely unnecessary, it's silently wrong (see
    `prelude._fixed_width_types`'s docstring for the full argument for why
    the prelude must be self-contained instead)."""
    return tuple(
        ValidationIssue(
            check="unresolved_include",
            defect_class=4,
            severity=Severity.ERROR,
            message="#include is never resolved by Joern's CDT frontend",
            line=_line_of(text, m.start()),
            detail=text[m.start() : text.find(chr(10), m.start())][:120],
        )
        for m in _INCLUDE_RE.finditer(text)
    )


def _check_brace_balance(text: str) -> tuple[ValidationIssue, ...]:
    """Net `{`/`}` depth over CODE (comment/string/char-blind) text must
    end at exactly 0 and never go negative — a cheap, general parse-health
    signal independent of any single defect class, catching whatever the
    seven classes' own checks don't."""
    masked = mask_non_code(text)
    depth = 0
    for i, ch in enumerate(masked):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return (
                    ValidationIssue(
                        check="brace_balance",
                        defect_class=0,
                        severity=Severity.ERROR,
                        message="unmatched closing brace",
                        line=_line_of(text, i),
                    ),
                )
    if depth != 0:
        return (
            ValidationIssue(
                check="brace_balance",
                defect_class=0,
                severity=Severity.ERROR,
                message=f"{depth} unclosed brace(s) at end of file",
            ),
        )
    return ()


def _check_halt_baddata(text: str) -> tuple[ValidationIssue, ...]:
    """A residual, unrewritten `halt_baddata()` call — Ghidra's own
    intrinsic, never declared, so it's an undeclared-function parse error
    if `rewrite_halt_baddata_for_joern` ever fails to catch one. Matched
    against CODE spans only, and deliberately not sharing the literal
    substring `halt_baddata()` with `prelude._halt_baddata_stub`'s own
    comment (see that function's docstring for why)."""
    issues = []
    offset = 0
    pattern = re.compile(r"\bhalt_baddata\s*\(\s*\)")
    for span in tokenize(text):
        if span.kind == SpanKind.CODE:
            for match in pattern.finditer(span.text):
                issues.append(
                    ValidationIssue(
                        check="halt_baddata",
                        defect_class=0,
                        severity=Severity.ERROR,
                        message="unrewritten halt_baddata() call survives",
                        line=_line_of(text, offset + match.start()),
                    )
                )
        offset += len(span.text)
    return tuple(issues)


_CHECKS = (
    _check_span_sync,
    _check_illegal_identifier,
    _check_double_colon,
    _check_undefined_intrinsic,
    _check_anonymous_enumerator,
    _check_duplicate_global,
    _check_void_value_use,
    _check_missing_prototype,
    _check_unresolved_include,
    _check_brace_balance,
    _check_halt_baddata,
)


def run(text: str) -> tuple[ValidationIssue, ...]:
    """Run every Layer A check over `text` and concatenate their issues,
    most-structural-first (`span_sync` — the root cause check — always
    leads). Pure, no dependency beyond the standard library and
    `normalize.spans`/`normalize.structure`; safe to call unconditionally,
    unlike `syntax.run` (Layer B), which needs a compiler on PATH."""
    issues: list[ValidationIssue] = []
    for check in _CHECKS:
        issues.extend(check(text))
    return tuple(issues)


__all__ = ["run"]
