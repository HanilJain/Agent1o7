"""Individual normalization passes: each one is a pure `(str) -> str`
function — no pass mutates, no pass does I/O, no pass raises on malformed
input (a pass that finds nothing to rewrite just returns its input
unchanged). `pipeline.py` composes these into the Joern- and LLM-targeted
pipelines; see its module docstring for the ordering rationale.

Every pass that could plausibly match inside a string/char literal or a
comment goes through `spans.apply_to_code`, which only ever hands it CODE
spans. The few that don't (`normalize_line_endings`, the two warning-comment
passes, `collapse_blank_lines`) either operate on line/comment structure
directly or are safe to run over the whole file by construction.

Two passes (`replace_thunk_bodies`, `dedupe_global_declarations`) take a
`normalize.context.BinaryContext` as their first argument rather than being
plain `(str) -> str` — `pipeline.py` binds the context via
`functools.partial` before these are added to a pipeline, so the resulting
closure is still `Callable[[str], str]` by the time `NamedPass` sees it.
`BinaryContext` is frozen and immutable, so the closure stays pure.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from fw_audit.stage2_extraction.normalize import structure
from fw_audit.stage2_extraction.normalize.context import BinaryContext
from fw_audit.stage2_extraction.normalize.spans import (
    SpanKind,
    apply_to_code,
    mask_non_code,
    tokenize,
)

# --------------------------------------------------------------------- #
# p01 — line endings
# --------------------------------------------------------------------- #


def normalize_line_endings(text: str) -> str:
    """CRLF/CR -> LF, trailing whitespace stripped per line, one trailing
    newline. Deterministic base every later regex pass can rely on."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    result = "\n".join(lines)
    return result if result.endswith("\n") else f"{result}\n"


# --------------------------------------------------------------------- #
# p02 — Ghidra's `WARNING: ...` comments
# --------------------------------------------------------------------- #

# Ghidra's CppExporter emits warnings as `// WARNING: ...` LINE comments in
# practice (confirmed against real output), not the `/* WARNING: */` block
# form this used to assume exclusively — that mismatch let 2,582 warning
# comments survive into delivered output on one real binary with the old
# `/\*\s*WARNING:`-only pattern. Matching both comment openers fixes it.
_WARNING_COMMENT_RE = re.compile(r"\A(?:/\*|//)\s*WARNING:", re.DOTALL)
_SEMANTIC_WARNING_MARKERS = ("Subroutine does not return", "Removing unreachable block")


def _is_ghidra_warning_comment(comment_text: str) -> bool:
    return bool(_WARNING_COMMENT_RE.match(comment_text))


def _drop_comment_spans(text: str, discard: Callable[[str], bool]) -> str:
    """Remove every COMMENT span for which `discard(span.text)` is true,
    and — when such a span is the only non-whitespace thing on its line —
    remove the blank line it would otherwise leave behind (the leading
    indentation and the line's own newline), rather than leaving an orphan
    blank line for `collapse_blank_lines` to only partially absorb later.
    A trailing comment on a code line (`x = 1; // WARNING: ...`) just has
    its comment text dropped; the code and its newline are untouched."""
    spans = tokenize(text)
    out: list[str] = []
    i = 0
    while i < len(spans):
        span = spans[i]
        if span.kind != SpanKind.COMMENT or not discard(span.text):
            out.append(span.text)
            i += 1
            continue
        # Is everything since the last '\n' in `out` pure whitespace?
        prefix = "".join(out)
        line_start = prefix.rfind("\n") + 1
        line_so_far = prefix[line_start:]
        if line_so_far.strip() == "":
            # Whole-line comment: drop the indentation already emitted for
            # this line by popping it back off `out`...
            out.clear()
            out.append(prefix[:line_start])
            # ...and swallow the single newline immediately following the
            # comment (if any), so no blank line remains.
            i += 1
            if i < len(spans) and spans[i].kind == SpanKind.CODE and spans[i].text.startswith(
                "\n"
            ):
                out.append(spans[i].text[1:])
                i += 1
            continue
        # Trailing comment: drop just the comment text.
        i += 1
    return "".join(out)


def strip_all_ghidra_warnings(text: str) -> str:
    """Joern target: delete every Ghidra `WARNING: ...` comment outright —
    Joern's CPG ignores comments, and they only inflate parse time and node
    count. The un-normalized originals stay readable in
    `raw/decompiled/whole.c` for anyone who needs them."""
    return _drop_comment_spans(text, _is_ghidra_warning_comment)


def strip_non_semantic_ghidra_warnings(text: str) -> str:
    """LLM target: delete `WARNING: ...` comments except ones carrying real
    signal (non-returning subroutines, unreachable blocks) — free context
    for the model at negligible token cost."""

    def _discard(comment_text: str) -> bool:
        if not _is_ghidra_warning_comment(comment_text):
            return False
        return not any(marker in comment_text for marker in _SEMANTIC_WARNING_MARKERS)

    return _drop_comment_spans(text, _discard)


# --------------------------------------------------------------------- #
# p04 — calling-convention markers
# --------------------------------------------------------------------- #

_CALLING_CONVENTION_RE = re.compile(
    r"\b(?:__stdcall|__fastcall|__cdecl|__thiscall|__regparm\d+)\s+"
)


def strip_calling_conventions(text: str) -> str:
    """`int __fastcall FUN_00401234(int p1)` -> `int FUN_00401234(int p1)`.
    These markers are compiler-specific noise Ghidra emits to record how a
    function actually receives arguments — dropping them changes nothing a
    CPG or an LLM needs, since neither executes the code."""
    return apply_to_code(text, lambda code: _CALLING_CONVENTION_RE.sub("", code))


# --------------------------------------------------------------------- #
# p05 — illegal `TYPE[N] name;` array declarations
# --------------------------------------------------------------------- #

# Ghidra's CppExporter occasionally emits an array declaration with the
# size subscript attached to the TYPE instead of the NAME — `undefined1[24]
# g_MUTEX;` instead of the legal `undefined1 g_MUTEX[24];`. This is not
# valid C in any context, so a match can never be legitimate code: Ghidra's
# own CORRECT array form (`undefined1 auStack_10 [16];`) has the `[` after
# the NAME, not immediately after the TYPE, so it can't be confused with
# this. Left unrepaired, gcc discards the whole declaration on the parse
# error, and then reports every later use of the symbol as undeclared —
# so this single pass also resolves what otherwise looks like a separate
# "undeclared global" problem.
_ILLEGAL_ARRAY_DECL_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<type>[A-Za-z_]\w*)[ \t]*\[(?P<n>\d+)\][ \t]+"
    r"(?P<ptr>\**)[ \t]*(?P<name>[A-Za-z_]\w*)[ \t]*;",
    re.MULTILINE,
)


def fix_illegal_array_declarations(text: str) -> str:
    """`undefined1[1372] mapInfo;` -> `undefined1 mapInfo[1372];`;
    `Elf32_Sym[1106] __DT_SYMTAB;` -> `Elf32_Sym __DT_SYMTAB[1106];`.
    Idempotent: after rewriting, the `]` is immediately followed by `;`,
    not by a second identifier, so the pattern cannot match its own output."""
    return apply_to_code(
        text,
        lambda code: _ILLEGAL_ARRAY_DECL_RE.sub(
            r"\g<indent>\g<type> \g<ptr>\g<name>[\g<n>];", code
        ),
    )


# --------------------------------------------------------------------- #
# p08 — illegal `::` in switch-case labels
# --------------------------------------------------------------------- #

# The right-hand identifier isn't only ever `caseD_<hex>` — confirmed
# against real Ghidra output (decompiling /bin/ls) that a switch's default
# case is emitted as `switchD_<addr>::default`, not a caseD_* label. Matching
# any trailing identifier, not just the caseD_ shape, covers both.
_ILLEGAL_SWITCH_LABEL_RE = re.compile(r"\b(switchD_[0-9A-Fa-f]+)::(\w+)\b")


def fix_illegal_switch_labels(text: str) -> str:
    """`switchD_00401234::caseD_5:` -> `switchD_00401234_caseD_5:`, and
    `switchD_00401234::default:` -> `switchD_00401234_default:` — `::` is a
    C++ token and a hard C parse error. `LAB_`/`DAT_`/`FUN_`/`PTR_`/`s_`
    symbols are deliberately left untouched elsewhere in the pipeline: they
    are the only stable cross-reference between the C, the .asm, and
    metadata.json."""
    return apply_to_code(text, lambda code: _ILLEGAL_SWITCH_LABEL_RE.sub(r"\1_\2", code))


# --------------------------------------------------------------------- #
# p08b — halt_baddata()
# --------------------------------------------------------------------- #

_HALT_BADDATA_CALL_RE = re.compile(r"\bhalt_baddata\s*\(\s*\)\s*;")


def rewrite_halt_baddata_for_joern(text: str) -> str:
    """Joern target: replace with a declared no-op call (see
    `normalize/prelude.py`) so the CFG keeps the statement node it had in
    the original decompiled output."""
    return apply_to_code(
        text, lambda code: _HALT_BADDATA_CALL_RE.sub("__fw_audit_unreachable();", code)
    )


def rewrite_halt_baddata_for_llm(text: str) -> str:
    """LLM target: replace with a comment — a fake call here would mislead
    the model into thinking real code exists at this point."""
    return apply_to_code(
        text,
        lambda code: _HALT_BADDATA_CALL_RE.sub(
            "/* ghidra: undefined instruction / bad data */", code
        ),
    )


# --------------------------------------------------------------------- #
# p08a — Ghidra thunk/PLT stubs whose body is just self-forwarding
# --------------------------------------------------------------------- #

# A stub body: zero or more local declarations, then one call whose result
# is optionally assigned to a local, then an optional `return`. This is
# deliberately narrow — genuine hand-decompiled logic essentially never has
# this exact shape as its ENTIRE body.
_STUB_BODY_RE = re.compile(
    r"\A\s*"
    r"(?:[A-Za-z_][\w \t*]*?[ \t*]+[A-Za-z_]\w*[ \t]*;\s*)*"  # local declarations
    r"(?:(?P<lhs>[A-Za-z_]\w*)[ \t]*=[ \t]*)?"  # optional `lhs =`
    r"(?P<callee>[A-Za-z_]\w*)[ \t]*\((?P<args>[^()]*)\)[ \t]*;\s*"  # the one call
    r"(?:return[ \t]*(?P<ret>[A-Za-z_]\w*)?[ \t]*;\s*)?"  # optional return
    r"\Z",
    re.DOTALL,
)
_BARE_IDENTIFIER_RE = re.compile(r"\A[A-Za-z_]\w*\Z")


def _is_self_forwarding_stub(body: structure.FunctionBody, body_text: str) -> bool:
    """True if `body_text` does nothing but call `body.name` with exactly
    `body.params`, in order, as bare identifiers, and (if it assigns the
    result to a local) return that same local.

    The argument-identity requirement — every call argument must be a bare
    identifier, and the argument list must equal the parameter list
    EXACTLY, in order — is what makes this safe even with no metadata at
    all: a thunk forwards its own parameters verbatim and does nothing
    else, so genuine recursion (`return fact(n - 1);`) can never match,
    because `n - 1` isn't a bare identifier and isn't `n` either."""
    match = _STUB_BODY_RE.match(mask_non_code(body_text))
    if not match or match.group("callee") != body.name:
        return False
    args = [a.strip() for a in match.group("args").split(",") if a.strip()]
    if tuple(args) != body.params:
        return False
    if not all(_BARE_IDENTIFIER_RE.match(a) for a in args):
        return False
    lhs, ret = match.group("lhs"), match.group("ret")
    return lhs is None or ret == lhs


def _extern_declarator(text: str, body: structure.FunctionBody) -> str:
    """The function's header text (return type through the closing `)` of
    its parameter list), collapsed onto one line and prefixed `extern `.

    Uses the C header text actually present in this file rather than
    `metadata.json`'s `signature` field — the two disagree in practice
    (Ghidra's Program-DB signature and its CppExporter C text are produced
    by different code paths), and the C text is what stays byte-consistent
    with this file's own call sites."""
    header = text[body.decl_start : body.header_end - 1].strip()
    header = re.sub(r"\s+", " ", header)
    # Collapsing a multi-line signature's whitespace runs to single spaces
    # (above) can leave one before the parameter list's '(' — e.g. Ghidra's
    # own `NAME\n          (params)` wrapping style — which a normal
    # single-line declaration never has; drop it so the output matches the
    # single-line form byte-for-byte.
    header = re.sub(r"\s+\(", "(", header)
    if header.startswith("extern "):
        return f"{header};"
    return f"extern {header};"


def replace_thunk_bodies(context: BinaryContext, text: str) -> str:
    """Replace a Ghidra thunk/PLT stub's self-forwarding body —
    `int calloc(size_t n,size_t s) { return calloc(n,s); }` — with an
    `extern` declaration of the same signature.

    Left as bodies, these fabricate self-recursive call edges in a CPG and
    hide the real external-call boundary; 63% of one real binary's
    functions were exactly this shape. `context.may_stub` is consulted as
    a VETO only (see `BinaryContext.may_stub`'s docstring for why) — the
    textual shape check in `_is_self_forwarding_stub` is what actually
    carries the safety burden, so this pass does something useful even
    under `EMPTY_CONTEXT`.

    Two bodies can legitimately share a name: a thunk record and the real
    definition it forwards to (both may appear in the same whole-program
    export). When that happens, or when two identical thunk stubs exist for
    the same name, every stub after the first surviving (non-stub, or
    already-declared) instance is deleted outright rather than declared —
    an `extern` before a REAL definition of the same name, or a second
    `extern`, is itself a conflicting/duplicate declaration."""
    bodies = structure.find_function_bodies(text)
    if not bodies:
        return text

    stub_indices = [
        i
        for i, body in enumerate(bodies)
        if context.may_stub(body.name)
        and _is_self_forwarding_stub(body, text[body.body_start : body.body_end])
    ]
    if not stub_indices:
        return text

    non_stub_names = {b.name for i, b in enumerate(bodies) if i not in stub_indices}
    declared_extern: set[str] = set()
    edits: list[tuple[int, int, str]] = []
    for i in stub_indices:
        body = bodies[i]
        if body.name in non_stub_names or body.name in declared_extern:
            # A non-stub definition (or an already-emitted extern) for this
            # name exists elsewhere in the file — deleted outright, no
            # comment: which pass removed which duplicate, and why, is
            # recorded in normalization_report.json, not narrated inline.
            replacement = ""
        else:
            declared_extern.add(body.name)
            replacement = f"{_extern_declarator(text, body)}"
        edits.append((body.decl_start, body.body_end + 1, replacement))
    return structure.splice(text, edits)


# --------------------------------------------------------------------- #
# p09 — undeclared register variables (in_*/unaff_*/extraout_*)
# --------------------------------------------------------------------- #

_REGISTER_VAR_RE = re.compile(r"\b(?:in|unaff|extraout)_[A-Za-z0-9_]+\b")

# Any declaration of a register-var-shaped name, anywhere in the body —
# requires a type token (or pointer marker) before the name so a plain
# ASSIGNMENT (`extraout_r2 = 5;`) is never mistaken for a declaration.
_REGISTER_VAR_DECL_RE = re.compile(
    r"^[ \t]*(?:[A-Za-z_]\w*[ \t]+)+\**[ \t]*((?:in|unaff|extraout)_[A-Za-z0-9_]+)[ \t]*;",
    re.MULTILINE,
)


def _unique_register_vars(body_text: str) -> list[str]:
    seen: dict[str, None] = {}
    for span in tokenize(body_text):
        if span.kind != SpanKind.CODE:
            continue
        for match in _REGISTER_VAR_RE.finditer(span.text):
            seen.setdefault(match.group(), None)
    return list(seen)


def _declared_register_vars(body_text: str) -> frozenset[str]:
    """Every register-var-shaped name that ALREADY has a declaration
    somewhere in `body_text` — whichever type Ghidra (or an earlier run of
    this very pass) gave it. Matched against the masked body so a name
    mentioned only inside a comment or string doesn't count."""
    masked = mask_non_code(body_text)
    return frozenset(m.group(1) for m in _REGISTER_VAR_DECL_RE.finditer(masked))


def declare_register_vars(text: str) -> str:
    """Inject a local declaration for every `in_*`/`unaff_*`/`extraout_*`
    identifier Ghidra references but never declares, at the top of the
    function body that uses it.

    Always as a per-function local, never as a file-scope global — a global
    would fabricate false inter-procedural data flow in a CPG, so Joern's
    taint analysis would report bogus flows between unrelated functions.
    Typed `uintptr_t` uniformly (register/stack-derived values, not typed
    program data) rather than sized per binary's address width — a
    deliberate simplification that keeps every pass a plain `(str) -> str`
    function with no per-binary parameters.

    Ghidra itself declares roughly a third of these references in
    practice (e.g. `int extraout_r2;`), just never all of them in the same
    body. The guard below therefore checks for ANY existing declaration of
    the name — not only one in our own synthesized `uintptr_t NAME;`
    format — otherwise this pass would inject a second, conflicting
    declaration next to Ghidra's own, which is a hard C error."""
    bodies = structure.find_function_bodies(text)
    if not bodies:
        return text

    edits: list[tuple[int, int, str]] = []
    for body in bodies:
        body_text = text[body.body_start : body.body_end]
        already_declared = _declared_register_vars(body_text)
        names = [
            name for name in _unique_register_vars(body_text) if name not in already_declared
        ]
        if not names:
            continue
        decls = "\n".join(
            f"  uintptr_t {name}; /* fw-audit: synthesized (Ghidra undefined register) */"
            for name in names
        )
        edits.append((body.body_start, body.body_start, f"\n{decls}"))

    if not edits:
        return text
    return structure.splice(text, edits)


# --------------------------------------------------------------------- #
# p10 — redundant casts (deliberately the most restricted pass)
# --------------------------------------------------------------------- #

_REDUNDANT_CAST_TYPES = (
    "uint",
    "int",
    "ulong",
    "ushort",
    "undefined1",
    "undefined2",
    "undefined4",
    "undefined8",
)
_REDUNDANT_CAST_RE = re.compile(
    r"\((" + "|".join(_REDUNDANT_CAST_TYPES) + r")\)\s*\(\1\)"
)
_VOID_ZERO_STATEMENT_RE = re.compile(r"\(void\)\s*0\s*;")


def collapse_redundant_casts(text: str) -> str:
    """Only exact adjacent duplicates — `(uint)(uint)x`, `(int)(int)x`,
    `(undefined4)(undefined4)x` — plus bare `(void)0;` statements.

    Deliberately does NOT touch `(int)(char)x` (a real sign-extension) or
    `*(int *)(param_1 + 0x10)` (pointer arithmetic that IS the semantics —
    "improving" it into `param_1->field_10` needs type recovery this
    pipeline doesn't have, and would fabricate structure that isn't there).
    Cast simplification carries the highest bug-introduction risk and the
    lowest payoff of any pass here, so it gets the smallest scope."""

    def _fix(code: str) -> str:
        code = _REDUNDANT_CAST_RE.sub(r"(\1)", code)
        return _VOID_ZERO_STATEMENT_RE.sub(";", code)

    return apply_to_code(text, _fix)


# --------------------------------------------------------------------- #
# p12 — duplicate type definitions
# --------------------------------------------------------------------- #

_TYPEDEF_NAME_RE = re.compile(r"typedef\s+[^;{}]+?\b(\w+)\s*;")
_STRUCT_DEF_RE = re.compile(r"struct\s+(\w+)\s*\{[^{}]*\}\s*;", re.DOTALL)


def dedupe_type_definitions(text: str) -> str:
    """Second and later `typedef ... NAME;` / `struct NAME {...};` sharing a
    NAME already seen are deleted outright; the first occurrence is kept.

    No explanatory comment is left behind for the removal — the pipeline's
    `normalization_report.json` already records how many duplicates each
    pass removed, so an inline comment per removal is redundant noise a
    CPG/LLM consumer gains nothing from (comments carry no semantic weight
    to either), while inflating every file with lines proportional to how
    duplicate-heavy Ghidra's typedef emission happened to be."""
    seen_typedefs: set[str] = set()
    seen_structs: set[str] = set()

    def _dedupe_typedefs(code: str) -> str:
        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name in seen_typedefs:
                return ""
            seen_typedefs.add(name)
            return match.group()

        return _TYPEDEF_NAME_RE.sub(repl, code)

    def _dedupe_structs(code: str) -> str:
        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name in seen_structs:
                return ""
            seen_structs.add(name)
            return match.group()

        return _STRUCT_DEF_RE.sub(repl, code)

    text = apply_to_code(text, _dedupe_typedefs)
    return apply_to_code(text, _dedupe_structs)


# --------------------------------------------------------------------- #
# p12b — duplicate/conflicting column-0 global variable declarations
# --------------------------------------------------------------------- #

# Column-0 (`^(?!\s)`) is what confines this to Ghidra's referenced-globals
# block and top-level definitions — every statement inside a function body
# is indented. `typedef`/`struct`/`union`/`enum`/`extern`/`static`/`const`/
# `volatile` are excluded so this never overlaps `dedupe_type_definitions`
# (p12) or a legitimate qualified declaration; excluding `(` from the
# character class keeps function declarations/definitions out of scope
# entirely, since only p08's thunk handling should ever touch those.
_GLOBAL_DECL_RE = re.compile(
    r"^(?!\s)(?!(?:typedef|struct|union|enum|extern|static|const|volatile)\b)"
    # `[ \t]+` (mandatory, not `*`) between the last type word and the
    # name/pointer-stars is what stops the engine from backtracking a type
    # word like `FUN_` into swallowing the leading letters of the NAME
    # that follows it with no separating space (`undefined FUN_x;` must
    # split as type=`undefined`, name=`FUN_x`, never type=`undefined FUN_`,
    # name=`x`).
    r"(?P<decl>[A-Za-z_]\w*(?:[ \t]+[A-Za-z_]\w*)*[ \t]+\**[ \t]*"
    r"(?P<name>[A-Za-z_]\w*)[ \t]*(?:\[[0-9]*\])?[ \t]*;)",
    re.MULTILINE,
)


def dedupe_global_declarations(context: BinaryContext, text: str) -> str:
    """Delete a column-0 global variable declaration outright when either:

    * its NAME has already been declared earlier in this same file (e.g.
      `undefined4 DAT_00292dcc;` followed later by `int DAT_00292dcc;` —
      conflicting types for the same symbol, a hard compile/parse error);
    * `context` confirms the NAME is actually a FUNCTION symbol — Ghidra's
      referenced-globals block occasionally emits a function's entry point
      as if it were a byte of data (`undefined FUN_000140c4;`), which then
      conflicts with that function's own real definition later in the file.

    The first declaration of a given name always wins and is kept as-is.
    No explanatory comment is left in its place — see
    `dedupe_type_definitions`'s docstring for why: the removal is recorded
    in `normalization_report.json`, not narrated inline in code a CPG
    builder or LLM has no use for reading as prose."""
    seen: set[str] = set()

    def repl(match: re.Match[str]) -> str:
        name = match.group("name")
        if context.is_function_symbol(name):
            return ""
        if name in seen:
            return ""
        seen.add(name)
        return match.group()

    return apply_to_code(text, lambda code: _GLOBAL_DECL_RE.sub(repl, code))


# --------------------------------------------------------------------- #
# p13 — conflicting builtin declarations (known Ghidra CppExporter bugs)
# --------------------------------------------------------------------- #

_CONFLICTING_BUILTIN_DECLS = ("__snprintf_chk", "__memcpy_chk", "sigaction")
_CONFLICTING_DECL_RE = re.compile(
    # `(?![ \t])` is the actual column-0 enforcement: `[^\n;{}]*` alone
    # would happily absorb leading indentation as part of its match, which
    # would let this fire on an indented, in-body call site too.
    r"^(?![ \t])(?:typedef\b)?[^\n;{}]*\b(?:"
    + "|".join(re.escape(n) for n in _CONFLICTING_BUILTIN_DECLS)
    + r")\b[^\n;{}]*;\s*\n?",
    re.MULTILINE,
)


def drop_conflicting_builtin_decls(text: str) -> str:
    """Removes Ghidra's known-buggy top-level (column-0) declarations for
    `__snprintf_chk`/`__memcpy_chk`/`sigaction` — CppExporter emits
    conflicting types for these (e.g. `sigaction` declared as both a
    typedef'd struct and a function parameter), which is a hard compile/
    parse error. Column-0-anchored so an indented, in-body call to one of
    these functions (a real statement, not a declaration) is never touched.

    Deleted outright, no explanatory comment — see
    `dedupe_type_definitions`'s docstring for why."""
    return apply_to_code(text, lambda code: _CONFLICTING_DECL_RE.sub("", code))


# --------------------------------------------------------------------- #
# p14 — trailing whitespace / blank-line collapsing (idempotence anchor)
# --------------------------------------------------------------------- #


def collapse_blank_lines(text: str) -> str:
    """Also re-trims trailing per-line whitespace, not just blank-line
    runs: a comment-stripping pass earlier in the pipeline (p02) can leave
    a line with only the whitespace that used to precede the comment —
    p01 already ran by then, so nothing else in this pass order catches
    it. Without this, the pipeline isn't a fixed point after one pass."""
    lines = [line.rstrip() for line in text.split("\n")]
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines))
    return text if text.endswith("\n") else f"{text}\n"
