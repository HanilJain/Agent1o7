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
"""

from __future__ import annotations

import re

from fw_audit.stage2_extraction.normalize.spans import SpanKind, apply_to_code, tokenize

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
# p02 — Ghidra's `/* WARNING: ... */` block comments
# --------------------------------------------------------------------- #

_WARNING_COMMENT_PREFIX_RE = re.compile(r"/\*\s*WARNING:", re.DOTALL)
_SEMANTIC_WARNING_MARKERS = ("Subroutine does not return", "Removing unreachable block")


def _is_ghidra_warning_comment(comment_text: str) -> bool:
    return bool(_WARNING_COMMENT_PREFIX_RE.match(comment_text))


def strip_all_ghidra_warnings(text: str) -> str:
    """Joern target: delete every `/* WARNING: ... */` comment outright —
    Joern's CPG ignores comments, and they only inflate parse time and node
    count. The un-normalized originals stay readable in
    `raw/decompiled/whole.c` for anyone who needs them."""
    return "".join(
        "" if span.kind == SpanKind.COMMENT and _is_ghidra_warning_comment(span.text) else span.text
        for span in tokenize(text)
    )


def strip_non_semantic_ghidra_warnings(text: str) -> str:
    """LLM target: delete `/* WARNING: ... */` comments except ones carrying
    real signal (non-returning subroutines, unreachable blocks) — free
    context for the model at negligible token cost."""

    def _keep(span_text: str) -> bool:
        if not _is_ghidra_warning_comment(span_text):
            return True
        return any(marker in span_text for marker in _SEMANTIC_WARNING_MARKERS)

    return "".join(span.text if _keep(span.text) else "" for span in tokenize(text))


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
# p09 — undeclared register variables (in_*/unaff_*/extraout_*)
# --------------------------------------------------------------------- #

_FUNCTION_HEADER_RE = re.compile(r"^[A-Za-z_].*\)\s*\{", re.MULTILINE)
_REGISTER_VAR_RE = re.compile(r"\b(?:in|unaff|extraout)_[A-Za-z0-9_]+\b")


def _find_function_bodies(text: str) -> list[tuple[int, int]]:
    """`(body_start, body_end)` char offsets for each function body found by
    the column-0 heuristic below — reliable specifically because this is
    generated code with a fixed emitter style, not hand-written C."""
    bodies: list[tuple[int, int]] = []
    for match in _FUNCTION_HEADER_RE.finditer(text):
        open_brace_pos = match.end() - 1
        if text[open_brace_pos] != "{":
            continue
        end = _find_matching_brace(text, open_brace_pos)
        if end is not None:
            bodies.append((open_brace_pos + 1, end))
    return bodies


def _find_matching_brace(text: str, open_pos: int) -> int | None:
    """Depth-count braces from `open_pos` (must be `{`), skipping any that
    fall inside a STRING/CHAR/COMMENT span."""
    depth = 0
    offset = open_pos
    for span in tokenize(text[open_pos:]):
        if span.kind == SpanKind.CODE:
            for i, ch in enumerate(span.text):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return offset + i
        offset += len(span.text)
    return None


def _unique_register_vars(body_text: str) -> list[str]:
    seen: dict[str, None] = {}
    for span in tokenize(body_text):
        if span.kind != SpanKind.CODE:
            continue
        for match in _REGISTER_VAR_RE.finditer(span.text):
            seen.setdefault(match.group(), None)
    return list(seen)


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
    function with no per-binary parameters."""
    bodies = _find_function_bodies(text)
    if not bodies:
        return text

    insertions: list[tuple[int, str]] = []
    for body_start, body_end in bodies:
        body_text = text[body_start:body_end]
        # Idempotence: on a second pass, a name this function already
        # declared (in our own fixed synthesized format, from a prior run)
        # must not be declared again.
        names = [
            name
            for name in _unique_register_vars(body_text)
            if f"uintptr_t {name};" not in body_text
        ]
        if not names:
            continue
        decls = "".join(
            f"  uintptr_t {name}; /* fw-audit: synthesized (Ghidra undefined register) */\n"
            for name in names
        )
        insertions.append((body_start, f"\n{decls}"))

    if not insertions:
        return text

    pieces: list[str] = []
    cursor = 0
    for pos, decl_text in insertions:
        pieces.append(text[cursor:pos])
        pieces.append(decl_text)
        cursor = pos
    pieces.append(text[cursor:])
    return "".join(pieces)


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
    NAME already seen are commented out; the first occurrence is kept."""
    seen_typedefs: set[str] = set()
    seen_structs: set[str] = set()

    def _dedupe_typedefs(code: str) -> str:
        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name in seen_typedefs:
                return f"/* fw-audit: duplicate definition removed: {match.group().strip()} */"
            seen_typedefs.add(name)
            return match.group()

        return _TYPEDEF_NAME_RE.sub(repl, code)

    def _dedupe_structs(code: str) -> str:
        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name in seen_structs:
                return f"/* fw-audit: duplicate definition removed: struct {name} {{...}}; */"
            seen_structs.add(name)
            return match.group()

        return _STRUCT_DEF_RE.sub(repl, code)

    text = apply_to_code(text, _dedupe_typedefs)
    return apply_to_code(text, _dedupe_structs)


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
    these functions (a real statement, not a declaration) is never touched."""

    def repl(match: re.Match[str]) -> str:
        return (
            "/* fw-audit: removed Ghidra's conflicting builtin declaration "
            f"(known decompiler-output bug): {match.group().strip()} */\n"
        )

    return apply_to_code(text, lambda code: _CONFLICTING_DECL_RE.sub(repl, code))


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
