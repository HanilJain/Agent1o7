"""Individual normalization passes: each one is a pure `(str) -> str`
function — no pass mutates, no pass does I/O, no pass raises on malformed
input (a pass that finds nothing to rewrite just returns its input
unchanged). `pipeline.py` composes these into the Joern-targeted pipeline;
see its module docstring for the ordering rationale.

Every pass that could plausibly match inside a string/char literal or a
comment goes through `spans.apply_to_code`, which only ever hands it CODE
spans. The few that don't (`normalize_line_endings`, the warning-comment
pass, `collapse_blank_lines`) either operate on line/comment structure
directly or are safe to run over the whole file by construction.

`canonicalize_ghidra_symbols` is a FOURTH, deliberate exception — and the
only one where the reason is "the tokenizer itself cannot be trusted yet",
not "safe by construction". Ghidra names string-derived symbols after the
string's own content (`PTR_s_<?xml_version="1.0"...`), and an odd quote
count inside that identifier desyncs `spans.tokenize`'s STRING regex,
opening a bogus span that swallows real code for hundreds of lines
(measured on real firmware: 91 multi-line spans, 4,680 swallowed lines).
Every pass downstream of that desync — including every `apply_to_code`
call — silently no-ops across the swallowed region. `canonicalize_ghidra_
symbols` MUST run first and MUST NOT call `apply_to_code`/`tokenize`; it is
line-scoped instead, which is what a symbol-shaped token needs and what
keeps it safe to run before spans are trustworthy. Do not "fix" this pass
to route through `apply_to_code` for consistency — that would silently
reintroduce the exact defect it exists to repair
(`test_canonicalize_does_not_use_apply_to_code` pins this).

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
# p01b — illegal characters in Ghidra-generated symbol names
# --------------------------------------------------------------------- #

# Ghidra's own symbol-name prefixes. `switchD_`/`caseD_`/`switchdataD_` are
# DELIBERATELY excluded — those are handled by `fix_illegal_switch_labels`
# (p08 below), which expects to see `::` intact; sanitizing it here first
# would produce a name that pass can no longer recognize as a switch label
# and that no longer matches its `goto` target.
_GHIDRA_SYMBOL_PREFIX = r"(?:PTR_|DAT_|OFF_|UNK_|FUN_|LAB_|SUB_|s_|u_|e_)"

# GREEDY, not lazy: a lazy `*?` stops at the FIRST hex-suffix-shaped run
# and can split one symbol into "sanitized head" + "untouched tail" (e.g.
# `PTR_s_</e:propertyset>_004692dc+0x12c_10000124;` would stop after
# `_004692dc`, leaving `+0x12c_10000124;` unsanitized). Greedy backtracks
# to the LAST such run, which is what actually terminates a Ghidra symbol
# — confirmed against real output: greedy converges every declaration/use
# spelling pair, lazy does not.
_SYMBOL_CANDIDATE_RE = re.compile(
    r"\b" + _GHIDRA_SYMBOL_PREFIX + r"[^\s,;()\[\]{}]*_[0-9A-Fa-f]{4,16}\b"
)

# A column-0, whole-line declaration of a Ghidra symbol — the same shape
# `_GLOBAL_DECL_RE` (p12b, below) matches, but line-scoped and independent
# of it: this pass must run before spans (and therefore before anything
# using `apply_to_code`) can be trusted at all.
_SYMBOL_DECL_LINE_RE = re.compile(
    r"^(?:[A-Za-z_]\w*(?:[ \t]+[A-Za-z_]\w*)*[ \t]*\**[ \t]*)"
    r"(?P<sym>" + _GHIDRA_SYMBOL_PREFIX + r"[^\s,;()\[\]{}]*_[0-9A-Fa-f]{4,16})"
    r"[ \t]*(?:\[[0-9]*\])?[ \t]*;[ \t]*$"
)

_ILLEGAL_IDENT_CHAR_RE = re.compile(r"[^A-Za-z0-9_]")


def canonicalize_ghidra_symbols(text: str) -> str:
    """Rewrite every character outside `[A-Za-z0-9_]` inside a Ghidra
    symbol name (`PTR_s_...`, `DAT_...`, `FUN_...`, ...) to `_`.

    Ghidra names string-pointer symbols after the STRING CONTENT they
    reference — `undefined *PTR_s_<?xml_version="1.0"_encoding="ut_
    1000011c;` — so any embedded XML/JSON/format-string fragment produces
    an unparseable "identifier" full of `< > " % : / + .` etc. Two
    independent failures follow: it's a hard parse error on its own, AND
    the stray unbalanced quote desyncs `spans.tokenize`'s STRING regex for
    every pass after this one (see this module's docstring). This pass is
    what prevents both.

    A char-for-char (not truncating) rewrite is deliberate: Ghidra itself
    partially sanitizes the SAME symbol differently at its declaration site
    (the referenced-globals block) than at use sites, e.g. declaring
    `PTR_s_<?xml_version="1.0"...` but using `PTR_s_<_xml_version__1_0__
    ...` — both 1-char-for-1-char maps of the same raw name. Rewriting the
    same way here makes both spellings converge on one identifier
    (verified against real firmware output); truncating to a shorter form
    would not preserve that convergence.

    Deliberately NOT `apply_to_code` — see this module's docstring for why
    that would be circular here. Two-scan, line-by-line instead:

    1. Collect the sanitized form of every symbol appearing in a column-0
       declaration (`_SYMBOL_DECL_LINE_RE`) into `canonical`.
    2. Rewrite each candidate (`_SYMBOL_CANDIDATE_RE`) only if either (a)
       its sanitized form is a name from step 1 — i.e. it's a genuine
       reference to a declared symbol, not two adjacent unrelated tokens a
       greedy match bridged (e.g. a ternary `c?DAT_1000:DAT_2000` bridges
       to `DAT_1000:DAT_2000`, whose sanitized form `DAT_1000_DAT_2000`
       matches no declaration and is left untouched) — or (b) the raw text
       contains a quote character, which independently guarantees a span
       desync regardless of whether it matches a known declaration.

    Idempotent: a symbol already sanitized has `clean == raw` for every
    candidate match, so a second pass makes zero edits (verified on real
    firmware output — same bytes after a second run)."""
    lines = text.split("\n")

    canonical: set[str] = set()
    for line in lines:
        match = _SYMBOL_DECL_LINE_RE.match(line)
        if match:
            canonical.add(_ILLEGAL_IDENT_CHAR_RE.sub("_", match.group("sym")))

    def _rewrite_line(line: str) -> str:
        def repl(match: re.Match[str]) -> str:
            raw = match.group()
            clean = _ILLEGAL_IDENT_CHAR_RE.sub("_", raw)
            if clean == raw:
                return raw
            if clean in canonical or '"' in raw or "'" in raw:
                return clean
            return raw

        return _SYMBOL_CANDIDATE_RE.sub(repl, line)

    return "\n".join(_rewrite_line(line) for line in lines)


# --------------------------------------------------------------------- #
# p02 — Ghidra's `WARNING: ...` comments
# --------------------------------------------------------------------- #

# Ghidra's CppExporter emits warnings as `// WARNING: ...` LINE comments in
# practice (confirmed against real output), not the `/* WARNING: */` block
# form this used to assume exclusively — that mismatch let 2,582 warning
# comments survive into delivered output on one real binary with the old
# `/\*\s*WARNING:`-only pattern. Matching both comment openers fixes it.
_WARNING_COMMENT_RE = re.compile(r"\A(?:/\*|//)\s*WARNING:", re.DOTALL)


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
# p08c — anonymous (value-only) enumerators
# --------------------------------------------------------------------- #

# A value-only enumerator line: Ghidra dropped the enumerator's NAME but
# kept its VALUE, e.g. `    =1879048203,` — a bare `= value,` with nothing
# before the `=`. Requiring the trailing `,` (Ghidra always emits it, even
# on the last member) is what stops this from matching a wrapped
# initializer continuation line elsewhere in the file.
_ANON_ENUMERATOR_RE = re.compile(
    r"^(?P<indent>[ \t]*)=[ \t]*(?P<val>-?(?:0[xX][0-9A-Fa-f]+|[0-9]+))(?P<tail>[ \t]*,)[ \t]*$",
    re.MULTILINE,
)


def _enum_value_slug(value: str) -> str:
    slug = value.replace("-", "n").replace("0x", "0X").replace("0X", "0x")
    return slug.upper() if slug.lower().startswith("0x") else slug


def name_anonymous_enumerators(text: str) -> str:
    """Synthesize a name for every enumerator whose NAME Ghidra dropped
    while keeping its VALUE — `    =1879048203,` inside an `enum { ... }`
    body is a hard parse error (`expected '=', ',', ';' ... before '<'
    token` in practice, since gcc treats the bare `=` as the START of the
    PRECEDING enumerator's initializer and recovers badly).

    Scoped to genuine enum bodies only (via `structure.find_enum_bodies`,
    itself brace-matched against masked text) rather than matching
    `^\\s*=value,$` anywhere in the file — an array initializer or a
    wrapped expression could otherwise produce a spurious match.

    Names are `<TAG>_RESERVED_<slug>` (`ANON<n>` for an untagged enum's
    tag), where `slug` is the literal value with `-` -> `n` and `0x`
    normalized to lowercase-`0x` — a deterministic function of (enum
    identity, value), not of a runtime counter, which is what keeps this
    idempotent even when a value repeats: the SAME two inputs always
    produce the SAME synthesized name, so a second run's dedup ordinal
    matches the first run's exactly.

    `seen` is scoped to the WHOLE FILE, not per enum — enumerators share
    the ordinary (file-scope) namespace in C, so two different enums each
    getting an anonymous member with the same value would otherwise
    synthesize the identical name twice, which is itself a new conflict
    this pass would be introducing.

    Idempotent: the rewritten line starts with an identifier, not `=`, so
    `_ANON_ENUMERATOR_RE` no longer matches it on a second pass."""
    bodies = structure.find_enum_bodies(text)
    if not bodies:
        return text

    seen: dict[str, int] = {}
    edits: list[tuple[int, int, str]] = []
    for index, body in enumerate(bodies):
        tag = body.tag or f"ANON{index}"
        body_text = text[body.body_start : body.body_end]
        for match in _ANON_ENUMERATOR_RE.finditer(body_text):
            base = f"{tag}_RESERVED_{_enum_value_slug(match.group('val'))}"
            count = seen.get(base, 0)
            seen[base] = count + 1
            name = base if count == 0 else f"{base}_{count + 1}"
            replacement = (
                f"{match.group('indent')}{name}={match.group('val')}{match.group('tail')}"
            )
            start = body.body_start + match.start()
            end = body.body_start + match.end()
            edits.append((start, end, replacement))

    if not edits:
        return text
    return structure.splice(text, edits)


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
# p13b — `void` functions whose result is used as a value
# --------------------------------------------------------------------- #

# `\A` (not `^`) — this matches against the SLICE of text from a function's
# `decl_start` to its `header_end`, not a whole-file line, so there is no
# preceding line to anchor past. `(?![ \t\n]*\*)` excludes `void *` (a real,
# correct return type) from matching.
_VOID_HEADER_RE = re.compile(r"\Avoid\b(?![ \t\n]*\*)")

# The two shapes actually observed on real firmware: `NAME = callee(...)`
# and `return callee(...)`. The negative lookbehind on `=` excludes `==`,
# `!=`, `<=`, `>=`, `+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `|=`, `^=` — none of
# those is a plain assignment FROM the call's result. `[ \t\n]*` (not just
# `[ \t]*`) between the callee name and its `(` is required because Ghidra
# wraps a long call site across lines exactly like it wraps long function
# HEADERS (`_extern_declarator`'s docstring documents the header case) —
# confirmed on real firmware: `iVar9 = tls_global_set_verify\n  (args);`
# would otherwise never match, silently leaving that one function `void`.
_VOID_VALUE_USE_RE = re.compile(
    r"(?:(?<![=!<>+\-*/%&|^])=[ \t]*|\breturn[ \t]+)(?P<callee>[A-Za-z_]\w*)[ \t\n]*\("
)

# A value-less `return;` — matched only within a promoted function's OWN
# body span (see the loop below), so this never touches a `return;` inside
# a genuinely void function elsewhere in the same file.
_BARE_RETURN_RE = re.compile(r"\breturn[ \t]*;")


def repair_void_function_results(text: str) -> str:
    """Promote a function's declared return type from `void` to `int`
    wherever a call site actually uses its result — `void FUN_004056f0(void)
    {...}` defined against call sites `iVar1 = FUN_004056f0();`,
    `sVar1 = FUN_004056f0();` elsewhere in the same file is a real defect
    (Ghidra couldn't resolve a shared PLT/syscall-dispatch trampoline's
    return type and defaulted to `void`, but the binary calls it
    polymorphically), and gcc reports it as `invalid use of void
    expression` at every such call site — one broken declaration, many
    downstream errors.

    Two-scan, one pure pass:

    1. `void_defined` — names of functions (`structure.find_function_
       bodies`) whose header starts `void` (excluding `void *`, a
       legitimate return type `_VOID_HEADER_RE` never matches).
    2. `used_as_value` — callee names appearing in the two observed value
       contexts (`_VOID_VALUE_USE_RE`), matched against `mask_non_code` so
       a callee-shaped token inside a comment or string can't count.

    Only the INTERSECTION is rewritten — the great majority of `void`
    functions on real firmware genuinely return nothing and must stay
    untouched. `int`, not `undefined4`: real call sites on this file assign
    into `int`-family locals (`iVar1 = ...`), and `undefined4` is
    `uint32_t` — an implicit narrowing at a `long`-typed assignment site
    would trade one diagnostic for another.

    A bare `return;` inside a promoted function (an early-exit path Ghidra
    emitted with no value) is rewritten to `return 0;` — verified on this
    project's own gcc toolchain (GCC 16, MinGW) that a value-less `return`
    in a NON-void function is a hard ERROR under `-Wreturn-mismatch`, NOT
    merely a warning `-w` would suppress: `int f(void) { return; }`
    reports `error: 'return' with no value, in function returning non-void`
    even with every warning flag off. Promoting the header without also
    fixing this would trade one hard compile error for another. `0` is an
    arbitrary but safe placeholder — Joern's CDT frontend doesn't type-
    check, so the specific value never affects CPG construction; this is
    purely what keeps `gcc -fsyntax-only` (this pipeline's optional Layer
    B validation) satisfied.

    This REVERSES a decision `normalize/__init__.py`'s module docstring
    used to record as deliberately out of scope — see that docstring's
    current text for the updated rationale: unlike control-flow
    restructuring or CONCAT/SUB expansion, an uncorrected `void`-as-value
    mismatch is a hard PARSE error under gcc's stricter checking and (via
    a missing return-value data-flow edge) an accuracy loss in the CPG
    itself, so the same "Joern doesn't type-check, no payoff" argument
    that rules out the other out-of-scope items does not apply here.

    Idempotent: after the edit, the header reads `int NAME(`, so
    `void_defined` no longer contains `NAME` on a second pass — the
    intersection with `used_as_value` is then empty, regardless of
    `used_as_value` itself, whose contents never change (nothing in this
    pass ever touches a call site's own text, only a declaration site)."""
    bodies = structure.find_function_bodies(text)
    if not bodies:
        return text

    void_defined = {
        body.name
        for body in bodies
        if _VOID_HEADER_RE.match(text[body.decl_start : body.header_end])
    }
    if not void_defined:
        return text

    masked = mask_non_code(text)
    used_as_value = {m.group("callee") for m in _VOID_VALUE_USE_RE.finditer(masked)}
    to_promote = void_defined & used_as_value
    if not to_promote:
        return text

    edits: list[tuple[int, int, str]] = []
    for body in bodies:
        if body.name not in to_promote:
            continue
        header = text[body.decl_start : body.header_end]
        match = _VOID_HEADER_RE.match(header)
        if not match:
            continue
        edits.append((body.decl_start, body.decl_start + match.end(), "int"))

        body_masked = mask_non_code(text[body.body_start : body.body_end])
        for ret_match in _BARE_RETURN_RE.finditer(body_masked):
            start = body.body_start + ret_match.start()
            end = body.body_start + ret_match.end()
            edits.append((start, end, "return 0;"))

    if not edits:
        return text
    return structure.splice(text, edits)


# --------------------------------------------------------------------- #
# p13c — forward declarations for functions called before their definition
# --------------------------------------------------------------------- #

_FORWARD_DECL_MARKER = "/* fw-audit: forward declarations (generated) */"

# A call site: a bare identifier immediately followed by `(` — used to find
# every name CALLED anywhere in the file, so hoisting can be scoped to only
# the names actually called before their own definition.
_CALL_SITE_RE = re.compile(r"\b(?P<callee>[A-Za-z_]\w*)[ \t]*\(")

# An existing column-0 function declaration/definition-header line for
# NAME — covers both a real definition's header and an `extern` declarator
# `replace_thunk_bodies`/this pass itself may already have emitted. `(`
# somewhere before the terminating `;` or `{` is what distinguishes this
# from `_GLOBAL_DECL_RE` (p12b), which explicitly excludes `(`.
def _existing_declaration_names(text: str) -> set[str]:
    masked = mask_non_code(text)
    names: set[str] = set()
    for match in re.finditer(
        r"^(?:extern[ \t]+)?[A-Za-z_][\w \t*]*?\b(?P<name>[A-Za-z_]\w*)[ \t]*\([^;{}]*\)[ \t]*[;{]",
        masked,
        re.MULTILINE,
    ):
        names.add(match.group("name"))
    return names


def hoist_function_prototypes(context: BinaryContext, text: str) -> str:
    """Emit a forward declaration for every function that is CALLED before
    its own definition appears in the file — Ghidra decompiles a statically
    linked binary's real libc functions (`gmtime`, `fcntl`, ...) as ordinary
    functions defined later in the same file, so nothing declares them
    before their first call site, C99's implicit-int fallback kicks in, and
    it then conflicts with the real (later) definition:
    `conflicting types for 'gmtime'`.

    Scoped NARROWLY to call-before-definition names only, not every
    function in the file — a full forward-declaration block for every
    function would be strictly safer but adds disproportionate size for a
    call-before-definition count that, once thunk bodies are excluded (see
    below), is small; Layer A's `missing_prototype` validation check
    reports if that count is ever larger than expected, so the narrow
    scope can grow on evidence.

    Reuses `_extern_declarator` (the same collapsing-to-one-line logic
    `replace_thunk_bodies` already uses) WITHOUT its `extern ` prefix — a
    forward declaration for a function DEFINED in this same file doesn't
    need `extern` (harmless if present, but redundant).

    Inserted at the first function body's `decl_start` — NOT immediately
    after the prelude — because a declaration's parameter/return types may
    reference a Ghidra struct typedef declared in Ghidra's own type block,
    which sits between the prelude and the first function body;
    `bodies[0].decl_start` is the earliest point where every type name any
    signature could reference is already in scope.

    Skips (all in addition to the call-before-definition requirement
    itself):

    * names with any existing column-0 declaration already in the file
      (`_existing_declaration_names` — covers `replace_thunk_bodies`'s own
      `extern` declarators and a second run of this same pass);
    * any declarator whose text contains a nested `(` before its own
      parameter list closes (a K&R-style or function-pointer-return-type
      header this module's regex-based declarator text can't safely
      re-flatten) — skipped rather than risk emitting a malformed
      prototype;
    * `context.thunk_names | context.external_names` — MANDATORY, not an
      optimization: `replace_thunk_bodies` only replaces a stub whose body
      matches its narrow "exact self-forwarding call" shape
      (`_is_self_forwarding_stub`); a different trampoline shape (measured
      on real firmware: MIPS PLT/GOT dispatch stubs, repeated indirect
      calls through `unaff_gp`-relative offsets, for `connect`, `fopen`,
      `qsort`, `getaddrinfo`, and 18+ other real libc names) is left as an
      ordinary function body with a header Ghidra wrote from its own
      symbol/debug info — using real system-header type names
      (`sockaddr`, `FILE`, `addrinfo`, `socklen_t`, `timeval`, `msghdr`,
      `__uid_t`, ...) that are never actually `typedef`'d as bare names
      anywhere in this closed-world translation unit. Metadata's
      `is_thunk=True` for exactly these names is what `context.thunk_
      names` carries — POSITIVE confirmation, not `may_stub`'s "not
      contradicted" bias-toward-True (which would veto hoisting for nearly
      every name under `EMPTY_CONTEXT` and defeat this pass on a binary
      with no/malformed metadata). `EMPTY_CONTEXT`'s empty `thunk_names`/
      `external_names` therefore vetoes nothing — the call-before-
      definition scoping is what keeps that degradation safe on its own.

    Idempotent via `_FORWARD_DECL_MARKER`, checked first and unconditionally
    honored — a second run makes zero edits."""
    if _FORWARD_DECL_MARKER in text:
        return text
    bodies = structure.find_function_bodies(text)
    if not bodies:
        return text

    masked = mask_non_code(text)
    body_by_name = {body.name: body for body in bodies}
    already_declared = _existing_declaration_names(text)
    veto_names = context.thunk_names | context.external_names

    needs_prototype: list[str] = []
    seen: set[str] = set()

    # Single left-to-right scan: a name is "called before its definition"
    # if any call site for it appears (by offset) before that name's own
    # `decl_start`.
    first_call_offset: dict[str, int] = {}
    for match in _CALL_SITE_RE.finditer(masked):
        name = match.group("callee")
        if name in body_by_name and name not in first_call_offset:
            first_call_offset[name] = match.start()

    for name, body in body_by_name.items():
        if name in already_declared or name in seen or name in veto_names:
            continue
        call_offset = first_call_offset.get(name)
        if call_offset is None or call_offset >= body.decl_start:
            continue
        header_text = text[body.decl_start : body.header_end]
        paren_start = header_text.index("(")
        declarator_body = header_text[paren_start + 1 : header_text.rindex(")")]
        if "(" in declarator_body:
            # A nested `(` inside the parameter list (K&R-style or a
            # function-pointer parameter/return type) — skip rather than
            # risk `_extern_declarator`'s single-line flattening producing
            # a malformed prototype.
            continue
        seen.add(name)
        needs_prototype.append(name)

    if not needs_prototype:
        return text

    # Preserve source order for determinism/readability.
    needs_prototype.sort(key=lambda n: body_by_name[n].decl_start)
    protos = [
        _extern_declarator(text, body_by_name[name]).removeprefix("extern ")
        for name in needs_prototype
    ]
    block = f"{_FORWARD_DECL_MARKER}\n" + "\n".join(protos) + "\n\n"
    return structure.splice(text, [(bodies[0].decl_start, bodies[0].decl_start, block)])


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
