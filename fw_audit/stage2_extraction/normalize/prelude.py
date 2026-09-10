"""Generate `ghidra_types.h` — the prelude that turns Ghidra's non-standard
vocabulary into a naming problem instead of a rewriting problem.

Every one of Ghidra's `undefined`/`uint`/`code`-family types "becomes" a
standard C type via a `typedef`, and every `CONCATxy`/`SUBxy`/`ZEXTxy`/
`SEXTxy` intrinsic "becomes" callable via a `#define` — no source text is
touched for any of these. A declaration cannot corrupt code; this is why
the prelude, not a textual pass, owns this whole category of distortion
(see `normalize/__init__.py`'s docstring for the full division of labour).
"""

from __future__ import annotations

_INCLUDE_GUARD = "FW_AUDIT_GHIDRA_TYPES_H"

# Sizes (in bytes) that map directly onto a native fixed-width integer type.
_NATIVE_SIZE_TO_TYPE = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}

# Container type (may be WIDER than the size itself, for 3/5/6/7) and its
# bitmask literal — shared by `_undefined_family` and the CONCAT generator,
# so an operand narrower than its container is masked consistently
# everywhere it's cast (see `_concat_macros`'s docstring for why the mask
# is mandatory, not cosmetic).
_CONTAINER_TYPE = {
    1: "uint8_t", 2: "uint16_t", 3: "uint32_t", 4: "uint32_t",
    5: "uint64_t", 6: "uint64_t", 7: "uint64_t", 8: "uint64_t",
}  # fmt: skip
_CONTAINER_MASK = {n: f"0x{'FF' * n}ULL" for n in range(1, 9)}


def _fixed_width_types() -> str:
    """Self-contained `uintN_t`/`intN_t`/`uintptr_t`/`intptr_t` typedefs —
    NOT `#include <stdint.h>`. Two independent reasons this include must
    never come back:

    1. `joern-parse` (Eclipse CDT) resolves an `#include` against NO system
       include path — it expands `#define`s in the translation unit but
       cannot follow `<stdint.h>` to anything, so every `uint32_t` etc. in
       this very header would be an unknown type IN THE CPG ITSELF. This is
       the decisive reason, independent of any host toolchain.
    2. On the host (`gcc -fsyntax-only`, used by this pipeline's optional
       validation layer), the REAL `<stdint.h>` transitively redeclares
       several of the same POSIX-internal names this file also declares
       (`size_t`, `ssize_t`, `time_t`, `intptr_t`, `__gnuc_va_list`, ...)
       with a different underlying type on different hosts (confirmed:
       MinGW and glibc each collide on a DIFFERENT subset) — same width,
       distinct C type, so it's a hard conflict even though semantically
       harmless. This translation unit never links against real libc, so
       it has no reason to depend on any host header at all.

    Widths here are NOMINAL (chosen to be correct on both LP64 and LLP64),
    not host-exact — nothing in this file is ever executed.

    `uintptr_t`/`intptr_t` are NOT optional: `passes.declare_register_vars`
    synthesizes `uintptr_t NAME;` locals for every `in_*`/`unaff_*`/
    `extraout_*` reference, and depended on `<stdint.h>` for that type
    before this function existed (measured on real firmware: 8 uses of
    `uintptr_t`, 2 of `intptr_t`, in one binary alone).

    Deliberately does NOT declare `size_t`/`ssize_t`: Ghidra emits its own
    (`typedef ulong size_t;`, confirmed present in real output) — adding
    ours would recreate exactly the conflict this function exists to
    eliminate."""
    return "\n".join(
        [
            "typedef unsigned char       uint8_t;",
            "typedef signed char         int8_t;",
            "typedef unsigned short      uint16_t;",
            "typedef short               int16_t;",
            "typedef unsigned int        uint32_t;",
            "typedef int                 int32_t;",
            "typedef unsigned long long  uint64_t;",
            "typedef long long           int64_t;",
            "typedef unsigned long long  uintptr_t;",
            "typedef long long           intptr_t;",
        ]
    )


def _undefined_family() -> str:
    lines = ["typedef unsigned char undefined;", "typedef unsigned char undefined1;"]
    for n in (2, 3, 4, 5, 6, 7, 8):
        container = _NATIVE_SIZE_TO_TYPE.get(n) or _NATIVE_SIZE_TO_TYPE[8]
        lines.append(f"typedef {container} undefined{n};")
    return "\n".join(lines)


def _short_aliases() -> str:
    # Ghidra's other common non-standard type names, all direct aliases.
    return "\n".join(
        [
            "typedef unsigned int uint;",
            "typedef unsigned long ulong;",
            "typedef unsigned short ushort;",
            "typedef unsigned char byte;",
            "typedef signed char sbyte;",
            "typedef unsigned short word;",
            "typedef unsigned int dword;",
            "typedef unsigned long long qword;",
            "typedef long long longlong;",
            "typedef unsigned long long ulonglong;",
            "typedef void *pointer;",
            "",
            "/* `code` is Ghidra's \"executable bytes at an address\" type;",
            " * `code *` is its generic function-pointer idiom, e.g.",
            " * `code *pcVar1` or `(*(code *)ptr)(a, b)`. It must be a",
            " * FUNCTION type, not `void` — that idiom needs something",
            " * dereferenceable, callable with any arguments, and",
            " * assignable-from all at once, which `typedef void code;`",
            " * cannot satisfy (verified: every such call site becomes a",
            " * hard 'invalid use of void expression' error under that",
            " * definition). C23 makes an empty `()` parameter list mean",
            " * `(void)` — `(...)` is required there instead — while a",
            " * pre-C23 compiler (and Eclipse CDT, Joern's C frontend) both",
            " * accept the classic unprototyped `()` form; branch on",
            " * __STDC_VERSION__ so both take the callable-with-anything",
            " * shape they each support. */",
            "#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L",
            "typedef int code(...);",
            "#else",
            "typedef int code();",
            "#endif",
        ]
    )


def _c99_bool() -> str:
    """`bool`/`true`/`false` — Ghidra emits them freely but never declares
    them. Guarded on `__STDC_VERSION__`: under C23 these are keywords, so
    redeclaring `bool` as a typedef is a hard error there; pre-C23 (and
    Eclipse CDT, which does not define `__STDC_VERSION__ >= 202311L`) treat
    `bool` as a plain identifier needing exactly this declaration."""
    return "\n".join(
        [
            "#ifndef __cplusplus",
            "#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L",
            "typedef unsigned char bool;",
            "#define true 1",
            "#define false 0",
            "#endif",
            "#endif",
        ]
    )


def _ghidra_pseudo_types() -> str:
    """Names Ghidra's CppExporter occasionally emits where a TYPE is
    expected but a PARAMETER NAME appears instead (observed on glibc's
    `pthread_create`-style prototypes: `__start_routine *__start_routine`).
    `typedef void X;` makes `X *` equivalent to `void *`, which is correct
    at every such site — this is a declaration-only fix, so it carries the
    same zero-rewriting-risk property as every other prelude entry.

    `string` is a second such pseudo-type, confirmed against real firmware:
    Ghidra labels a recovered string-literal address symbol
    (`s_<hash>_<addr>`) with the bare declaration `string s_...;` and every
    site that references it treats it exactly like `char *` (assigned to
    a `char *` local, passed where a `char *` argument is expected) — so
    `typedef char *string;` is the correct, zero-rewriting declaration."""
    return "\n".join(
        [
            "typedef void __start_routine;",
            "typedef char *string;",
        ]
    )


def _unk_wide_types() -> str:
    """Widths Ghidra reaches for when a CONCAT/cast result exceeds 8 bytes
    and no native integer type covers it (9..16 bytes) — a byte-array
    struct is the only portable representation."""
    lines = []
    for n in range(9, 17):
        lines.append(f"typedef struct {{ uint8_t b[{n}]; }} unkbyte{n};")
        lines.append(f"typedef unkbyte{n} unkuint{n};")
    return "\n".join(lines)


def _concat_macros() -> str:
    """`CONCAT<H><L>(hi, lo)` concatenates an H-byte high part and an
    L-byte low part into one H+L-byte value. Generated for every `H, L in
    1..8` whose result fits in 8 bytes (28 macros) — a FULL combinatorial
    set, not only the power-of-two totals {2, 4, 8} an earlier version of
    this function covered.

    That earlier, narrower version was not just incomplete — it was
    ACTIVELY WRONG for any 3/5/6/7-byte operand: it cast the operand to a
    type like `uint24_t`/`uint40_t`/`uint48_t`/`uint56_t`, none of which
    exist anywhere (confirmed against real firmware: `CONCAT13`/`CONCAT17`/
    `CONCAT26`/`CONCAT31`/`CONCAT35`/`CONCAT53`/`CONCAT62`/`CONCAT71` all
    referenced `uintNN_t` types this very header never defines — 8 of the
    11 CONCAT macros shipped were poison that detonated on use, and all 8
    ARE used on real firmware). This version casts every operand to its
    CONTAINER type (`_CONTAINER_TYPE`, which for 3/5/6/7 is the next-wider
    NATIVE type: `uint32_t`/`uint64_t`) instead — a type that always
    exists — and then MASKS it (`_CONTAINER_MASK`) before shifting/OR-ing.
    The mask is what makes this correct, not merely parse-legal: a 3-byte
    operand's high byte inside its (wider) `uint32_t` container is garbage
    from whatever produced it, and without the mask that garbage would
    leak into the concatenated result's own high bits.

    9-16 byte results need a 128-bit container (`unsigned __int128`, a
    GCC/Clang extension both gcc's `-fsyntax-only` and Joern's Eclipse-CDT
    frontend accept) guarded by `#ifdef __SIZEOF_INT128__`. Rather than all
    228 combinatorially possible wide forms (~30 KB of largely-unused
    macros in every normalized file), only the forms actually observed on
    real firmware are generated: `CONCAT88` (the two 8-byte-operand halves
    of a 16-byte result). Deliberately NO `#else` fallback for these: a
    lossy 64-bit definition would silently change semantics for whichever
    caller uses it, whereas leaving a rare wide form undefined is
    correct — Eclipse CDT treats an unknown macro-shaped call as an
    ordinary (unresolved) function call and still builds the CPG; this
    module's validation gate separately reports any USED-but-undefined
    intrinsic, so the guarded set can grow from evidence rather than
    speculation without ever reintroducing the `uint24_t`-style poison."""
    lines: list[str] = []
    seen: set[str] = set()
    for h in range(1, 9):
        for lo in range(1, 9):
            total = h + lo
            if total > 8:
                continue
            name = f"CONCAT{h}{lo}"
            assert name not in seen, f"duplicate macro name generated: {name}"
            seen.add(name)
            result_type = _CONTAINER_TYPE[total]
            hi_type, hi_mask = _CONTAINER_TYPE[h], _CONTAINER_MASK[h]
            lo_type, lo_mask = _CONTAINER_TYPE[lo], _CONTAINER_MASK[lo]
            lines.append(
                f"#define {name}(hi, lo) "
                f"(({result_type})"
                f"((({result_type})(({hi_type})(hi) & ({hi_type}){hi_mask}) << {lo * 8})"
                f" | (({result_type})(({lo_type})(lo) & ({lo_type}){lo_mask}))))"
            )
    lines.append("#ifdef __SIZEOF_INT128__")
    lines.append(
        "#define CONCAT88(hi, lo) "
        "((unsigned __int128)(((unsigned __int128)(uint64_t)(hi)) << 64"
        " | (unsigned __int128)(uint64_t)(lo)))"
    )
    lines.append("#endif")
    return "\n".join(lines)


def _sub_zext_sext_macros() -> str:
    """`SUB<X><Y>(v, n)` extracts Y bytes starting at byte offset `n` from an
    X-byte value; `ZEXT<X><Y>`/`SEXT<X><Y>` zero/sign-extend an X-byte value
    to Y bytes. Generated for the FULL combinatorial set `X, Y in 1..8`
    (28 SUB + 28 ZEXT + 28 SEXT), not only `{1, 2, 4, 8}` — an earlier
    version's narrower set was silent (parse-legal, but the macro simply
    didn't exist) for any 3/5/6/7-byte operand, the same failure mode
    `_concat_macros` had for its result type, just without that version's
    additional "references a type that doesn't exist" defect, since these
    two macro families only ever cast to/from `_CONTAINER_TYPE`'s (always-
    real) native types.

    `SUB<X><Y>`'s `X` container may be WIDER than `X` bytes (3/5/6/7 map to
    a native 4/8-byte container) — masking with `_CONTAINER_MASK[x]` before
    the right-shift is what keeps a genuinely 3-byte value's upper
    (garbage) container byte from leaking into the extracted result,
    exactly as in `_concat_macros`.

    Also generates the narrow, `__int128`-guarded 9-16 byte forms
    `SUB16{1,2,4,8}` / `ZEXT{1,2,4,8}16` / `SEXT{1,2,4,8}16` — the same
    "guard the wide forms, generate only what's evidenced, no `#else`
    fallback" policy `_concat_macros` applies to `CONCAT88`, for the same
    reason: the full 9-16-byte combinatorial set is ~130 more macros for
    forms that (unlike the portable {1..8} set) are rare in practice, and
    an undefined wide form is CORRECT for Joern (an unknown macro-shaped
    call still lets CDT build the CPG) whereas a lossy `#else` definition
    would silently change semantics."""
    lines: list[str] = []
    seen: set[str] = set()
    for x in range(1, 9):
        x_type, x_mask = _CONTAINER_TYPE[x], _CONTAINER_MASK[x]
        for y in range(1, x):
            name = f"SUB{x}{y}"
            assert name not in seen, f"duplicate macro name generated: {name}"
            seen.add(name)
            y_type = _CONTAINER_TYPE[y]
            lines.append(
                f"#define {name}(v, n) "
                f"(({y_type})((({x_type})(v) & ({x_type}){x_mask}) >> ((n) * 8)))"
            )
    for x in range(1, 9):
        x_type = _CONTAINER_TYPE[x]
        x_signed = f"int{bit_width(x)}_t"
        for y in range(x + 1, 9):
            y_type = _CONTAINER_TYPE[y]
            y_signed = f"int{bit_width(y)}_t"
            zext_name, sext_name = f"ZEXT{x}{y}", f"SEXT{x}{y}"
            assert zext_name not in seen and sext_name not in seen, (
                f"duplicate macro name generated: {zext_name}/{sext_name}"
            )
            seen.add(zext_name)
            seen.add(sext_name)
            lines.append(f"#define {zext_name}(v) (({y_type})({x_type})(v))")
            lines.append(f"#define {sext_name}(v) (({y_signed})({x_signed})(v))")

    lines.append("#ifdef __SIZEOF_INT128__")
    for x in (1, 2, 4, 8):
        x_type, x_mask = _CONTAINER_TYPE[x], _CONTAINER_MASK[x]
        sub_name = f"SUB16{x}"
        assert sub_name not in seen, f"duplicate macro name generated: {sub_name}"
        seen.add(sub_name)
        lines.append(
            f"#define {sub_name}(v, n) "
            f"(({x_type})((unsigned __int128)(v) >> ((n) * 8)) & ({x_type}){x_mask})"
        )
    for x in (1, 2, 4, 8):
        x_type = _CONTAINER_TYPE[x]
        x_signed = f"int{bit_width(x)}_t"
        zext_name, sext_name = f"ZEXT{x}16", f"SEXT{x}16"
        assert zext_name not in seen and sext_name not in seen, (
            f"duplicate macro name generated: {zext_name}/{sext_name}"
        )
        seen.add(zext_name)
        seen.add(sext_name)
        lines.append(f"#define {zext_name}(v) ((unsigned __int128)({x_type})(v))")
        lines.append(f"#define {sext_name}(v) ((__int128)({x_signed})(v))")
    lines.append("#endif")
    return "\n".join(lines)


def bit_width(container_bytes: int) -> int:
    """Bit width of the NATIVE container type for `container_bytes` — 3
    maps to 32 (its container is `uint32_t`), not 24 (`uint24_t` does not
    exist; this is exactly the mistake `_concat_macros`'s docstring
    documents). Used to build `intN_t`/`uintN_t` names that are guaranteed
    to already exist, from `_fixed_width_types` or Ghidra's own `stdint`-
    family typedefs — never `int24_t`/`int40_t`/`int48_t`/`int56_t`."""
    type_name = _CONTAINER_TYPE[container_bytes]
    return int(type_name.removeprefix("uint").removesuffix("_t"))


def _halt_baddata_stub() -> str:
    # Deliberately never spells the literal call "halt_baddata()" (with
    # parens) in this comment — tests assert no unrewritten call remains in
    # normalized output via that exact substring, and this header text
    # itself gets inlined into that same output for the Joern target.
    return "\n".join(
        [
            "/* Joern target only: Ghidra's halt_baddata calls are rewritten",
            " * to this no-op rather than removed outright, so the CFG keeps",
            " * the same statement node it had in the original decompiled",
            " * output. */",
            "static inline void __fw_audit_unreachable(void) {}",
        ]
    )


def _libc_declarations() -> str:
    return "\n".join(
        [
            "extern void __assert_fail(const char *, const char *, unsigned int, const char *);",
            "extern void __stack_chk_fail(void);",
            "extern void abort(void);",
            "extern void exit(int);",
            "extern void _exit(int);",
        ]
    )


def generate_prelude_header() -> str:
    """The full `ghidra_types.h` content, deterministic given no inputs —
    it depends only on Ghidra's fixed emitter vocabulary, not on any
    specific binary.

    Deliberately ZERO `#include` directives — see `_fixed_width_types`'s
    docstring for why `#include <stdint.h>` specifically must never come
    back. This header is a fully self-contained, closed-world translation
    unit by design."""
    sections = [
        f"#ifndef {_INCLUDE_GUARD}",
        f"#define {_INCLUDE_GUARD}",
        "",
        "/* Generated by fw_audit.stage2_extraction.normalize.prelude — do not",
        " * hand-edit; regenerate by re-running Stage 2. No #include: this",
        " * header is a self-contained, closed-world translation unit — see",
        " * _fixed_width_types()'s docstring. */",
        "",
        "/* ---- Self-contained fixed-width types (NOT <stdint.h>) --------- */",
        _fixed_width_types(),
        "",
        "/* ---- Ghidra's `undefined`-family byte-sized types ------------- */",
        _undefined_family(),
        "",
        "/* ---- Ghidra's other short type aliases ------------------------ */",
        _short_aliases(),
        "",
        "/* ---- C99 bool (Ghidra emits it, never declares it) ------------- */",
        _c99_bool(),
        "",
        "/* ---- Ghidra pseudo-types (parameter name used as a type) ------- */",
        _ghidra_pseudo_types(),
        "",
        "/* ---- Wide (9-16 byte) container types -------------------------- */",
        _unk_wide_types(),
        "",
        "/* ---- CONCAT intrinsics ----------------------------------------- */",
        _concat_macros(),
        "",
        "/* ---- SUB/ZEXT/SEXT intrinsics ----------------------------------- */",
        _sub_zext_sext_macros(),
        "",
        "/* ---- halt_baddata replacement (Joern target only) --------------- */",
        _halt_baddata_stub(),
        "",
        "/* ---- libc declarations Ghidra references but doesn't declare --- */",
        _libc_declarations(),
        "",
        f"#endif /* {_INCLUDE_GUARD} */",
        "",
    ]
    return "\n".join(sections)


#: Computed once at import time — the header's content is a pure function
#: of nothing, so there is no reason to regenerate it per call.
PRELUDE_HEADER = generate_prelude_header()


def inline_prelude(text: str) -> str:
    """Prepend the full header text verbatim — Joern runs no preprocessor
    and will not resolve an `#include`.

    Guarded by the include-guard macro name rather than being unconditional
    — `normalize()` must be idempotent (see `tests/test_normalizer.py`), and
    an unconditional prepend would double the prelude on a second pass."""
    if _INCLUDE_GUARD in text:
        return text
    return f"{PRELUDE_HEADER}\n{text}"
