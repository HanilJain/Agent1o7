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
    """`CONCAT<H><L>(high, low)` concatenates an H-byte high part and an
    L-byte low part into one H+L-byte value — generated only for the
    power-of-two result widths {2, 4, 8, 16} Ghidra emits most often; wider,
    non-power-of-two results are rare enough in practice to leave unhandled
    rather than bloat this header with ~60 combinations for little gain."""
    lines: list[str] = []
    for total, result_type in ((2, "uint16_t"), (4, "uint32_t"), (8, "uint64_t")):
        for h in range(1, total):
            low = total - h
            if low < 1:
                continue
            lines.append(
                f"#define CONCAT{h}{low}(hi, lo) "
                f"(({result_type})((({result_type})(uint{h * 8}_t)(hi)) << {low * 8}"
                f" | ({result_type})(uint{low * 8}_t)(lo)))"
            )
    # 16-byte results (e.g. CONCAT88) need a 128-bit container; `__int128`
    # is a GCC/Clang extension, which both gcc's `-fsyntax-only` and Joern's
    # Eclipse-CDT-based C frontend accept.
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
    to Y bytes. Generated for the widths {1, 2, 4, 8} Ghidra uses."""
    widths = (1, 2, 4, 8)
    lines: list[str] = []
    for x in widths:
        x_type = _NATIVE_SIZE_TO_TYPE[x]
        for y in widths:
            if y >= x:
                continue
            y_type = _NATIVE_SIZE_TO_TYPE[y]
            lines.append(
                f"#define SUB{x}{y}(v, n) (({y_type})(({x_type})(v) >> ((n) * 8)))"
            )
    for x in widths:
        x_type = _NATIVE_SIZE_TO_TYPE[x]
        x_signed = f"int{x * 8}_t"
        for y in widths:
            if y <= x:
                continue
            y_type = _NATIVE_SIZE_TO_TYPE[y]
            y_signed = f"int{y * 8}_t"
            lines.append(f"#define ZEXT{x}{y}(v) (({y_type})({x_type})(v))")
            lines.append(f"#define SEXT{x}{y}(v) (({y_signed})({x_signed})(v))")
    return "\n".join(lines)


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
    specific binary."""
    sections = [
        f"#ifndef {_INCLUDE_GUARD}",
        f"#define {_INCLUDE_GUARD}",
        "",
        "/* Generated by fw_audit.stage2_extraction.normalize.prelude — do not",
        " * hand-edit; regenerate by re-running Stage 2. */",
        "",
        "#include <stdint.h>",
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

PRELUDE_HEADER_FILENAME = "ghidra_types.h"


def inline_prelude(text: str) -> str:
    """Joern target: prepend the full header text verbatim — Joern runs no
    preprocessor and will not resolve an `#include`.

    Guarded by the include-guard macro name rather than being unconditional
    — `normalize()` must be idempotent (see `tests/test_normalizer.py`), and
    an unconditional prepend would double the prelude on a second pass."""
    if _INCLUDE_GUARD in text:
        return text
    return f"{PRELUDE_HEADER}\n{text}"


_INCLUDE_DIRECTIVE = f'#include "{PRELUDE_HEADER_FILENAME}"'


def include_prelude(text: str) -> str:
    """LLM target: a one-line `#include`, saving ~100+ lines of typedefs
    and macros from every function-granular chunk's context budget. The
    header itself is written once to `stage2/ghidra_types.h` by the caller.

    Guarded the same way as `inline_prelude`, for the same idempotence reason."""
    if _INCLUDE_DIRECTIVE in text:
        return text
    return f"{_INCLUDE_DIRECTIVE}\n\n{text}"
