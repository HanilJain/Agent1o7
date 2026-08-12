"""Find function-body boundaries in Ghidra-emitted C, and splice edits into
the surrounding text — the one structural primitive `passes.py`'s
body-aware passes (`declare_register_vars`, `replace_thunk_bodies`) share,
instead of each hand-rolling its own cursor loop.

Extracted from `passes.py` (where an earlier, per-pass version of this
existed as `_find_function_bodies`/`_find_matching_brace`) for three
reasons, all confirmed against real Ghidra output:

1. **Performance.** The original re-tokenized the whole remaining file per
   function header to find that header's matching brace — quadratic in
   file size. Measured on a 6 MB whole-program file: ~15-20 minutes. This
   version tokenizes the file once and matches braces via a precomputed,
   sorted offset list.
2. **Comment-blindness.** Ghidra emits failure comments like
   `/* Unable to decompile 'FUN_0007783c' ... */` whose body reads as
   plausible function-header text to a regex run against raw source,
   producing spurious matches. Structural regexes here run against
   `spans.mask_non_code`, not the raw text.
3. **Multi-line signatures.** Ghidra sometimes wraps a signature across
   lines when it's long:
       bool wlcsm_mngr_resume_restart
                      (undefined4 param_1,undefined4 param_2)
       {
   A single-line header pattern misses these outright (measured: 150 of
   162 bodies found in one real binary). The pattern here spans lines but
   cannot run away, because `;`, `{`, and `}` are all excluded from what it
   may match.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Sequence
from typing import NamedTuple

from fw_audit.stage2_extraction.normalize.spans import mask_non_code

# A function header: starts at column 0 with an identifier character (never
# whitespace, `{`, or a preprocessor `#`), then anything at all EXCEPT `;`,
# `{`, `}`, or `(`/`)` outside the parameter list, up to a parenthesized
# parameter list, then `{`. Excluding `;{}` from the "anything" portion is
# what bounds the match — it cannot cross into a neighboring statement or
# definition. Runs against the masked (comment/string/char-blanked) text.
_FUNCTION_HEADER_RE = re.compile(
    r"^[A-Za-z_][^;{}()]*\([^;{}]*\)\s*\{",
    re.MULTILINE | re.DOTALL,
)

# The declarator name is the identifier immediately before the parameter
# list's opening '('.
_DECLARATOR_NAME_RE = re.compile(r"([A-Za-z_]\w*)\s*\([^;{}()]*\)\s*\{\Z", re.DOTALL)

# One top-level parameter's declared name is the trailing identifier in its
# comma-separated chunk (skips `void`, `...`, and bare type names with no
# name, all of which have no trailing identifier of interest).
_PARAM_NAME_RE = re.compile(r"([A-Za-z_]\w*)\s*$")


class FunctionBody(NamedTuple):
    """One function definition found in a file's text.

    All offsets index into the ORIGINAL (unmasked) text — `mask_non_code`
    preserves length and newlines, so offsets found against the mask are
    valid there unchanged.
    """

    name: str
    params: tuple[str, ...]
    decl_start: int
    """Start of the declaration (the function's return type), i.e. the
    start of the regex match — NOT the same as `body_start`."""
    header_end: int
    """Index just past the opening `{`."""
    body_start: int
    """Index of the first character of the function body (== header_end)."""
    body_end: int
    """Index of the matching closing `}`."""


def _brace_offsets(masked: str) -> tuple[int, ...]:
    """Every `{`/`}` offset in `masked`'s CODE-equivalent text, in order.
    `masked` already has STRING/CHAR/COMMENT spans blanked, so a plain scan
    is safe — no need to re-tokenize."""
    return tuple(i for i, ch in enumerate(masked) if ch in "{}")


def _matching_brace(masked: str, brace_offsets: Sequence[int], open_pos: int) -> int | None:
    """Depth-count forward from `open_pos` (must index a `{` in `masked`)
    using the precomputed offset list, so this does not rescan `masked`
    character-by-character from scratch for every call."""
    start_idx = bisect_right(brace_offsets, open_pos) - 1
    if start_idx < 0 or brace_offsets[start_idx] != open_pos:
        return None
    depth = 0
    for offset in brace_offsets[start_idx:]:
        depth += 1 if masked[offset] == "{" else -1
        if depth == 0:
            return offset
    return None


def _parse_params(param_list: str) -> tuple[str, ...]:
    """Extract each top-level parameter's declared name, in order. `void`
    and `...` contribute nothing; nested parens (function-pointer params)
    aren't split on, since there is no top-level comma inside one — this
    only ever matters for the argument-identity check in
    `passes.replace_thunk_bodies`, where a function-pointer param is rare
    and, if present, simply won't match a call argument (safe failure)."""
    param_list = param_list.strip()
    if not param_list or param_list == "void":
        return ()
    names = []
    for chunk in param_list.split(","):
        chunk = chunk.strip()
        if chunk in ("", "..."):
            continue
        match = _PARAM_NAME_RE.search(chunk)
        if match:
            names.append(match.group(1))
    return tuple(names)


def find_function_bodies(text: str) -> tuple[FunctionBody, ...]:
    """Every function definition in `text`, in source order.

    Reliable specifically because this is Ghidra-generated code with a
    small, fixed, highly regular emitter style — not hand-written C (see
    `normalize/__init__.py`'s module docstring for the fuller argument)."""
    masked = mask_non_code(text)
    brace_offsets = _brace_offsets(masked)
    bodies: list[FunctionBody] = []
    for match in _FUNCTION_HEADER_RE.finditer(masked):
        header_end = match.end()
        open_pos = header_end - 1
        if masked[open_pos] != "{":
            continue
        body_end = _matching_brace(masked, brace_offsets, open_pos)
        if body_end is None:
            continue
        header_text = match.group()
        name_match = _DECLARATOR_NAME_RE.search(header_text)
        if not name_match:
            continue
        paren_start = header_text.index("(", name_match.start())
        paren_end = header_text.rindex(")")
        params = _parse_params(header_text[paren_start + 1 : paren_end])
        bodies.append(
            FunctionBody(
                name=name_match.group(1),
                params=params,
                decl_start=match.start(),
                header_end=header_end,
                body_start=header_end,
                body_end=body_end,
            )
        )
    return tuple(bodies)


def splice(text: str, edits: Sequence[tuple[int, int, str]]) -> str:
    """Replace each `text[start:end]` with `replacement`, for a sequence of
    non-overlapping `(start, end, replacement)` edits given in any order.
    Pure — returns new text, `text` itself is never mutated."""
    ordered = sorted(edits, key=lambda e: e[0])
    pieces: list[str] = []
    cursor = 0
    for start, end, replacement in ordered:
        if start < cursor:
            raise ValueError(f"overlapping edit at {start}: cursor already at {cursor}")
        pieces.append(text[cursor:start])
        pieces.append(replacement)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


__all__ = ["FunctionBody", "find_function_bodies", "splice"]
