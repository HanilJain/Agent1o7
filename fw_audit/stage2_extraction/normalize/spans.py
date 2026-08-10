"""Split Ghidra-emitted C source into CODE/STRING/CHAR/COMMENT spans.

This is what makes regex-based rewriting in `passes.py` safe: every pass
that needs to avoid touching string/char literals and comments calls
`apply_to_code`, which only ever hands a pass function the CODE spans and
reassembles the STRING/CHAR/COMMENT spans verbatim around them. Without
this, a pass matching e.g. `undefined4` as a bare identifier could also
rewrite it inside a string literal or a `/* WARNING: ... */` comment.

Deliberately regex-based, not a full C tokenizer: Ghidra's emitter output is
generated text with a small, fixed, highly regular vocabulary (see
`normalize/__init__.py`'s docstring for the fuller argument), so a
string/char/comment splitter is the only span-awareness this pipeline needs.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

# Order matters: comments are checked before string/char so a `"` inside a
# `//` or `/* */` comment is never mistaken for the start of a string.
_TOKEN_RE = re.compile(
    r"(?P<BLOCK_COMMENT>/\*.*?\*/)"
    r"|(?P<LINE_COMMENT>//[^\n]*)"
    r"|(?P<STRING>\"(?:\\.|[^\"\\])*\")"
    r"|(?P<CHAR>'(?:\\.|[^'\\])*')",
    re.DOTALL,
)


class SpanKind(str, Enum):
    CODE = "code"
    STRING = "string"
    CHAR = "char"
    COMMENT = "comment"


@dataclass(frozen=True)
class Span:
    kind: SpanKind
    text: str


_GROUP_TO_KIND = {
    "BLOCK_COMMENT": SpanKind.COMMENT,
    "LINE_COMMENT": SpanKind.COMMENT,
    "STRING": SpanKind.STRING,
    "CHAR": SpanKind.CHAR,
}


def tokenize(text: str) -> tuple[Span, ...]:
    """Split `text` into an ordered sequence of spans covering it exactly —
    `"".join(s.text for s in tokenize(text)) == text` always holds."""
    spans: list[Span] = []
    pos = 0
    for match in _TOKEN_RE.finditer(text):
        if match.start() > pos:
            spans.append(Span(SpanKind.CODE, text[pos : match.start()]))
        kind = next(k for g, k in _GROUP_TO_KIND.items() if match.group(g) is not None)
        spans.append(Span(kind, match.group()))
        pos = match.end()
    if pos < len(text):
        spans.append(Span(SpanKind.CODE, text[pos:]))
    return tuple(spans)


def reassemble(spans: tuple[Span, ...]) -> str:
    return "".join(s.text for s in spans)


def apply_to_code(text: str, fn: Callable[[str], str]) -> str:
    """Apply `fn` only to CODE spans; STRING/CHAR/COMMENT spans pass through
    untouched. This is what a pass calls instead of matching `text` directly."""
    spans = tokenize(text)
    return "".join(fn(s.text) if s.kind == SpanKind.CODE else s.text for s in spans)
