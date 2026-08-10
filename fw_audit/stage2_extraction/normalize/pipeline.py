"""Compose `passes.py`'s individual transforms into the Joern- and
LLM-targeted pipelines, and fold one over one file's text.

Ordering is deliberate:

1. `normalize_line_endings` — a stable base every later regex pass relies on.
2. Warning-comment handling — decided before anything else touches comments.
3. Prelude insertion — the first substantive content change, so every later
   pass's output already reflects the file as it will actually be delivered.
4. Calling-convention stripping, illegal-label fix, halt_baddata rewrite,
   register-var declaration, redundant-cast collapse, dedupe, conflicting-
   decl removal — the substantive rewrites. `declare_register_vars` and
   `collapse_redundant_casts` run latest among these: they're the two most
   likely to interact with text an earlier pass just introduced or removed.
5. `collapse_blank_lines` — last, cleaning up blank lines any earlier
   removal pass left behind. Also the idempotence anchor: everything before
   it should already be a fixed point (see `tests/test_normalizer.py`).

The two pipelines share every pass except the three that must differ by
target (see each pass's own docstring for why): warning-comment handling,
prelude insertion, and the `halt_baddata()` rewrite.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import NamedTuple

from fw_audit.stage2_extraction.normalize import passes
from fw_audit.stage2_extraction.normalize.prelude import include_prelude, inline_prelude
from fw_audit.stage2_extraction.normalize.report import (
    NormalizationResult,
    PassStat,
    sha256_of_text,
)


class NamedPass(NamedTuple):
    name: str
    apply: Callable[[str], str]
    description: str


JOERN_PIPELINE: tuple[NamedPass, ...] = (
    NamedPass(
        "normalize_line_endings",
        passes.normalize_line_endings,
        "CRLF -> LF, trim trailing whitespace",
    ),
    NamedPass(
        "strip_all_ghidra_warnings",
        passes.strip_all_ghidra_warnings,
        "remove every /* WARNING: */ comment",
    ),
    NamedPass(
        "inline_prelude",
        inline_prelude,
        "prepend ghidra_types.h inline (Joern runs no preprocessor)",
    ),
    NamedPass(
        "strip_calling_conventions",
        passes.strip_calling_conventions,
        "drop __fastcall/__stdcall/etc.",
    ),
    NamedPass(
        "fix_illegal_switch_labels",
        passes.fix_illegal_switch_labels,
        "switchD_X::caseD_Y -> switchD_X_caseD_Y",
    ),
    NamedPass(
        "rewrite_halt_baddata",
        passes.rewrite_halt_baddata_for_joern,
        "halt_baddata() -> declared no-op call",
    ),
    NamedPass(
        "declare_register_vars",
        passes.declare_register_vars,
        "synthesize in_*/unaff_*/extraout_* locals",
    ),
    NamedPass(
        "collapse_redundant_casts",
        passes.collapse_redundant_casts,
        "drop exact duplicate adjacent casts",
    ),
    NamedPass(
        "dedupe_type_definitions",
        passes.dedupe_type_definitions,
        "comment out duplicate typedef/struct defs",
    ),
    NamedPass(
        "drop_conflicting_builtin_decls",
        passes.drop_conflicting_builtin_decls,
        "remove known-buggy Ghidra builtin decls",
    ),
    NamedPass(
        "collapse_blank_lines",
        passes.collapse_blank_lines,
        "collapse 3+ blank lines, ensure trailing newline",
    ),
)

LLM_PIPELINE: tuple[NamedPass, ...] = (
    NamedPass(
        "normalize_line_endings",
        passes.normalize_line_endings,
        "CRLF -> LF, trim trailing whitespace",
    ),
    NamedPass(
        "strip_non_semantic_ghidra_warnings",
        passes.strip_non_semantic_ghidra_warnings,
        "remove WARNING comments except semantically-loaded ones",
    ),
    NamedPass("include_prelude", include_prelude, "#include ghidra_types.h"),
    NamedPass(
        "strip_calling_conventions",
        passes.strip_calling_conventions,
        "drop __fastcall/__stdcall/etc.",
    ),
    NamedPass(
        "fix_illegal_switch_labels",
        passes.fix_illegal_switch_labels,
        "switchD_X::caseD_Y -> switchD_X_caseD_Y",
    ),
    NamedPass(
        "rewrite_halt_baddata", passes.rewrite_halt_baddata_for_llm, "halt_baddata() -> comment"
    ),
    NamedPass(
        "declare_register_vars",
        passes.declare_register_vars,
        "synthesize in_*/unaff_*/extraout_* locals",
    ),
    NamedPass(
        "collapse_redundant_casts",
        passes.collapse_redundant_casts,
        "drop exact duplicate adjacent casts",
    ),
    NamedPass(
        "dedupe_type_definitions",
        passes.dedupe_type_definitions,
        "comment out duplicate typedef/struct defs",
    ),
    NamedPass(
        "drop_conflicting_builtin_decls",
        passes.drop_conflicting_builtin_decls,
        "remove known-buggy Ghidra builtin decls",
    ),
    NamedPass(
        "collapse_blank_lines",
        passes.collapse_blank_lines,
        "collapse 3+ blank lines, ensure trailing newline",
    ),
)


def _count_changed_lines(before: str, after: str) -> int:
    """Multiset (not positional) line diff: an insertion/removal shifts
    every following line, so a naive zip would spuriously mark all of them
    changed. `Counter` subtraction avoids that."""
    before_lines = before.split("\n")
    after_lines = after.split("\n")
    if before_lines == after_lines:
        return 0
    diff = Counter(before_lines) - Counter(after_lines)
    return sum(diff.values()) or 1  # at least 1 if anything changed at all


def normalize(text: str, pipeline: tuple[NamedPass, ...]) -> NormalizationResult:
    """Fold `pipeline` over `text`, left to right. No pass mutates; each
    receives the previous pass's output and returns new text."""
    source_sha256 = sha256_of_text(text)
    stats: list[PassStat] = []
    current = text
    for named_pass in pipeline:
        before = current
        current = named_pass.apply(before)
        stats.append(
            PassStat(
                name=named_pass.name,
                replacements=_count_changed_lines(before, current),
                chars_before=len(before),
                chars_after=len(current),
            )
        )
    return NormalizationResult(text=current, stats=tuple(stats), source_sha256=source_sha256)
