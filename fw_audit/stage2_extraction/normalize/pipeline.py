"""Compose `passes.py`'s individual transforms into the Joern- and
LLM-targeted pipelines, and fold one over one file's text.

Ordering is deliberate:

1. `normalize_line_endings` — a stable base every later regex pass relies on.
2. Warning-comment handling — decided before anything else touches comments.
3. Prelude insertion — the first substantive content change, so every later
   pass's output already reflects the file as it will actually be delivered.
4. Calling-convention stripping, illegal-array-declaration fix, illegal-
   label fix, halt_baddata rewrite — syntax repairs that must land before
   anything walks function bodies.
5. `replace_thunk_bodies` — deletes/declares thunk stubs BEFORE
   `declare_register_vars` walks bodies, so that pass never has to look
   inside a body that's about to disappear, and so its text edits can never
   collide with the thunk pass's edits to the same span.
6. `declare_register_vars`, `collapse_redundant_casts`, `dedupe_type_
   definitions`, `dedupe_global_declarations`, `drop_conflicting_builtin_
   decls` — the remaining substantive rewrites. `dedupe_global_declarations`
   runs after `fix_illegal_array_declarations` (step 4), so it can already
   see a repaired `TYPE NAME[N];` declaration as one declaring `NAME` —
   before the fix, the illegal `TYPE[N] NAME;` form wouldn't be recognized
   as a declaration of `NAME` at all.
7. `collapse_blank_lines` — last, cleaning up blank lines any earlier
   removal pass left behind. Also the idempotence anchor: everything before
   it should already be a fixed point (see `tests/test_normalizer.py`).

The two pipelines share every pass except the three that must differ by
target (see each pass's own docstring for why): warning-comment handling,
prelude insertion, and the `halt_baddata()` rewrite.

`replace_thunk_bodies` and `dedupe_global_declarations` additionally need a
per-binary `normalize.context.BinaryContext` — see `build_joern_pipeline`/
`build_llm_pipeline` below for how that's threaded in without breaking the
"every pass is `Callable[[str], str]`" contract every other pass relies on.
"""

from __future__ import annotations

import functools
from collections import Counter
from collections.abc import Callable
from typing import NamedTuple

from fw_audit.stage2_extraction.normalize import passes
from fw_audit.stage2_extraction.normalize.context import EMPTY_CONTEXT, BinaryContext
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


def _head_passes(warnings_pass: NamedPass, prelude_pass: NamedPass) -> tuple[NamedPass, ...]:
    """Steps 1-4 above: line endings, warning comments, prelude insertion,
    then the syntax repairs that must land before anything walks function
    bodies. Shared verbatim by both pipelines except the two passed in."""
    return (
        NamedPass(
            "normalize_line_endings",
            passes.normalize_line_endings,
            "CRLF -> LF, trim trailing whitespace",
        ),
        warnings_pass,
        prelude_pass,
        NamedPass(
            "strip_calling_conventions",
            passes.strip_calling_conventions,
            "drop __fastcall/__stdcall/etc.",
        ),
        NamedPass(
            "fix_illegal_array_declarations",
            passes.fix_illegal_array_declarations,
            "TYPE[N] name; -> TYPE name[N];",
        ),
        NamedPass(
            "fix_illegal_switch_labels",
            passes.fix_illegal_switch_labels,
            "switchD_X::caseD_Y -> switchD_X_caseD_Y",
        ),
    )


def _body_passes(context: BinaryContext, halt_pass: NamedPass) -> tuple[NamedPass, ...]:
    """Steps 5-6 above: everything that inspects or rewrites a function
    body, or a context-scoped set of declarations. `halt_pass` is the only
    target-specific pass in this group."""
    return (
        halt_pass,
        NamedPass(
            "replace_thunk_bodies",
            functools.partial(passes.replace_thunk_bodies, context),
            "self-forwarding Ghidra thunk/PLT stub -> extern declaration",
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
            "dedupe_global_declarations",
            functools.partial(passes.dedupe_global_declarations, context),
            "comment out duplicate/function-shadowing global var decls",
        ),
        NamedPass(
            "drop_conflicting_builtin_decls",
            passes.drop_conflicting_builtin_decls,
            "remove known-buggy Ghidra builtin decls",
        ),
    )


def _tail_passes() -> tuple[NamedPass, ...]:
    """Step 7 above: the idempotence anchor."""
    return (
        NamedPass(
            "collapse_blank_lines",
            passes.collapse_blank_lines,
            "collapse 3+ blank lines, ensure trailing newline",
        ),
    )


def _build_pipeline(
    *,
    warnings_pass: NamedPass,
    prelude_pass: NamedPass,
    halt_pass: NamedPass,
    context: BinaryContext,
) -> tuple[NamedPass, ...]:
    return (
        _head_passes(warnings_pass, prelude_pass)
        + _body_passes(context, halt_pass)
        + _tail_passes()
    )


def build_joern_pipeline(context: BinaryContext = EMPTY_CONTEXT) -> tuple[NamedPass, ...]:
    """The Joern-targeted pipeline, bound to `context` (a binary's thunk/
    external/known-function-name sets, from `normalize.context.build_
    context`). Defaults to `EMPTY_CONTEXT` — the correct degradation when
    `metadata.json` is absent or malformed, since every context-bound pass
    is designed to still do useful, safe work with no metadata at all."""
    return _build_pipeline(
        warnings_pass=NamedPass(
            "strip_all_ghidra_warnings",
            passes.strip_all_ghidra_warnings,
            "remove every Ghidra WARNING comment",
        ),
        prelude_pass=NamedPass(
            "inline_prelude",
            inline_prelude,
            "prepend ghidra_types.h inline (Joern runs no preprocessor)",
        ),
        halt_pass=NamedPass(
            "rewrite_halt_baddata",
            passes.rewrite_halt_baddata_for_joern,
            "halt_baddata() -> declared no-op call",
        ),
        context=context,
    )


def build_llm_pipeline(context: BinaryContext = EMPTY_CONTEXT) -> tuple[NamedPass, ...]:
    """The LLM-targeted pipeline — see `build_joern_pipeline` for the
    `context` default's rationale."""
    return _build_pipeline(
        warnings_pass=NamedPass(
            "strip_non_semantic_ghidra_warnings",
            passes.strip_non_semantic_ghidra_warnings,
            "remove WARNING comments except semantically-loaded ones",
        ),
        prelude_pass=NamedPass("include_prelude", include_prelude, "#include ghidra_types.h"),
        halt_pass=NamedPass(
            "rewrite_halt_baddata", passes.rewrite_halt_baddata_for_llm, "halt_baddata() -> comment"
        ),
        context=context,
    )


#: The no-metadata pipelines — kept as module-level constants (rather than
#: requiring every caller to invoke the factory) because they have a real
#: meaning of their own: "the pipeline to run when there is no
#: `BinaryContext` to give it". Every existing caller/test that references
#: these by name keeps working unchanged; `test_pipeline.py` asserts they
#: can never silently drift from `build_*_pipeline()`'s own default.
JOERN_PIPELINE: tuple[NamedPass, ...] = build_joern_pipeline()
LLM_PIPELINE: tuple[NamedPass, ...] = build_llm_pipeline()


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
