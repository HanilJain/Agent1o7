"""Compose `passes.py`'s individual transforms into the Joern-targeted
pipeline, and fold it over one file's text.

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

`build_joern_pipeline` takes the three passes that are inherently
target-specific (warning-comment handling, prelude insertion, and the
`halt_baddata()` rewrite) as parameters rather than hardcoding them, so a
second target-specific pipeline can reuse `_head_passes`/`_body_passes`/
`_tail_passes` without duplicating the shared pass list — see
`build_clean_pipeline` below, the LLM-facing sibling that does exactly
this.

`replace_thunk_bodies` and `dedupe_global_declarations` additionally need a
per-binary `normalize.context.BinaryContext` — see `build_joern_pipeline`
below for how that's threaded in without breaking the "every pass is
`Callable[[str], str]`" contract every other pass relies on.
"""

from __future__ import annotations

import functools
from collections import Counter
from collections.abc import Callable
from typing import NamedTuple

from fw_audit.stage2_extraction.normalize import passes
from fw_audit.stage2_extraction.normalize.context import EMPTY_CONTEXT, BinaryContext
from fw_audit.stage2_extraction.normalize.prelude import inline_prelude
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


#: The no-metadata pipeline — kept as a module-level constant (rather than
#: requiring every caller to invoke the factory) because it has a real
#: meaning of its own: "the pipeline to run when there is no
#: `BinaryContext` to give it". Every existing caller/test that references
#: it by name keeps working unchanged; `test_pipeline.py` asserts it can
#: never silently drift from `build_joern_pipeline()`'s own default.
JOERN_PIPELINE: tuple[NamedPass, ...] = build_joern_pipeline()


_NOOP_PRELUDE_PASS = NamedPass(
    "noop_prelude",
    lambda text: text,
    "no-op: the LLM/cleaning target discards the prelude wholesale once "
    "clean.extract's function-only filter runs, so inlining ghidra_types.h "
    "here would only spend tokens on text that never survives",
)

_NOOP_HALT_PASS = NamedPass(
    "noop_halt_baddata",
    lambda text: text,
    "no-op: rewrite_halt_baddata_for_joern exists only to satisfy Joern's "
    "CDT-based C frontend, which doesn't accept halt_baddata(); an LLM "
    "reads the original Ghidra intrinsic call just fine",
)


def build_clean_pipeline(context: BinaryContext = EMPTY_CONTEXT) -> tuple[NamedPass, ...]:
    """The LLM/cleaning-targeted pipeline, bound to `context` exactly like
    `build_joern_pipeline`. Reuses `_head_passes`/`_body_passes`/
    `_tail_passes` verbatim (see this module's docstring, lines 28-33,
    which anticipated exactly this pipeline) with three target-specific
    substitutions:

    * `warnings_pass` — same as Joern's (`strip_all_ghidra_warnings`);
      warning comments are noise for an LLM reader too.
    * `prelude_pass` — a no-op: `clean.extract.extract_functions`'s
      function-only filter discards every declaration anyway, so
      inlining `ghidra_types.h` here would burn tokens on text that
      never survives.
    * `halt_pass` — a no-op: `rewrite_halt_baddata_for_joern` exists only
      to make Joern's CDT-based C frontend accept `halt_baddata()`; an
      LLM has no such requirement.

    This runs BEFORE `stage2_extraction.clean.extract.extract_functions`
    (see `extract.py::_clean_whole_c`) — unlike the Joern pipeline, whose
    output is delivered as-is, this pipeline's output is an intermediate
    that still contains every declaration `extract_functions` will filter
    out; that's expected and does not need `EMIT_TYPE_DEFINITIONS`-style
    tuning, since none of it survives into `cleaned/whole.c`.
    """
    return _build_pipeline(
        warnings_pass=NamedPass(
            "strip_all_ghidra_warnings",
            passes.strip_all_ghidra_warnings,
            "remove every Ghidra WARNING comment",
        ),
        prelude_pass=_NOOP_PRELUDE_PASS,
        halt_pass=_NOOP_HALT_PASS,
        context=context,
    )


#: Kept for the same reason `JOERN_PIPELINE` is: a real meaning of its own
#: ("the cleaning pipeline to run when there is no `BinaryContext`"), and
#: so `test_pipeline_constants_match_factory_defaults` can guard it against
#: drifting from `build_clean_pipeline()`'s own default the same way.
CLEAN_PIPELINE: tuple[NamedPass, ...] = build_clean_pipeline()


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
