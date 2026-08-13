"""Function-only extraction: parse, filter, respan, index.

See `clean/__init__.py`'s module docstring for the real-data finding that
motivates this (a 7,150-line boilerplate head block ahead of every real
function in `sbin/wpasupp.c`) and why tree-sitter over a regex approach.

Moved here from `stage3_analysis.clean` (see that package's former module
docstring in git history) — `text` is now expected to already be repaired
by `normalize.pipeline.build_clean_pipeline()` before it reaches
`extract_functions`, since that pipeline runs first in `extract.py::
_clean_whole_c` and already includes the repair passes this module used to
apply itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fw_audit.common.schemas import ExtractedFunction, ExtractedSource
from fw_audit.stage2_extraction.clean.parser import get_parser

if TYPE_CHECKING:
    import tree_sitter


def extract_functions(text: str, *, bin_id: str) -> ExtractedSource:
    """Parse `text` with `tree-sitter-c` and keep only top-level
    `function_definition` nodes.

    `text` must already be repaired (see this module's docstring) — unlike
    the original `stage3_analysis.clean.extract_functions`, this no longer
    runs its own repair pass, since `normalize.pipeline.
    build_clean_pipeline()` already covers it (and more) upstream in
    `extract.py::_clean_whole_c`.

    Raises `CleanUnavailableError` (via `clean.parser.get_parser`) only if
    `tree-sitter`/`tree-sitter-c` aren't installed — never for malformed or
    unparseable C, which tree-sitter tolerates by design (it's built for
    editor use on incomplete code): a syntax error elsewhere in the file
    still lets correctly-formed functions elsewhere be recognized.
    """
    tree = get_parser().parse(text.encode("utf-8"))

    functions = tuple(
        _extract_function(node)
        for node in tree.root_node.children
        if node.type == "function_definition"
    )

    total_lines = text.count("\n") + 1
    kept_lines = sum(f.end_line - f.start_line + 1 for f in functions)
    dropped_line_count = max(total_lines - kept_lines, 0)

    return ExtractedSource(
        bin_id=bin_id,
        functions=functions,
        total_lines=total_lines,
        dropped_line_count=dropped_line_count,
    )


def respan_for_concatenated_text(
    functions: tuple[ExtractedFunction, ...],
) -> tuple[ExtractedFunction, ...]:
    """Recompute `start_line`/`end_line` for each function as if freshly
    joined by `ExtractedSource.to_text()` (`"\n\n".join(...)`), rather
    than trusting the spans `extract_functions` computed against its INPUT
    text.

    This is load-bearing, not cosmetic: `extract_functions`'s spans are
    relative to the repaired-but-unfiltered raw C it parsed — a document
    that still contains every dropped declaration/prelude line. Once
    written to `cleaned/whole.c` (the CONCATENATED, filtered output),
    those original spans point at the wrong lines entirely. Every entry
    written to `cleaned/functions.json` must use spans computed by this
    function, not the ones `extract_functions` returned.
    """
    respanned: list[ExtractedFunction] = []
    current_line = 1
    last_index = len(functions) - 1
    for i, func in enumerate(functions):
        line_count = func.text.count("\n") + 1
        start = current_line
        end = start + line_count - 1
        respanned.append(func.model_copy(update={"start_line": start, "end_line": end}))
        current_line = end + 1
        if i != last_index:
            current_line += 1  # the blank separator line "\n\n".join(...) inserts
    return tuple(respanned)


def _node_text(node: tree_sitter.Node) -> str:
    """`node.text` is typed `bytes | None` by tree-sitter's stubs — `None`
    only for a node with no associated source, which never applies to a
    node obtained by parsing real text. Decoded once here so callers don't
    each need their own guard, and a failure is explicit rather than an
    unguarded `AttributeError` on `None`. Deliberately a plain `RuntimeError`
    (not `CleanUnavailableError`): that exception specifically means
    "tree-sitter isn't installed" and is caught to degrade gracefully —
    this is a different, genuinely unexpected failure that should
    propagate loudly instead of being silently misattributed."""
    if node.text is None:
        raise RuntimeError(f"tree-sitter node {node.type!r} has no associated source text")
    return node.text.decode("utf-8")


def _extract_function(node: tree_sitter.Node) -> ExtractedFunction:
    text = _node_text(node)
    start_line = node.start_point.row + 1
    # Derived from the extracted text itself, not trusted directly from
    # node.end_point.row, so this is self-consistent regardless of whether
    # tree-sitter's end point is inclusive of a trailing newline.
    end_line = start_line + text.count("\n")
    return ExtractedFunction(
        name=_function_name(node),
        start_line=start_line,
        end_line=end_line,
        text=text,
    )


def _function_name(node: tree_sitter.Node) -> str:
    """Recurse through `declarator` fields (through any `pointer_declarator`
    wrapper) until reaching the innermost `identifier`/`field_identifier`,
    which has no `declarator` field of its own and terminates the walk."""
    declarator = node.child_by_field_name("declarator")
    if declarator is None:
        return _node_text(node)
    return _function_name(declarator)


__all__ = ["extract_functions", "respan_for_concatenated_text"]
