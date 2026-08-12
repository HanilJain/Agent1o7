"""Function-only extraction: repair, parse, filter.

See `clean/__init__.py`'s module docstring for the real-data finding that
motivates this (a 7,150-line boilerplate head block ahead of every real
function in `sbin/wpasupp.c`) and why tree-sitter over a regex approach.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fw_audit.stage2_extraction.normalize import passes
from fw_audit.stage2_extraction.normalize.context import BinaryContext
from fw_audit.stage3_analysis.clean.parser import get_parser
from fw_audit.stage3_analysis.models import ExtractedFunction, ExtractedSource

if TYPE_CHECKING:
    import tree_sitter


def extract_functions(text: str, *, bin_id: str, context: BinaryContext) -> ExtractedSource:
    """Repair `text` (reusing 3 of Stage 2's repair passes), parse it with
    `tree-sitter-c`, and keep only top-level `function_definition` nodes.

    Raises `Stage3InputError` (via `clean.parser.get_parser`) only if
    `tree-sitter`/`tree-sitter-c` aren't installed — never for malformed or
    unparseable C, which tree-sitter tolerates by design (it's built for
    editor use on incomplete code): a syntax error elsewhere in the file
    still lets correctly-formed functions elsewhere be recognized.
    """
    repaired = _repair(text, context)
    tree = get_parser().parse(repaired.encode("utf-8"))

    functions = tuple(
        _extract_function(node)
        for node in tree.root_node.children
        if node.type == "function_definition"
    )

    total_lines = repaired.count("\n") + 1
    kept_lines = sum(f.end_line - f.start_line + 1 for f in functions)
    dropped_line_count = max(total_lines - kept_lines, 0)

    return ExtractedSource(
        bin_id=bin_id,
        functions=functions,
        total_lines=total_lines,
        dropped_line_count=dropped_line_count,
    )


def _repair(text: str, context: BinaryContext) -> str:
    """The 3 of Stage 2's original 7 Group-A repair passes still relevant
    once every top-level declaration is discarded wholesale by the
    function-only filter below.

    `replace_thunk_bodies` is NOT optional to keep: a self-forwarding thunk
    stub (`int foo(int a){ return foo(a); }`, still present verbatim in
    stale mirror files) is syntactically indistinguishable from a real
    function to a structural `function_definition` filter — both have a
    body. Only this pass's semantic check (`_is_self_forwarding_stub`) can
    tell the difference, and it does so by rewriting the stub into an
    `extern` declaration — no longer a `function_definition` node — so the
    filter below excludes it correctly *because* this pass ran first.

    `declare_register_vars` stays because it adds a synthetic *local*
    declaration inside a kept function body for Ghidra's undeclared
    `in_*`/`unaff_*`/`extraout_*` identifiers, so an extracted function read
    in isolation (no file-scope context around it anymore) stays
    self-consistent instead of referencing a mystery undeclared name.

    `collapse_blank_lines` is purely cosmetic token-saving.

    The other 4 passes from Stage 2's Group A (`fix_illegal_array_
    declarations`, `dedupe_type_definitions`, `dedupe_global_declarations`,
    `drop_conflicting_builtin_decls`) are deliberately NOT reused here —
    every one of them repairs a top-level declaration, and declarations are
    discarded wholesale below regardless of whether they were valid.
    Running them would be correct but wasted work with zero effect on the
    final output.
    """
    text = passes.replace_thunk_bodies(context, text)
    text = passes.declare_register_vars(text)
    text = passes.collapse_blank_lines(text)
    return text


def _node_text(node: tree_sitter.Node) -> str:
    """`node.text` is typed `bytes | None` by tree-sitter's stubs — `None`
    only for a node with no associated source, which never applies to a
    node obtained by parsing real text. Decoded once here so callers don't
    each need their own guard, and a failure is explicit rather than an
    unguarded `AttributeError` on `None`. Deliberately a plain `RuntimeError`
    (not `Stage3InputError`): `ingest.py`'s `--debug` wiring specifically
    catches `Stage3InputError` to mean "tree-sitter isn't installed" and
    degrade gracefully — this is a different, genuinely unexpected failure
    that should propagate loudly instead of being silently misattributed."""
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


__all__ = ["extract_functions"]
