"""Per-binary metadata carried into the two context-dependent passes
(`passes.replace_thunk_bodies`, `passes.dedupe_global_declarations`)
without breaking the rest of the pipeline's `(str) -> str` purity contract.

`BinaryContext` is frozen and built entirely from `frozenset`s, so binding
it into a pass with `functools.partial` (see `pipeline.py`) yields a
genuinely pure closure — no mutable shared state, no I/O, nothing that
weakens the "every pass is `Callable[[str], str]`" guarantee the rest of
this package relies on.

Deliberately duck-typed via `FunctionFacts` rather than importing
`fw_audit.common.schemas.GhidraFunction` directly: this package must never
import anything outside itself plus the standard library (see
`normalize/__init__.py`), and `GhidraFunction` already structurally
satisfies this Protocol with no adapter needed.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol


class FunctionFacts(Protocol):
    """The minimum shape `build_context` needs from a function record."""

    name: str
    is_thunk: bool
    is_external: bool


@dataclass(frozen=True)
class BinaryContext:
    """Everything the context-bound passes know about one binary, derived
    from Ghidra's Program DB (`GhidraFunction` records) rather than from
    the decompiled C text itself."""

    thunk_names: frozenset[str] = field(default_factory=frozenset)
    external_names: frozenset[str] = field(default_factory=frozenset)
    known_function_names: frozenset[str] = field(default_factory=frozenset)

    def may_stub(self, name: str) -> bool:
        """True unless metadata POSITIVELY contradicts treating `name` as a
        thunk/external forwarding stub.

        `metadata.json`'s function list is capped at
        `Settings.ghidra_max_functions` (2000 by default) while the whole-
        program C export is not — on a large binary, most function names
        simply never appear in `known_function_names` at all. Silence about
        a name therefore means "metadata has no opinion" (truncation), not
        "this is definitely not a thunk" — so an unknown name still passes.
        Only a record that explicitly said `is_thunk=False` for this exact
        name is a real veto, and that can only happen by NOT being in
        `thunk_names | external_names` while being in
        `known_function_names`.
        """
        if name in self.thunk_names or name in self.external_names:
            return True
        return name not in self.known_function_names

    def is_function_symbol(self, name: str) -> bool:
        """True if metadata confirms `name` is a function, distinct from a
        data symbol. Used to catch Ghidra's occasional
        `undefined FUN_00401234;` — a function entry point mis-emitted as a
        one-byte data declaration, which conflicts with its own real
        definition elsewhere in the same file."""
        return name in self.known_function_names


EMPTY_CONTEXT = BinaryContext()
"""The context to use when no metadata is available (missing/malformed
`metadata.json`, or a caller with nothing to offer). `may_stub` returns
`True` unconditionally in this case — every context-bound pass then relies
solely on its own textual safety checks, which is why those checks (see
`passes.replace_thunk_bodies`) are designed to stand on their own."""


def build_context(functions: Iterable[FunctionFacts]) -> BinaryContext:
    """Build a `BinaryContext` from a binary's function records (typically
    `DecompiledBinary.functions`). Tolerates records with default/missing
    `is_thunk`/`is_external` — those simply don't join the respective set."""
    thunk_names: set[str] = set()
    external_names: set[str] = set()
    known_function_names: set[str] = set()
    for func in functions:
        known_function_names.add(func.name)
        if func.is_thunk:
            thunk_names.add(func.name)
        if func.is_external:
            external_names.add(func.name)
    return BinaryContext(
        thunk_names=frozenset(thunk_names),
        external_names=frozenset(external_names),
        known_function_names=frozenset(known_function_names),
    )


__all__ = ["EMPTY_CONTEXT", "BinaryContext", "FunctionFacts", "build_context"]
