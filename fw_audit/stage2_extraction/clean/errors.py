"""The one exception this package's cleaning step can raise."""

from __future__ import annotations


class CleanUnavailableError(RuntimeError):
    """`tree-sitter`/`tree-sitter-c` (the `stage2` extra) aren't installed.

    NOT `Stage2InputError`: that exception is reserved for load-phase
    failures that abort the whole Stage 2 run (`stage1_io`'s docstring).
    A missing optional dependency for one normalization target is a
    per-binary, best-effort concern — `extract.py::_clean_whole_c` catches
    this and records a warning, exactly like a mirror-write failure or a
    normalization-report write failure elsewhere in that module. The Joern
    artifact and `stage2_summary.json` are written regardless.
    """
