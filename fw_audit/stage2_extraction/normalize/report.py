"""The per-file audit trail `pipeline.normalize()` produces, serialized to
`normalized/normalization_report.json` alongside the normalized output.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field


def sha256_of_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PassStat:
    """One pipeline pass's effect on one file.

    `replacements` is an approximate count of changed lines, not an exact
    regex-match count — passes stay plain `(str) -> str` functions (see
    `passes.py`'s module docstring), so an exact per-substitution count
    isn't observable without instrumenting every pass individually; a
    line-level diff is a cheap, honest proxy that's still useful for
    spotting a pass that unexpectedly touched far more (or less) than
    expected."""

    name: str
    replacements: int
    chars_before: int
    chars_after: int

    def to_json_dict(self) -> dict:
        return {
            "name": self.name,
            "replacements": self.replacements,
            "chars_before": self.chars_before,
            "chars_after": self.chars_after,
        }


@dataclass(frozen=True)
class NormalizationResult:
    """The outcome of running one pipeline over one file's raw text."""

    text: str
    stats: tuple[PassStat, ...]
    source_sha256: str
    """sha256 of the RAW (pre-normalization) input text — ties this result
    back to the exact `raw/` artifact it was derived from."""

    def to_json_dict(self) -> dict:
        return {
            "source_sha256": self.source_sha256,
            "result_sha256": sha256_of_text(self.text),
            "stats": [s.to_json_dict() for s in self.stats],
        }


@dataclass(frozen=True)
class NormalizationReport:
    """One binary's full normalization audit trail — the evidence that
    cleaning actually happened, since without this the only way to check
    is to grep the output by hand. Written to
    `layout.normalization_report_path(bin_dir)` by
    `extract.py::_normalize_all`, non-fatally (a write failure is a
    warning, same discipline as the decompiled-tree mirror)."""

    bin_id: str
    context_summary: Mapping[str, int] = field(default_factory=dict)
    """`{"functions": n, "thunks": n, "externals": n}` — the only way to
    tell from this artifact alone whether the context-bound passes ran
    against real Ghidra metadata or degraded to `EMPTY_CONTEXT` (e.g.
    because `metadata.json` was missing or failed to parse)."""
    joern_whole_c: NormalizationResult | None = None
    cleaned_whole_c: NormalizationResult | None = None
    """The `build_clean_pipeline()` pass's effect on `raw/decompiled/
    whole.c`, BEFORE `clean.extract.extract_functions`'s function-only
    filter runs on top of it — `.text` here is an intermediate, not what
    ends up in `cleaned/whole.c` (which is `ExtractedSource.to_text()`,
    the filtered/concatenated result). `None` if cleaning didn't run for
    this binary (see `DecompiledBinary.warnings`)."""

    def to_json_dict(self) -> dict:
        return {
            "bin_id": self.bin_id,
            "context_summary": dict(self.context_summary),
            "joern_whole_c": self.joern_whole_c.to_json_dict() if self.joern_whole_c else None,
            "cleaned_whole_c": self.cleaned_whole_c.to_json_dict()
            if self.cleaned_whole_c
            else None,
        }
