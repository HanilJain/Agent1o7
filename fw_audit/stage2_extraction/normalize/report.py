"""The per-file audit trail `pipeline.normalize()` produces, serialized to
`normalized/normalization_report.json` alongside the normalized output.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
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


def aggregate_stats(results: Sequence[NormalizationResult]) -> tuple[PassStat, ...]:
    """Sum `PassStat`s across many files (e.g. every per-function LLM
    result for one binary), keyed by pass name, preserving each name's
    first-seen order. `chars_before`/`chars_after` sum too, so the ratio
    stays meaningful as a rough measure of how much of the aggregate text
    a pass touched."""
    order: list[str] = []
    totals: dict[str, list[int]] = {}
    for result in results:
        for stat in result.stats:
            if stat.name not in totals:
                order.append(stat.name)
                totals[stat.name] = [0, 0, 0]
            bucket = totals[stat.name]
            bucket[0] += stat.replacements
            bucket[1] += stat.chars_before
            bucket[2] += stat.chars_after
    return tuple(
        PassStat(
            name=name,
            replacements=totals[name][0],
            chars_before=totals[name][1],
            chars_after=totals[name][2],
        )
        for name in order
    )


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
    llm_function_count: int = 0
    llm_function_totals: tuple[PassStat, ...] = ()

    def to_json_dict(self) -> dict:
        return {
            "bin_id": self.bin_id,
            "context_summary": dict(self.context_summary),
            "joern_whole_c": self.joern_whole_c.to_json_dict() if self.joern_whole_c else None,
            "llm_function_count": self.llm_function_count,
            "llm_function_totals": [s.to_json_dict() for s in self.llm_function_totals],
        }
