"""The per-file audit trail `pipeline.normalize()` produces, serialized to
`normalized/normalization_report.json` alongside the normalized output.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


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
