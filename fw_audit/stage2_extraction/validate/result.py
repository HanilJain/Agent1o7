"""Typed result of one validation pass over a normalized C file — pure
dataclasses, no imports beyond the standard library. Kept as a module of
its own (rather than folded into `structural.py`/`syntax.py`) so both of
those, and any future caller, can share one shape without a circular
import.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class ValidationIssue:
    """One concrete problem found in one file.

    `defect_class` ties this back to the Stage 2 Normalization Hardening
    Spec's numbering (1-7) where applicable; `0` means "not one of the
    seven" — a genuine defect this validation pass caught that isn't
    covered by any of the seven passes (e.g. `brace_balance`,
    `halt_baddata`, or a Layer B gcc diagnostic this module's substring
    table doesn't recognize)."""

    check: str
    """Stable machine id, e.g. "span_sync", "illegal_identifier" — the
    same id `structural.py`'s per-check functions and `syntax.py`'s
    substring-classification table use, so a check's id never depends on
    its (freely rephraseable) human-readable `message`."""
    defect_class: int
    severity: Severity
    message: str
    line: int | None = None
    end_line: int | None = None
    detail: str = ""
    """The offending text, truncated — enough to grep for in the file
    without inflating `normalization_report.json` with the whole line."""

    def to_json_dict(self) -> dict:
        return {
            "check": self.check,
            "defect_class": self.defect_class,
            "severity": self.severity.value,
            "message": self.message,
            "line": self.line,
            "end_line": self.end_line,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ValidationResult:
    """The outcome of one validation LAYER (structural or gcc) run against
    one target artifact. `_normalize_whole_c` (see `extract.py`) produces
    one of these per layer per binary; both are carried in
    `NormalizationReport.validation`."""

    target: str
    """Which artifact this checked — "joern_whole_c" today; kept as a
    free-form string rather than an enum so a future target doesn't need
    a schema change here."""
    layer: str
    """"structural" (Layer A, `structural.py`) or "gcc" (Layer B,
    `syntax.py`)."""
    checked_sha256: str
    """sha256 of EXACTLY the text this result was computed against — must
    equal `NormalizationResult.to_json_dict()["result_sha256"]`
    (`report.py`) for the same run, so a stale validation result can never
    silently describe different bytes than the ones actually written to
    disk."""
    issues: tuple[ValidationIssue, ...] = field(default_factory=tuple)
    tool_available: bool = True
    """False only for Layer B when the configured compiler isn't on PATH —
    the correct, non-error degradation (see `syntax.py`); always True for
    Layer A, which has no external dependency to be unavailable."""
    tool_exit_code: int | None = None
    """Layer B's compiler exit code, `None` for Layer A or when
    `tool_available` is False."""

    @property
    def errors(self) -> tuple[ValidationIssue, ...]:
        return tuple(i for i in self.issues if i.severity is Severity.ERROR)

    @property
    def ok(self) -> bool:
        """True iff nothing at ERROR severity was found. A WARNING-only
        result is still `ok` — see `policy.apply_policy` for how severity
        maps to the configured fail policy."""
        return not self.errors

    def to_json_dict(self) -> dict:
        return {
            "target": self.target,
            "layer": self.layer,
            "checked_sha256": self.checked_sha256,
            "tool_available": self.tool_available,
            "tool_exit_code": self.tool_exit_code,
            "issue_count": len(self.issues),
            "error_count": len(self.errors),
            "issues": [i.to_json_dict() for i in self.issues],
        }


__all__ = ["Severity", "ValidationIssue", "ValidationResult"]
