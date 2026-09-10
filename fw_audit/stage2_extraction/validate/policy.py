"""Turn one or more `ValidationResult`s plus a configured policy string
into a single fail/don't-fail decision — pure, no I/O, no imports beyond
the standard library and `result.py`.

Deliberately its own module rather than a method on `ValidationResult`
(which stays a plain data holder) or logic inlined at the `extract.py`
call site — this is the one place the three-way "off"/"warn"/"fail"
semantics `Settings.stage2_validation` documents are actually implemented,
so a future policy value only needs a change here.
"""

from __future__ import annotations

from collections.abc import Sequence

from fw_audit.stage2_extraction.validate.result import ValidationResult

_VALID_POLICIES = ("off", "warn", "fail")


def apply_policy(
    results: Sequence[ValidationResult], policy: str
) -> tuple[bool, list[str]]:
    """Returns `(should_fail_binary, messages)`.

    `policy == "off"`: always `(False, [])` — validation results exist
    (already computed by the caller) but are never consulted for pass/fail.

    `policy == "warn"` (default): `should_fail_binary` is always `False`;
    `messages` is one capped, aggregated line per result that has at least
    one issue (never one line per issue — a 400-issue file must not drown
    `Stage2Summary.warnings`), naming the most frequent check ids.

    `policy == "fail"`: `should_fail_binary` is `True` iff any result has
    at least one ERROR-severity issue (`ValidationResult.errors`) —
    WARNING-only results never fail a binary under any policy, since every
    WARNING-severity check (`void_value_use`, `missing_prototype`) is
    already a known, evidence-driven residual outside the seven defect
    classes' hard-parse-error guarantee (see those checks' own
    docstrings), not a Joern-CDT parse failure."""
    if policy not in _VALID_POLICIES:
        raise ValueError(
            f"unknown stage2 validation policy {policy!r}, expected one of {_VALID_POLICIES}"
        )

    if policy == "off":
        return False, []

    messages = [_summarize(result) for result in results if result.issues]
    if policy == "warn":
        return False, messages

    should_fail = any(result.errors for result in results)
    return should_fail, messages


def _summarize(result: ValidationResult, *, top_n: int = 3) -> str:
    """One capped line: `<layer>: N error(s), M warning(s) [check x1, ...]`."""
    error_count = len(result.errors)
    warning_count = len(result.issues) - error_count
    counts: dict[str, int] = {}
    for issue in result.issues:
        counts[issue.check] = counts.get(issue.check, 0) + 1
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]
    detail = ", ".join(f"{check} x{count}" for check, count in top)
    return (
        f"validation ({result.layer}): {error_count} error(s), "
        f"{warning_count} warning(s) [{detail}]"
    )


__all__ = ["apply_policy"]
