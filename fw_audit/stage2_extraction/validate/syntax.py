"""Layer B: an OPTIONAL `gcc -fsyntax-only` pass, run only when a compiler
happens to be on PATH. This is the one module in `stage2_extraction.
validate` allowed to import `subprocess`/`shutil` — kept separate from
`structural.py` (which must stay dependency-free) for exactly that reason.

No Docker image this pipeline builds (`Dockerfile.ghidra`, `Dockerfile.
joern`, `Dockerfile.verification`) ships a C compiler, so in production
this layer is disabled by default (`Settings.stage2_validation_gcc`) and,
even when enabled, degrades to "not available" rather than failing — never
a hard dependency of a real run completing. See `Settings.stage2_
validation_gcc`'s docstring for the full policy.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from fw_audit.stage2_extraction.validate.result import Severity, ValidationIssue, ValidationResult

# gcc's diagnostic line is `<file>:<line>:<col>: error|warning: <msg>`.
# `[^:]+` for `<file>` is WRONG on Windows: a Windows absolute path is
# itself `C:\...`, so a naive negated-colon class stops at the drive
# letter's own colon, leaving `<line>` to try (and fail) to parse the rest
# of the path as digits (confirmed: on Windows this regex silently matched
# nothing, producing zero issues despite gcc reporting real errors).
# `.+?` (non-greedy, DOTALL-free so `.` still excludes `\n`) is safe here
# because the compiler is ALWAYS invoked against exactly ONE file this
# module itself wrote (`candidate` below) — there's no second `:`-bearing
# path segment in the line for it to stop at too early.
_GCC_DIAGNOSTIC_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+):\s*(?P<sev>error|warning):\s*(?P<msg>.*)$"
)

# Substring -> defect class, checked in order (first match wins). Mirrors
# `structural.py`'s own check ids where the same defect can fire from
# either layer, so a report reader sees one coherent classification
# regardless of which layer caught it first.
_MESSAGE_TO_DEFECT_CLASS: tuple[tuple[str, int], ...] = (
    ("missing terminating", 3),
    ("expected declaration or statement", 3),
    ("before '<' token", 3),
    ("conflicting types for 'size_t'", 4),
    ("conflicting types for 'ssize_t'", 4),
    ("conflicting types for 'time_t'", 4),
    ("conflicting types for 'intptr_t'", 4),
    ("conflicting types for '__gnuc_va_list'", 4),
    ("conflicting types", 2),
    ("redeclared as different kind of symbol", 2),
    ("invalid use of void expression", 5),
    ("undeclared (first use", 6),
    ("implicit declaration of function", 6),
    ("invalid suffix", 3),
    ("expected identifier", 1),
)


def _classify(message: str) -> int:
    lowered = message.lower()
    for substring, defect_class in _MESSAGE_TO_DEFECT_CLASS:
        if substring.lower() in lowered:
            return defect_class
    return 0


def _parse_diagnostics(stderr: str) -> tuple[ValidationIssue, ...]:
    issues = []
    for line in stderr.split("\n"):
        match = _GCC_DIAGNOSTIC_RE.match(line)
        if not match:
            continue
        severity = Severity.ERROR if match.group("sev") == "error" else Severity.WARNING
        message = match.group("msg")
        issues.append(
            ValidationIssue(
                check="gcc_diagnostic",
                defect_class=_classify(message),
                severity=severity,
                message=message,
                line=int(match.group("line")),
                detail=line.strip()[:200],
            )
        )
    return tuple(issues)


def run(
    text: str,
    *,
    target: str,
    compiler: str = "gcc",
    timeout_seconds: int = 60,
) -> ValidationResult:
    """Run `<compiler> -fsyntax-only -std=gnu17 -w -fmax-errors=100000`
    over `text` and return a `ValidationResult`. `tool_available=False`
    (never an exception, never a failed run) when `compiler` isn't on
    PATH — the correct degradation for a layer that is opt-in by design.

    `text` is written to a throwaway `tempfile.TemporaryDirectory()`, NEVER
    into any binary's `raw/`/`normalized/` tree — this module has no
    business writing pipeline artifacts, only a scratch file for the
    compiler to read.

    Flags/args match `tests/test_normalizer_gcc.py`'s own invocation:
    `-std=gnu17` (not gnu99 — `_short_aliases`'s `code` typedef branches on
    `__STDC_VERSION__ >= 202311L`, which gnu17 correctly reports False for)
    and `-w` (suppress every WARNING; only ERRORs are load-bearing for a
    parse-health check, and `_check_void_value_use`/`_check_missing_
    prototype`'s WARNING-severity Layer A counterparts already cover the
    two defect classes gcc would otherwise warn, not error, about)."""
    checked_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    resolved = shutil.which(compiler)
    if resolved is None:
        return ValidationResult(
            target=target,
            layer="gcc",
            checked_sha256=checked_sha256,
            tool_available=False,
        )

    with tempfile.TemporaryDirectory(prefix="fwaudit-stage2-validate-") as tmp:
        candidate = Path(tmp) / "whole.c"
        candidate.write_text(text, encoding="utf-8")
        try:
            proc = subprocess.run(
                [
                    resolved,
                    "-fsyntax-only",
                    "-std=gnu17",
                    "-w",
                    "-fmax-errors=100000",
                    str(candidate),
                ],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ValidationResult(
                target=target,
                layer="gcc",
                checked_sha256=checked_sha256,
                tool_available=True,
                tool_exit_code=None,
                issues=(
                    ValidationIssue(
                        check="gcc_diagnostic",
                        defect_class=0,
                        severity=Severity.ERROR,
                        message=f"gcc timed out after {timeout_seconds}s",
                    ),
                ),
            )

    return ValidationResult(
        target=target,
        layer="gcc",
        checked_sha256=checked_sha256,
        tool_available=True,
        tool_exit_code=proc.returncode,
        issues=_parse_diagnostics(proc.stderr),
    )


__all__ = ["run"]
