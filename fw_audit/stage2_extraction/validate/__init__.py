"""Mandatory-by-default, dependency-free syntax/structure validation for
Stage 2's normalized Joern-target output — the hard pipeline gate the
Stage 2 Normalization Hardening Spec calls for, so a broken `whole.c` can
never again silently reach `joern-parse` and either fail the CPG build or
(worse) build one missing methods, with no error anywhere.

Deliberately a SEPARATE top-level package from `normalize/`, not a
sub-package of it — `normalize/` carries its own hard import-purity
guarantee (`tests/test_normalizer.py::test_normalize_import_purity_...`:
transitively imports NEITHER `subprocess` NOR `fw_audit.executors`), and
`validate/` needs `subprocess` for its optional gcc layer (`syntax.py`).
Keeping them siblings rather than parent/child is what keeps that
guarantee legible without a special-cased exception.

Two independent layers, always run together via `validate_text`/
`validate_file`:

* Layer A (`structural.py`) — always on, stdlib + `normalize.spans`/
  `normalize.structure` only. No Docker, no external tool, no network.
  Runs identically on every platform this pipeline's CI or a developer's
  own machine happens to be.
* Layer B (`syntax.py`) — optional, `gcc -fsyntax-only` when a compiler
  happens to be on PATH (`Settings.stage2_validation_gcc`). Never a hard
  dependency: no Docker image this pipeline builds ships a compiler, so in
  production this layer is normally a no-op reporting `tool_available=
  False`, not an error.

`fw_audit.stage2_extraction.extract` wires this in immediately after the
Joern-target `whole.c` is written (see `extract.py::_normalize_whole_c`)
and applies `Settings.stage2_validation`'s policy (`policy.py`) — default
"warn": record every issue, keep the artifact, never sink an otherwise-
successful binary over this alone.

Also runnable as a standalone CLI, independent of the rest of the
pipeline — no Docker, no `fw-extract` run required, only the file on disk:

    python -m fw_audit.stage2_extraction.validate path/to/whole.c
    python -m fw_audit.stage2_extraction.validate --gcc path/to/whole.c

Exits 0 if the structural (and, with `--gcc`, gcc) layer found zero
ERROR-severity issues; 1 otherwise. This Python module IS the real gate —
`stage2_extraction/validate.sh` (a sibling of this package, not inside it)
is a thin `exec`-wrapper around the `python -m` command above, kept for a
CI system that only knows how to invoke a shell script. It deliberately
does NOT reimplement any check in bash/grep: the Spec's original draft was
a self-contained `grep -oP`-based script, but that syntax does not run
unmodified on this project's own Windows development environment
(confirmed this session: Git Bash/MSYS `grep` refuses `-P` outright), and
hand-maintaining the same seven defect-class checks in two languages risks
them silently drifting apart — so there is exactly one implementation,
callable identically everywhere Python itself runs, and the shell script
is a pass-through to it.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from fw_audit.stage2_extraction.validate import structural, syntax
from fw_audit.stage2_extraction.validate.policy import apply_policy
from fw_audit.stage2_extraction.validate.result import Severity, ValidationIssue, ValidationResult

__all__ = [
    "Severity",
    "ValidationIssue",
    "ValidationResult",
    "apply_policy",
    "validate_file",
    "validate_text",
]


def validate_text(
    text: str,
    *,
    target: str = "joern_whole_c",
    run_gcc: bool = False,
    compiler: str = "gcc",
) -> tuple[ValidationResult, ...]:
    """Run Layer A (always) and, if `run_gcc`, Layer B, over `text`.
    Returns one `ValidationResult` per layer actually run — one element if
    `run_gcc` is False, two otherwise."""
    structural_result = ValidationResult(
        target=target,
        layer="structural",
        checked_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        issues=structural.run(text),
    )
    if not run_gcc:
        return (structural_result,)
    return (structural_result, syntax.run(text, target=target, compiler=compiler))


def validate_file(
    path: str | Path,
    *,
    target: str = "joern_whole_c",
    run_gcc: bool = False,
    compiler: str = "gcc",
) -> tuple[ValidationResult, ...]:
    """`validate_text` over the file at `path` (UTF-8, `errors="replace"` —
    the same read discipline `extract.py` uses for every raw/normalized
    C file, so a validation run never crashes on the same bytes the rest
    of Stage 2 already tolerates)."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return validate_text(text, target=target, run_gcc=run_gcc, compiler=compiler)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m fw_audit.stage2_extraction.validate",
        description=(
            "Validate a normalized Joern-target whole.c against the Stage 2 "
            "Normalization Hardening Spec's 7 defect classes plus general "
            "structural checks."
        ),
    )
    parser.add_argument("file", help="path to the normalized .c file to validate")
    parser.add_argument(
        "--gcc",
        action="store_true",
        help="also run 'gcc -fsyntax-only' if a compiler is on PATH (opt-in, off by default)",
    )
    parser.add_argument(
        "--cc", default="gcc", help="compiler executable to resolve for --gcc (default: gcc)"
    )
    args = parser.parse_args(argv)

    results = validate_file(args.file, run_gcc=args.gcc, compiler=args.cc)
    ok = True
    for result in results:
        print(f"[{result.layer}] target={result.target} tool_available={result.tool_available}")
        for issue in result.issues:
            loc = f":{issue.line}" if issue.line is not None else ""
            print(f"  {issue.severity.value.upper():7} {issue.check}{loc}: {issue.message}")
        if not result.ok:
            ok = False
    if ok:
        print(f"OK: {args.file} passed all Stage 2 validation gates")
        return 0
    print(f"FAIL: {args.file} has at least one ERROR-severity validation issue")
    return 1
