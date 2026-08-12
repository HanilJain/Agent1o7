"""Parse-check the golden fixture with a real C compiler after Joern-target
normalization. Marked `integration` (needs a `gcc` on PATH) and skipped
otherwise, rather than being part of the always-on unit suite.

Deliberately asserts on error CATEGORY substrings, not on a zero exit code:
the prelude's `#include <stdint.h>` pulls in the HOST libc, and on a
64-bit-Windows/MinGW host Ghidra's own `typedef ulong size_t;` legitimately
conflicts with MinGW's `size_t` — an environment artifact of running a
Linux-firmware decompiler's prelude through a Windows toolchain's headers,
not a defect in this pipeline's output. What this test actually guards is
the class of error the normalizer exists to eliminate: illegal syntax,
unknown types, redefinitions, and undeclared identifiers caused by illegal
declarations being silently discarded.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from fw_audit.stage2_extraction.normalize.pipeline import build_joern_pipeline, normalize

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not on PATH"),
]

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "ghidra"

# -std=gnu17 is the closest available proxy for Eclipse CDT's C dialect
# (Joern's C frontend) — in particular, it is what selects the prelude's
# pre-C23 `typedef int code();` branch, the one actually exercised by
# Joern. -w suppresses warnings entirely; only hard parse/semantic ERRORS
# are being checked for here.
_GCC_ARGS = ("-fsyntax-only", "-std=gnu17", "-w", "-fmax-errors=100000")

# Substrings that indicate the class of defect this pipeline exists to
# eliminate — NOT the full set of gcc diagnostics (see module docstring).
_FORBIDDEN_ERROR_SUBSTRINGS = (
    "expected identifier or '('",
    "unknown type name",
    "redefinition of",
    "undeclared (first use",
    "invalid use of void expression",
    "expected ')' before",
)


def _gcc_errors(source: str, tmp_path: Path) -> str:
    source_path = tmp_path / "normalized.c"
    source_path.write_text(source, encoding="utf-8")
    proc = subprocess.run(
        ["gcc", *_GCC_ARGS, str(source_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc.stderr


def test_normalized_golden_fixture_has_no_illegal_syntax_or_undeclared_identifiers(tmp_path):
    fixture = (FIXTURES_DIR / "sample_mips_httpd.c").read_text(encoding="utf-8")
    result = normalize(fixture, build_joern_pipeline())
    stderr = _gcc_errors(result.text, tmp_path)
    for forbidden in _FORBIDDEN_ERROR_SUBSTRINGS:
        assert forbidden not in stderr, f"{forbidden!r} found in gcc output:\n{stderr}"
