"""Parse-check the golden fixture (and each defect-class fixture) with a
real C compiler after Joern-target normalization. Marked `integration`
(needs a `gcc` on PATH) and skipped otherwise, rather than being part of
the always-on unit suite.

Asserts on a ZERO exit code, not error-category substrings. An earlier
version of this test used substring matching because the prelude's
`#include <stdint.h>` pulled in the HOST libc, and on a 64-bit-Windows/
MinGW host Ghidra's own `typedef ulong size_t;` legitimately conflicted
with MinGW's `size_t` — an environment artifact of running a Linux-
firmware decompiler's prelude through a Windows toolchain's headers.

The prelude no longer includes ANY system header (see
`normalize.prelude._fixed_width_types`'s docstring for the full argument —
Joern's Eclipse-CDT frontend resolves no include path either, so this was
never merely a test-environment inconvenience) — this translation unit is
fully self-contained now, so `returncode == 0` is the correct, tight
assertion on every platform, not only the developer's own.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from fw_audit.stage2_extraction.normalize.context import build_context
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
# are being checked for here — the same discipline `syntax.py`'s Layer B
# validation layer uses in production.
_GCC_ARGS = ("-fsyntax-only", "-std=gnu17", "-w", "-fmax-errors=100000")


def _gcc(source: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    source_path = tmp_path / "normalized.c"
    source_path.write_text(source, encoding="utf-8")
    return subprocess.run(
        ["gcc", *_GCC_ARGS, str(source_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _fixture_context():
    """The `BinaryContext` a real Stage 2 run would build for the golden
    fixture, from its companion metadata fixture — mirrors `test_
    normalizer.py::_fixture_context`. Used here (rather than
    `EMPTY_CONTEXT`) because the golden fixture's `undefined FUN_00401234;`
    (Ghidra mis-emitting a function entry point as a byte of data) is only
    resolved by `dedupe_global_declarations`'s `context.is_function_
    symbol` check under REAL context — exactly the metadata a real
    `fw-extract` run always has available for a successfully decompiled
    binary."""

    class _FuncFacts:
        def __init__(self, d: dict) -> None:
            self.name = d["name"]
            self.is_thunk = d.get("is_thunk", False)
            self.is_external = d.get("is_external", False)

    metadata = json.loads(
        (FIXTURES_DIR / "sample_mips_httpd_metadata.json").read_text(encoding="utf-8")
    )
    return build_context(_FuncFacts(d) for d in metadata["functions"])


def test_normalized_golden_fixture_compiles_with_zero_gcc_errors(tmp_path):
    fixture = (FIXTURES_DIR / "sample_mips_httpd.c").read_text(encoding="utf-8")
    result = normalize(fixture, build_joern_pipeline(_fixture_context()))
    proc = _gcc(result.text, tmp_path)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize(
    "fixture_name",
    [
        "defect_anonymous_enumerator.c",
        "defect_illegal_identifiers.c",
        "defect_intrinsic_macros.c",
        "defect_void_function_result.c",
        "defect_missing_prototypes.c",
        "defect_stdint_free.c",
    ],
)
def test_each_defect_fixture_compiles_with_zero_gcc_errors(fixture_name, tmp_path):
    """The direct end-to-end proof for each of the seven defect classes:
    a real compiler, not just this module's own structural checks, agrees
    the normalized output is valid C. `defect_intrinsic_macros.c`
    specifically is the fixture that would have caught the `uint24_t`
    phantom-type regression — gcc reports 'unknown type name' for a
    phantom type where `structural.py`'s own `_PHANTOM_TYPE_RE` check
    might, in principle, miss a variant it wasn't written to recognize."""
    fixture = (FIXTURES_DIR / fixture_name).read_text(encoding="utf-8")
    result = normalize(fixture, build_joern_pipeline())
    proc = _gcc(result.text, tmp_path)
    assert proc.returncode == 0, proc.stderr
