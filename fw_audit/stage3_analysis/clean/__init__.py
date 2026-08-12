"""Function-only extraction: turn the decompiled mirror tree's Joern-shaped
C into an LLM-shaped stream containing nothing but real function bodies.

Why this exists — the real-data finding that drove it
--------------------------------------------------------------------------
`sbin/wpasupp.c` (198,871 lines, the largest binary in this repo's real
committed run) has exactly two segments with zero interleaving: lines
1-7150 are the inlined Ghidra type prelude, 343 real struct/typedef
declarations, and a 1,006-line wall of `extern <sig>; /* thunk/PLT stub */`
declarations for functions whose real implementation isn't even in this
binary — followed immediately by 2,102 function definitions straight
through to EOF. Sending the first ~1,000-line chunk of that file to an LLM
for vulnerability analysis sends zero actual program logic.

What this package does about it
--------------------------------------------------------------------------
`extract.extract_functions()` runs a small repair-pass subset reused
directly from `fw_audit.stage2_extraction.normalize.passes` (never
reimplemented — see that function's docstring for exactly which 3 of the
original 7 repair passes are still relevant once declarations are
discarded wholesale), then parses the repaired text with `tree-sitter-c`
and keeps only `function_definition` top-level nodes. Struct/typedef/enum
declarations, the prelude, and the extern thunk-wall are all dropped —
not preserved as "type context" — per this session's confirmed scope.

Invariants
--------------------------------------------------------------------------
* Import-pure, like Stage 2's `normalize/` package: no `os`, `subprocess`,
  `pathlib`, or `fw_audit.executors` imports anywhere in this package.
  Every function here takes a `str` in and returns data out; all
  filesystem I/O (reading the source file, writing the `--debug` dump)
  happens in `ingest.py`, not here.
* Never writes into `stage2/` or the decompiled mirror tree — this package
  can't, since it has no filesystem access at all.
* `tree-sitter`/`tree-sitter-c` are optional (the `stage3` extra) and
  imported lazily inside `parser.get_parser()` — this package must import
  cleanly even when they aren't installed; only calling `get_parser()`
  requires them.
"""

from __future__ import annotations
