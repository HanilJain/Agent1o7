"""Function-only extraction: turn the raw decompiled C into an LLM-shaped
stream containing nothing but real function bodies.

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
`extract.extract_functions()` parses text already repaired by
`normalize.pipeline.build_clean_pipeline()` (the LLM-target sibling of
`build_joern_pipeline()` — see that module's docstring) with `tree-sitter-c`
and keeps only `function_definition` top-level nodes. Struct/typedef/enum
declarations, the prelude, and the extern thunk-wall are all dropped — not
preserved as "type context" — per this project's confirmed scope.

Originally lived in `stage3_analysis.clean`, recomputed in memory on every
Stage 3 run. Moved here so `extract.py::_normalize_one` can run it once per
binary, right alongside the existing Joern normalization pass, and persist
the result to `binaries/<bin_id>/cleaned/` — Stage 3's chunking now reads
that stored artifact instead of re-parsing (see `stage3_analysis.
cleaned_io`), and a future Stage 4 has a durable artifact to consume too.

Invariants
--------------------------------------------------------------------------
* Import-pure like Stage 2's `normalize/` package w.r.t. filesystem access:
  no `os`, `subprocess`, or `fw_audit.executors` imports anywhere in this
  package (`pathlib` IS used, unlike `normalize/`, only for type hints in
  `TYPE_CHECKING` blocks — no filesystem I/O). Every function here takes a
  `str` in and returns data out; all filesystem I/O (reading raw C, writing
  `cleaned/whole.c`+`functions.json`) happens in `stage2_extraction.extract`,
  not here.
* `tree-sitter`/`tree-sitter-c` are optional (the `stage2` extra, aliased
  as `stage3` for backward compatibility) and imported lazily inside
  `parser.get_parser()` — this package must import cleanly even when they
  aren't installed; only calling `get_parser()` requires them.
"""

from __future__ import annotations
