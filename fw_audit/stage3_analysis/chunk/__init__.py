"""Pure accumulation of an already-extracted, already-ordered
`tuple[ExtractedFunction, ...]` (Step 2's output) into ~`stage3_chunk_lines`
-line `Chunk` objects, never splitting a function.

Why this package needs no AST walk of its own
--------------------------------------------------------------------------
`clean.extract.extract_functions` already walked tree-sitter's AST and
already knows every kept function's exact line span (`ExtractedFunction.
start_line`/`end_line`) and verbatim text. Chunking a firmware binary's
~2,000 extracted functions into LLM-context-sized pieces is therefore pure
greedy accumulation over an already-ordered sequence — see
`strategy.chunk_source`'s docstring for the exact algorithm and its
soft-limit/hard-cap edge cases.

Invariants
--------------------------------------------------------------------------
* Import-pure, like `clean/`: `chunk_source` takes an `ExtractedSource` in
  and returns a `tuple[Chunk, ...]` out — no filesystem I/O. Unlike
  `clean/`, this package has NO dependency on `tree-sitter`/`tree-sitter-c`
  at all: it never re-parses, so it imports cleanly with or without the
  `stage3` extra installed, and its tests need no `importorskip` gate.
* Bounded per single binary: `chunk_source` never accumulates more than
  one binary's `ExtractedSource` worth of chunk text in memory at a time —
  callers (`ingest.py`) invoke it once per `Target`, matching
  `extract_functions`'s own per-target granularity.
* Never writes to disk. All filesystem I/O (the `--debug-chunks` dump)
  lives in `ingest.py`, exactly like `--debug`'s cleaned-source dump.
"""

from __future__ import annotations
