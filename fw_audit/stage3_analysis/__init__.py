"""Stage 3: Vulnerability Analysis Core — ingest Stage 2's whitelist, clean
its decompiled C for LLM consumption, chunk it along AST boundaries, and
queue the chunks for an agent worker pool.

Renamed from the original `stage3_rag` placeholder: this package is not a
retrieval-augmented-generation layer, it is the bridge between Stage 2's
Ghidra/Joern output and Stage 4+'s analysis agents. See `CLAUDE.md` for the
pipeline-wide rationale.

Why this package exists at all — the contract it fills
--------------------------------------------------------------------------
Stage 2 normalizes decompiled C for exactly one target: Joern, a CPG
builder (see `stage2_extraction.normalize`). Its own `pipeline.py` module
docstring says as much: the target-specific passes are parameterized "so a
future target-specific pipeline (e.g. LLM-facing preparation, planned for a
later stage) can reuse [the shared pass groups] without duplicating the
shared pass list." This package is that later stage. It never re-implements
Stage 2's repair passes (thunk stubs, illegal array declarations, duplicate
globals, ...) — it imports and reuses them — and adds only the conversion
from Joern-flavored C (CPG-shaped: inlined prelude, extern thunk walls,
warning comments stripped) to LLM-flavored C (chunk-shaped, low-noise).

Component boundaries (see the project plan for the full four-step design)
--------------------------------------------------------------------------
* **Component 1** (this package, current scope): ingest -> clean -> chunk ->
  queue. Everything up to and including handing a chunk to an
  `asyncio.Queue` for a worker to pull.
* **Component 2** (not yet built): the parallel agent orchestrator that
  drains the queue this package produces, three workers deep, and returns
  JSON vulnerability reports per chunk.

Invariant that holds across the whole package: nothing here ever writes
into `stage2/` or the Stage 2 decompiled-C mirror tree. Every module that
touches the filesystem only reads Stage 2's output and writes into its own
`<db_subfolder>/stage3/` directory.
"""

from __future__ import annotations
