# Stage 3 — Analysis Core

Bridges Stage 2's decompiled output to LLM-backed vulnerability analysis.
**Component 1** (ingest → chunk → queue) and **Component 2** (the LLM
vulnerability-analysis worker pool, `agent/`) are both implemented. Step
2 — Clean — moved into Stage 2 (`stage2_extraction.clean`); Stage 3 reads
its persisted output rather than running tree-sitter itself.

## What it does

- **Step 1 — Ingest** (`ingest.py`): joins Stage 1's whitelist against
  Stage 2's verified index (`whitelist.py`), locates each match in the
  decompiled mirror tree (`discover.py`), and produces an `IngestionReport`
  of `Target`s (analyzable) and `SkippedTarget`s (with a reason code).
- **Step 2 — Read cleaned artifact** (`cleaned_io.py`): loads Stage 2's
  persisted `cleaned/whole.c` + `cleaned/functions.json` for each `Target`
  and reconstructs an `ExtractedSource` by slicing line ranges — no
  tree-sitter, no re-parsing. A `Target` whose Stage 2 run skipped cleaning
  (e.g. the `stage2` extra wasn't installed there) is skipped individually
  with a warning, not a whole-run failure.
- **Step 3 — Chunk** (`chunk/strategy.py`): greedily groups an
  `ExtractedSource`'s functions into ~1000-line chunks, never splitting a
  function; an oversized single function becomes its own chunk.
- **Step 4 — Queue** (`chunk_queue.py`): an in-process `asyncio.Queue` (no
  external broker) persists each chunk to disk and drains it through a
  worker pool with ack/nack retry semantics.
- **Component 2** (`agent/`): fills the queue's `consumer=` extension point.
  Each chunk goes to `AgentRole.STAGE3_VULN_ANALYST` (Anthropic Claude
  Sonnet by default), validated against `common.findings.AnalysisReport`,
  and persisted per chunk — crash-resilient.

## Files

See [CLAUDE.md](CLAUDE.md) for the full file-by-file table (kept there to
avoid duplicating it in both docs).

## How to run

```bash
fw-analyze data/db/<stem>/stage1_summary.json                    # Step 1 only
fw-analyze data/db/<stem>/stage1_summary.json --debug             # dump raw+cleaned source
fw-analyze data/db/<stem>/stage1_summary.json --debug-chunks --chunk-lines 500
fw-analyze data/db/<stem>/stage1_summary.json --queue              # Step 4, plumbing check
fw-analyze data/db/<stem>/stage1_summary.json --analyze             # Component 2, real LLM
fw-analyze data/db/<stem>/stage1_summary.json --analyze --model ollama:qwen2.5-coder:1.5b
```

## Input

`stage1_summary.json` (Stage 2's summary is loaded internally).

## Output

`data/db/<stem>/stage3/`: `ingestion_report.json` always; `debug/`,
`chunks/`, `stage3_summary.json`, `findings/<chunk_id>.json`, and
`analysis_summary.json` depending on which flags are passed. Never writes
into `stage2/` or the mirror tree.

## Debugging

- Stage 3 itself needs no `tree-sitter` extra — cleaning happens in Stage 2.
  A `Target` with no cleaned artifact recorded (Stage 2 skipped cleaning for
  it, e.g. the `stage2` extra wasn't installed there) degrades gracefully
  per-target (raw dump still succeeds, cleaned/chunk dump skipped with a
  warning), never crashes.
- `--analyze` requires an LLM credential (`ANTHROPIC_API_KEY` or
  `FWA_STAGE3_ANALYST_MODEL` for an offline Ollama run) — fails fast with
  `AnalystModelUnavailableError` otherwise, before any chunk is processed.
- A chunk over `FWA_STAGE3_MAX_CHUNK_TOKENS` is skipped rather than retried.
- `qwen2.5-coder:1.5b` verifies plumbing only — expect materially worse
  finding quality than Claude Sonnet on the large `AnalysisReport` schema.
- `--trace` (or `LANGSMITH_TRACING=true`) traces `--analyze` runs in
  LangSmith: one root run per chunk, with schema-repair retries visible as
  sibling child runs — see the project root `CLAUDE.md`'s Observability
  section.

## Testing

```bash
pytest -m "not integration" tests/test_stage3_*.py tests/test_findings_schema.py
```

See the [project CLAUDE.md](../../CLAUDE.md) and
[project README.md](../../README.md) for LLM provider setup.
