# CLAUDE.md — Stage 3: Analysis Core

Read this file first for any Stage 3 work. Both Components are implemented:
**Component 1** (ingest → chunk → queue) and **Component 2** (`agent/` —
the LLM vulnerability-analysis worker pool). Step 2 — Clean — now lives in
Stage 2 (`stage2_extraction.clean`); Stage 3 reads its persisted
`cleaned/whole.c`/`functions.json` via `cleaned_io.py` instead of running
tree-sitter itself. Root `CLAUDE.md` covers only cross-cutting concerns
(LLM routing, Settings) — link back for those.

## Hard constraints — never violate

- Never write into `stage2/` or the Stage 2 decompiled mirror tree — only
  into this stage's own `stage3/` directory.
- `ingest()` raises `Stage3InputError` **only** while loading Stage 1/2's
  hand-offs or resolving the mirror tree. Every per-binary problem past
  that becomes a `SkippedTarget`, never an exception. This includes a
  `Target` with no cleaned artifact recorded — never raised, just skipped
  for cleaning/chunking with a warning.
- `chunk_source()` never splits a function across chunks.
- `chunk_queue.py` is **never modified by Component 2** — `agent/` only
  fills its `consumer=` extension point.
- Never re-implement tree-sitter extraction here — if the cleaned artifact
  format needs to change, that's a Stage 2 change
  (`stage2_extraction.clean`/`extract.py::_clean_whole_c`), not a Stage 3
  one.

## Files

| File | Purpose |
|---|---|
| `stage2_io.py` | Loads `stage2_summary.json`, resolves the mirror-tree dir. |
| `whitelist.py` | Joins Stage 1 `identified_binaries` ∩ Stage 2 `binaries[]` (pure). |
| `discover.py` | Locates each matched binary's `.c` in the mirror tree (path-traversal guarded). |
| `ingest.py` | Step 1 orchestrator → `IngestionReport`; hosts `--debug`/`--debug-chunks` writers. |
| `cleaned_io.py` | Step 2: loads Stage 2's persisted `cleaned/whole.c` + `functions.json`, reconstructs `ExtractedSource` by slicing — no tree-sitter, no re-parsing. |
| `chunk/strategy.py` | Step 3: greedy function-preserving chunking, in-memory, no I/O. |
| `chunk_queue.py` | Step 4: in-process `asyncio.Queue` + worker pool, persists chunk text to disk (`ChunkHandle` only carries a pointer). |
| `layout.py`, `models.py`, `errors.py` | Path algebra, `Target`/`SkippedTarget`/`IngestionReport`, `Stage3InputError`. `Target` carries `cleaned_source_path`/`cleaned_index_path` (both `None` if Stage 2 skipped cleaning for that binary). |
| `agent/prompts.py` | Worker system prompt + `[Lnnn]`-marked message builder. |
| `agent/analyst.py` | `analyze_chunk()` — structured-output LLM call + bounded schema-repair retry. |
| `agent/consumer.py` | `AnalysisConsumer` — the real `consumer=` for `run_queue`; backoff, token-limit skip, persists findings. |
| `agent/orchestrator.py` | `run_analysis()` entry point — fails fast on missing credential, writes `analysis_summary.json`. |
| `runner.py` | `fw-analyze` CLI entry point. |

## Invoke

```bash
fw-analyze data/db/<stem>/stage1_summary.json                      # ingest only
fw-analyze data/db/<stem>/stage1_summary.json --only bin/httpd     # repeatable
fw-analyze data/db/<stem>/stage1_summary.json --debug              # raw+cleaned dump
fw-analyze data/db/<stem>/stage1_summary.json --debug-chunks --chunk-lines 500
fw-analyze data/db/<stem>/stage1_summary.json --queue              # Step 4, no-op consumer
fw-analyze data/db/<stem>/stage1_summary.json --analyze            # Component 2, real LLM
fw-analyze data/db/<stem>/stage1_summary.json --analyze --model ollama:qwen2.5-coder:1.5b
```

## Input

`stage1_summary.json` only (Stage 2's summary is loaded internally via the
mirror-tree fallback chain).

## Output — `data/db/<stem>/stage3/`

`ingestion_report.json` (always) → `debug/<bin_id>.c`/`.cleaned.c`
(`--debug`) → `chunks/<chunk_id>.c` (`--debug-chunks` or `--queue`/`--analyze`,
unconditional) → `stage3_summary.json` (`--queue`/`--analyze`) →
`findings/<chunk_id>.json` + `analysis_summary.json` (`--analyze`).

## Debugging

- `--trace` (or `LANGSMITH_TRACING=true` + `LANGSMITH_API_KEY`) traces every
  `--analyze` run: one `stage3.chunk` root run per chunk, containing the
  analyst LLM call and any schema-repair retry (tagged `repair`,
  `attempt:N` in metadata) — see root `CLAUDE.md`'s Observability section.

## Debugging

- A `Target` with no cleaned artifact recorded (Stage 2 skipped cleaning
  for it — e.g. the `stage2` extra wasn't installed there): `--debug`'s
  cleaned dump is skipped for that target with a warning;
  `--debug-chunks`/`--queue`/`--analyze` degrade the same way, per-target
  (not a whole-run abandonment — that changed when cleaning moved to
  Stage 2, where availability is decided once per binary rather than
  process-wide).
- `--analyze` needs `ANTHROPIC_API_KEY` (or `FWA_STAGE3_ANALYST_MODEL`) —
  else `AnalystModelUnavailableError` before any chunk is processed.
- A chunk over `FWA_STAGE3_MAX_CHUNK_TOKENS` (100k default) is skipped, not
  retried. Retries cap at `FWA_STAGE3_QUEUE_MAX_ATTEMPTS` (3).
- Unit: `pytest -m "not integration" tests/test_stage3_*.py tests/test_findings_schema.py`

## Adding a feature here

New analysis behavior goes in `agent/`, never in `chunk_queue.py`. New
finding fields go in `common/findings.py` (not `common/schemas.py`). A
change to what "cleaned" C looks like belongs in Stage 2
(`stage2_extraction.clean`/`extract.py`), not here.
