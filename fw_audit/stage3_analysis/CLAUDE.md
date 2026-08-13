# CLAUDE.md — Stage 3: Analysis Core

Read this file first for any Stage 3 work. Both Components are implemented:
**Component 1** (ingest → clean → chunk → queue) and **Component 2**
(`agent/` — the LLM vulnerability-analysis worker pool). Root `CLAUDE.md`
covers only cross-cutting concerns (LLM routing, Settings) — link back for
those.

## Hard constraints — never violate

- Never write into `stage2/` or the Stage 2 decompiled mirror tree — only
  into this stage's own `stage3/` directory.
- `ingest()` raises `Stage3InputError` **only** while loading Stage 1/2's
  hand-offs or resolving the mirror tree. Every per-binary problem past
  that becomes a `SkippedTarget`, never an exception.
- `chunk_source()` never splits a function across chunks.
- `chunk_queue.py` is **never modified by Component 2** — `agent/` only
  fills its `consumer=` extension point.

## Files

| File | Purpose |
|---|---|
| `stage2_io.py` | Loads `stage2_summary.json`, resolves the mirror-tree dir. |
| `whitelist.py` | Joins Stage 1 `identified_binaries` ∩ Stage 2 `binaries[]` (pure). |
| `discover.py` | Locates each matched binary's `.c` in the mirror tree (path-traversal guarded). |
| `ingest.py` | Step 1 orchestrator → `IngestionReport`; hosts `--debug`/`--debug-chunks` writers. |
| `clean/parser.py`, `clean/extract.py` | Step 2: tree-sitter function-only extraction (needs the `stage3` extra — pinned `tree-sitter==0.23.2`/`tree-sitter-c==0.23.2`). |
| `chunk/strategy.py` | Step 3: greedy function-preserving chunking, in-memory, no I/O. |
| `chunk_queue.py` | Step 4: in-process `asyncio.Queue` + worker pool, persists chunk text to disk (`ChunkHandle` only carries a pointer). |
| `layout.py`, `models.py`, `errors.py` | Path algebra, `Target`/`SkippedTarget`/`IngestionReport`, `Stage3InputError`. |
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

- Missing `stage3` extra: `--debug`'s cleaned dump is skipped with a
  warning; `--debug-chunks`/`--queue`/`--analyze` degrade the same way.
- `--analyze` needs `ANTHROPIC_API_KEY` (or `FWA_STAGE3_ANALYST_MODEL`) —
  else `AnalystModelUnavailableError` before any chunk is processed.
- A chunk over `FWA_STAGE3_MAX_CHUNK_TOKENS` (100k default) is skipped, not
  retried. Retries cap at `FWA_STAGE3_QUEUE_MAX_ATTEMPTS` (3).
- Unit: `pytest -m "not integration" tests/test_stage3_*.py tests/test_findings_schema.py`

## Adding a feature here

New analysis behavior goes in `agent/`, never in `chunk_queue.py`. New
finding fields go in `common/findings.py` (not `common/schemas.py`).
