# Stage 4 — RAG Sink-to-Source Identifier

Traces the security-relevant sinks Stage 3 flags back to their real
sources (NVRAM, HTTP params, network, IPC, files) across the whole
firmware corpus, using retrieval-augmented context assembly. See
[MASTERPLAN_STAGE4.md](../../MASTERPLAN_STAGE4.md) at the repo root for
the full architecture, component breakdown, and milestone roadmap.

## Status

**All six components implemented, running entirely locally.** The
original Colab-split design (C1+C2 in Colab, C3-C6 local) has been
superseded — Colab is now an optional alternate path for C1+C2, not
required for any part of the pipeline.

## Pipeline

1. **`fw-trace build-corpus`** (C1+C2) — classifies Stage 1's rootfs files
   against a strict extension allow-list
   (`colab.chunk_and_embed.ALLOWED_TEXT_EXTENSIONS` — no printable-byte
   heuristic fallback for unlisted/extensionless files), chunks (~500
   words), embeds each chunk with a local Qwen3 embedding model
   (`Qwen/Qwen3-Embedding-0.6B` by default), and indexes into a persistent
   local ChromaDB collection under `<db_subfolder>/stage4/chroma/`. No
   zip/upload step — the rootfs directory is read directly from disk.
   Stage 2's cleaned decompiled C (`cleaned/whole.c` per binary) is
   **excluded by default** — set `FWA_STAGE4_INCLUDE_DECOMPILED_C=true`
   (`Settings.stage4_include_decompiled_c`) to fold it back in.
2. **`fw-trace run`** (C3-C6) — for each Stage 3 finding with
   `decision in {ESCALATE, CONTEXT_REQUIRED}`: generates 4-5 search
   queries (C3), retrieves + merges top-k matching chunks (C4, embedding
   queries with the exact same model as step 1), and reasons over the
   retrieved context to build a structured `TaintPathReport` (C5) — all
   through a bounded async worker pool (C6), same shape as Stage 3's
   `chunk_queue.py`.
3. **`fw-trace debug ...`** — inspect/verify any single step (corpus
   stats, embedding parity, sink listing, or a single finding's
   query/retrieve/taint output) without running the whole pipeline.

## Setup

```bash
pip install -e ".[stage4,anthropic,ollama,dev]"

fw-trace build-corpus --db-subfolder data/db/<stem> \
  --rootfs data/db/<stem>/binwalk_1/_input.pkgtb.extracted/squashfs-root \
  --stage2-binaries data/db/<stem>/stage2/binaries

fw-trace run --db-subfolder data/db/<stem>
```

## Optional: Colab path for C1+C2

`colab/chunk_and_embed.py` (the underlying engine `corpus_build.py`
imports) is still dependency-light and Colab-pasteable, and
`colab/stage4_colab.ipynb`/`colab/package_input.py` still work if you
specifically want to build the corpus on Colab's free GPU. Unzip the
result under `<db_subfolder>/stage4/` and `fw-trace run` picks up from
there exactly as if `build-corpus` had run locally.

## Debugging

`--trace` (or `LANGSMITH_TRACING=true` + `LANGSMITH_API_KEY`) traces `run`
in LangSmith: one root run per finding (C3->C4->C5), with C4's retrieval
step as a `run_type="retriever"` span recording each query's returned
chunk ids and distances — the fastest way to tell whether a bad taint path
came from a bad query (C3) or bad retrieval (C4). See the project root
`CLAUDE.md`'s Observability section.

## Testing

```bash
pytest -m "not integration" tests/test_stage4_*.py
```

No `chromadb`/`sentence-transformers`/network required for the unit suite
— heavy ML imports are lazy and LLM calls are mocked. Real-model/network
tests are marked `integration` and skipped by default.

See [CLAUDE.md](CLAUDE.md) for the file table, hard constraints, and
debugging notes.
