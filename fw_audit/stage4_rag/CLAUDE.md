# CLAUDE.md — Stage 4: RAG Sink-to-Source Identifier

Read this file first for Stage 4 work. **All six components (C1-C6) are
implemented and run locally** — the original Colab-split design has been
superseded; the notebook now demoted to an optional alternate path. Root
`CLAUDE.md` covers only cross-cutting concerns (LLM routing, Settings).

## Hard constraints — never violate

- Never write into `stage3/` or an earlier stage's output tree — only into
  this stage's own `stage4/` directory.
- Component 4 (`retrieval/store.py`) MUST embed queries with the exact same
  `Qwen3Embedder`/`Settings.stage4_embedding_model` that built the corpus —
  drift here degrades retrieval silently rather than raising an error.
- `colab/chunk_and_embed.py` stays dependency-light and Colab-pasteable
  (stdlib + `chromadb` + a sentence-embedding lib only, zero `fw_audit.*`
  imports) — `corpus_build.py` imports its functions rather than
  duplicating them; don't inline that logic elsewhere.
- `debug.py`'s functions never write into `queries/`/`retrieval/`/`taint/`
  — those are `driver.py`'s persisted, tracked output; debug runs (`taint`
  in particular) are dry runs.

## Files

| File | Purpose |
|---|---|
| `layout.py` | Pure path algebra for `stage4/`. |
| `sink_index.py` | C0: resolves `stage3/findings/*.json` into `SinkCandidate`s, summary-free. |
| `corpus_build.py` | C1+C2 local entry point: wraps `colab/chunk_and_embed.py`, persists straight to `stage4/{chroma,corpus_report.json}` — no zip/upload. |
| `colab/chunk_and_embed.py` | The underlying classify/chunk/embed/index engine (reused, not duplicated). Optional Colab path still works via `colab/stage4_colab.ipynb`/`package_input.py`. |
| `query/schemas.py`, `query/prompts.py`, `query/planner.py` | C3: `MultiQueryPlan` structured-output LLM call, no tools. |
| `retrieval/store.py`, `retrieval/engine.py` | C4: loads local Chroma + parity-matched embedder, top-k search + merge/dedupe, `build_c5_prompt()`. |
| `taint/prompts.py`, `taint/analyst.py` | C5: `TaintPathReport` structured-output LLM call, no tools. |
| `driver.py` | C6: async worker-pool loop, C3->C4->C5->persist, mirrors `stage3_analysis.chunk_queue`. |
| `debug.py` | Per-component inspection: corpus stats, embedding parity check, sink listing, single-finding query/retrieve/taint dry runs. |
| `runner.py` | `fw-trace` CLI: `build-corpus`, `run`, `debug {corpus,parity,sinks,query,retrieve,taint}`. |
| `errors.py` | `Stage4InputError`, `VectorStoreUnavailableError`. |

## Invoke

```bash
pip install -e ".[stage4,anthropic,ollama,dev]"

fw-trace build-corpus --db-subfolder data/db/<stem> \
  --rootfs data/db/<stem>/binwalk_1/_input.pkgtb.extracted/squashfs-root \
  --stage2-binaries data/db/<stem>/stage2/binaries

fw-trace run --db-subfolder data/db/<stem>
fw-trace debug corpus --db-subfolder data/db/<stem>
fw-trace debug parity
fw-trace debug taint --db-subfolder data/db/<stem> --gid "<chunk_id>::<finding_id>"
```

## Input

Stage 1's rootfs directory + Stage 2's `stage2/binaries/` (C1+C2); Stage 3's
`stage3/findings/*.json` (C0/C6) — never `stage3_summary.json`/
`analysis_summary.json`, both best-effort and often absent.

## Output — `<db_subfolder>/stage4/`

`chroma/`, `corpus_report.json` (build-corpus) → `queries/<gid>.json`,
`retrieval/<gid>.json`, `taint/<gid>.json`, `stage4_summary.json` (run).

## Debugging

- `fw-trace debug parity` first if retrieval looks wrong — near-zero cosine
  similarity means the query/document embedder setup has drifted.
- `VectorStoreUnavailableError` before `run`/`debug retrieve|taint`: run
  `build-corpus` first, or check `Settings.stage4_chroma_collection_name`
  matches what built the collection.
- `query/prompts.py`/`taint/prompts.py`'s `SYSTEM_PROMPT` are placeholders
  (marked `TODO(user)`) — replace with the specialized prompts when supplied.
- Unit: `pytest -m "not integration" tests/test_stage4_*.py`.

## Adding a feature here

New chunking strategies implement `ChunkStrategy` in `colab/chunk_and_embed.py`.
New retrieval fusion goes in `retrieval/engine.py`. New taint fields go in
`common/taint.py`, never `common/findings.py` (that's Stage 3's).
