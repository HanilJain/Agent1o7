# CLAUDE.md — Stage 4: RAG Sink-to-Source Identifier

Read this file first for Stage 4 work. **In progress** — only Components 1
(chunking) + 2 (embedding/vector store) are implemented, both inside
`colab/chunk_and_embed.py`. Components 3-6 (local: query generation,
retrieval, taint analysis, driver) aren't built yet. See
[MASTERPLAN_STAGE4.md](../../MASTERPLAN_STAGE4.md) (repo root) for the full
architecture. Root `CLAUDE.md` covers cross-cutting concerns only (LLM
routing, Settings).

## Hard constraints — never violate

- `colab/chunk_and_embed.py` stays **dependency-light and self-contained**
  — stdlib + `chromadb` + a sentence-embedding lib only, **zero
  `fw_audit.*` imports** — it is both this repo's source of truth and a
  file meant to be pasted verbatim into a Colab cell.
- Heavy ML imports (`chromadb`, `sentence_transformers`) stay **lazy**,
  inside the functions that need them, never at module level — this is
  what lets the unit suite test the classifier/chunker without them
  installed.
- Never write into `stage3/` or an earlier stage's output tree — only into
  this stage's own `stage4/` directory (once Components 3-6 land).
- Component 4 (local retrieval, not yet built) MUST embed queries with the
  exact same Qwen3 instruction template `Qwen3Embedder.embed_query` uses —
  drift here degrades retrieval silently rather than raising an error.

## Files

| File | Purpose |
|---|---|
| `colab/chunk_and_embed.py` | Components 1+2: file classifier, `FixedWordChunker`, Qwen3 embedding wrapper, ChromaDB setup, embed+upsert, zip packaging. Colab-pasteable. |
| `colab/stage4_colab.ipynb` | Narrative notebook wrapping the same script (install/upload/run/download cells). |
| `colab/package_input.py` | **Local-only** helper: zips Stage 1 rootfs + Stage 2 `stage2/binaries/` into the one-file upload the notebook's Option A expects. Never runs in Colab itself. |
| `errors.py` | `Stage4InputError`, `VectorStoreUnavailableError`. |

## Invoke

Components 1+2 run in Google Colab — see `colab/stage4_colab.ipynb` for the
cell-by-cell walkthrough, or run the script locally for testing:

```bash
pip install -e ".[stage4-colab]"
python fw_audit/stage4_rag/colab/chunk_and_embed.py \
  --rootfs data/db/<stem>/binwalk_1/_input.pkgtb.extracted/squashfs-root \
  --stage2-binaries data/db/<stem>/stage2/binaries \
  --output ./stage4_corpus_build
```

## Input

Stage 1's extracted rootfs directory + Stage 2's `stage2/binaries/`
directory (reads `<bin_id>/cleaned/whole.c` per binary — never re-runs
tree-sitter).

## Output

A zip (`stage4_corpus_build/stage4_corpus.zip`) containing the persisted
Chroma collection (`chroma/`) and `corpus_report.json`. Download from
Colab and unzip under `<db_subfolder>/stage4/` for local Components 3-6 to
consume once built.

## Debugging

- A Windows-extracted rootfs contains entries `Path.is_file()`/
  `.is_symlink()` raise `OSError` on (device nodes, unsupported reparse
  points) — `discover_rootfs_files` and `package_input.py` both wrap those
  calls; don't remove either guard or swap in `Compress-Archive`/
  `shutil.make_archive` (both abort the whole zip on the first such entry).
- Zero chunks discovered usually means `rootfs_dir`/`stage2_binaries_dir`
  point at the wrong directory — `run()` prints both before embedding.
- `ALLOWED_TEXT_EXTENSIONS`/`SKIP_EXTENSIONS` in `chunk_and_embed.py` are
  the first place to look if real files are mis-classified — plain
  module-level sets, per the brief's "make list of them easily parsing".
- Unit: `pytest -m "not integration" tests/test_stage4_colab_chunk_embed.py`
  (no `chromadb`/`sentence-transformers` needed — lazy imports).

## Adding a feature here

New chunking strategies implement the `ChunkStrategy` protocol in
`colab/chunk_and_embed.py` — v1 ships only `FixedWordChunker`. Component 3
onward (query generation, retrieval, taint analysis, driver) are separate,
not-yet-built local modules — see `MASTERPLAN_STAGE4.md` §7-10 for their
planned shape before adding them.
