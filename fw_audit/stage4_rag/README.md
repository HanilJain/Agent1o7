# Stage 4 — RAG Sink-to-Source Identifier

Traces the security-relevant sinks Stage 3 flags back to their real
sources (NVRAM, HTTP params, network, IPC, files) across the whole
firmware corpus, using retrieval-augmented context assembly. See
[MASTERPLAN_STAGE4.md](../../MASTERPLAN_STAGE4.md) at the repo root for
the full architecture, component breakdown, and milestone roadmap.

## Status

**In progress.** Components 1 (chunking) and 2 (embedding + vector store)
are implemented, both in `colab/chunk_and_embed.py`. Components 3
(multi-query generator), 4 (retrieval engine), 5 (taint path analyzer),
and 6 (local driver) are not yet built — see the masterplan's milestone
table for what's next.

## Deployment model

Corpus-heavy work runs **once, in Google Colab** (free GPU, no local
install burden); per-finding reasoning will run **locally** once
Components 3-6 land, against a downloaded copy of the resulting vector
store.

## Components 1+2 — Google Colab

`colab/chunk_and_embed.py` classifies Stage 1's rootfs files (skipping
anything that needs Ghidra/IDA decompilation first) and Stage 2's cleaned
decompiled C, splits everything into ~500-word chunks, embeds each chunk
with a Qwen3 embedding model, and indexes it into a persistent ChromaDB
collection. The file is deliberately dependency-light — stdlib plus
`chromadb`/`sentence-transformers` only, no `fw_audit` imports — so it can
be pasted directly into a Colab cell. `colab/stage4_colab.ipynb` wraps the
same code in a narrative, cell-by-cell notebook (install → provide input
folders → paste script → configure → run → download).

Output is a zip containing the Chroma collection and a
`corpus_report.json` summary. Download it and unzip under
`<db_subfolder>/stage4/` once local components exist to read it.

### Running locally instead (for testing)

```bash
pip install -e ".[stage4-colab]"
python fw_audit/stage4_rag/colab/chunk_and_embed.py \
  --rootfs data/db/<stem>/binwalk_1/_input.pkgtb.extracted/squashfs-root \
  --stage2-binaries data/db/<stem>/stage2/binaries \
  --output ./stage4_corpus_build
```

## Testing

```bash
pytest -m "not integration" tests/test_stage4_colab_chunk_embed.py
```

Covers the classifier and chunker only — no `chromadb`/
`sentence-transformers` install required, since those imports are lazy.

See [CLAUDE.md](CLAUDE.md) for the file table, hard constraints, and
debugging notes.
