"""Stage 4: RAG Sink-to-Source Identifier — trace Stage 3's flagged sinks
backward to real sources (NVRAM, HTTP params, network, IPC, files) across
the whole firmware corpus using retrieval-augmented context assembly.

Renamed from the original `stage4_analysis` placeholder — this package
*is* the RAG layer, so the name should say that rather than leave the
generic scaffold name in place (mirrors `stage3_analysis/__init__.py`'s
own inverse rename note).

See `MASTERPLAN_STAGE4.md` (repo root) for the full architecture and
milestone roadmap. `CLAUDE.md` in this directory is the quick-reference
kept current as implementation lands.

Deployment split (see the masterplan for the full rationale)
--------------------------------------------------------------------------
* **C1 (chunking) + C2 (vector store + embedding)** run in a **Google
  Colab notebook** — see `colab/chunk_and_embed.py`, deliberately
  dependency-light (stdlib + `chromadb` + embedding lib only, no
  `fw_audit.*` imports) so it is both this repo's source of truth and
  directly paste-able into a Colab cell.
* **C3 (multi-query generator), C4 (retrieval engine), C5 (taint path
  analyzer), C6 (local driver)** run locally, against a downloaded copy of
  the Colab-built Chroma collection.

Nothing here writes into `stage3/` or earlier stages' output trees — only
into this stage's own `<db_subfolder>/stage4/` directory.
"""

from __future__ import annotations
