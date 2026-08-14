"""Loads the local Chroma collection built by `corpus_build.py` (C1+C2), and
the query-side embedder Component 4 needs to search it.

**Hard embedding-parity requirement**: `load_embedder` MUST use the exact
same `Qwen3Embedder` class (same instruction template, same model name) as
`corpus_build.py` used to embed the documents — mismatched embeddings still
produce a same-shaped vector that "works" but silently degrades retrieval
quality, with no error to catch it. See `colab/chunk_and_embed.py`'s
`QWEN3_QUERY_INSTRUCTION` docstring for the exact recipe being mirrored.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fw_audit.config.settings import Settings, get_settings
from fw_audit.stage4_rag.errors import VectorStoreUnavailableError


def load_local_collection(chroma_dir: Path, *, collection_name: str) -> Any:
    """Opens the persisted Chroma collection at `chroma_dir`.

    Raises `VectorStoreUnavailableError` before any query embedding is
    attempted if `chroma_dir` doesn't exist or doesn't look like a valid
    persisted Chroma directory — fail fast on a missing precondition,
    mirroring `stage3_analysis`'s own "check up front, before per-item
    work" posture (see `errors.py`'s docstring for this class).
    """
    if not chroma_dir.is_dir():
        raise VectorStoreUnavailableError(
            f"No local Chroma collection at {chroma_dir}. Run `fw-trace build-corpus` "
            "first (or unzip a Colab-built corpus under this path)."
        )
    try:
        import chromadb
    except ImportError as exc:
        raise VectorStoreUnavailableError(
            'chromadb is not installed. Install it with: pip install "fw-audit[stage4]"'
        ) from exc

    client = chromadb.PersistentClient(path=str(chroma_dir))
    try:
        return client.get_collection(name=collection_name)
    except Exception as exc:  # chromadb raises its own NotFoundError subclass
        raise VectorStoreUnavailableError(
            f"Collection {collection_name!r} not found in {chroma_dir}: {exc}"
        ) from exc


def load_embedder(*, settings: Settings | None = None) -> Any:
    """Builds the same `Qwen3Embedder` used at corpus-build time, from
    `Settings.stage4_embedding_model`/`stage4_embedding_device` — see this
    module's docstring for why this must never drift from what built the
    collection being searched."""
    settings = settings or get_settings()
    try:
        from fw_audit.stage4_rag.colab.chunk_and_embed import Qwen3Embedder
    except ImportError as exc:
        raise VectorStoreUnavailableError(
            'sentence-transformers is not installed. Install it with: '
            'pip install "fw-audit[stage4]"'
        ) from exc
    return Qwen3Embedder(settings.stage4_embedding_model, device=settings.stage4_embedding_device)


__all__ = ["load_embedder", "load_local_collection"]
