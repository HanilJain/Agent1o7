"""Stage 4, Components 1+2 — local corpus build (primary supported path).

Wraps `colab/chunk_and_embed.py`'s classify/chunk/embed/index engine — that
file stays dependency-light and Colab-pasteable (see its own docstring); this
module is the normal `fw_audit`-integrated entry point: it reads local
`Settings`, uses `logging` instead of `print()`, and persists straight into
`<db_subfolder>/stage4/{chroma,corpus_report.json}` — **no zip packaging, no
upload/download round-trip** — since the rootfs and Stage 2 directories are
already on this machine, there is nothing to upload anywhere.

Deliberately does NOT call `chunk_and_embed.run()` (that function's own
zip/`package_for_download` step is Colab-specific, for getting a build off a
Colab runtime). Instead it calls the same underlying pieces directly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from fw_audit.config.settings import Settings, get_settings
from fw_audit.stage4_rag import layout
from fw_audit.stage4_rag.colab.chunk_and_embed import (
    Chunk,
    Stage4ColabConfig,
    build_corpus_chunks,
    embed_and_upsert,
    get_or_create_collection,
    write_corpus_report,
)

logger = logging.getLogger("fw_audit.stage4_rag.corpus_build")


@dataclass(frozen=True)
class CorpusBuildReport:
    """Result of one local corpus build — mirrors `corpus_report.json`'s
    content plus the resolved output paths, for callers (CLI, debug module)
    that want both without re-reading the file."""

    total_files: int
    total_chunks: int
    chunks_by_kind: dict[str, int]
    embedding_model: str
    chroma_dir: Path
    corpus_report_path: Path


def build_corpus(
    *,
    db_subfolder: Path,
    rootfs_dir: Path,
    stage2_binaries_dir: Path,
    settings: Settings | None = None,
) -> CorpusBuildReport:
    """Runs C1 (discover+chunk) then C2 (embed+index) end to end, persisting
    directly under `<db_subfolder>/stage4/` — the local equivalent of the
    Colab notebook's Sections 2-5, minus the zip/upload/download steps those
    exist only to move a build off Colab's ephemeral runtime.
    """
    settings = settings or get_settings()
    stage4_dir_ = layout.stage4_dir(db_subfolder)
    chroma_dir_ = layout.chroma_dir(stage4_dir_)
    report_path = layout.corpus_report_path(stage4_dir_)

    config = Stage4ColabConfig(
        rootfs_dir=rootfs_dir,
        stage2_binaries_dir=stage2_binaries_dir,
        output_dir=stage4_dir_,
        chunk_words=settings.stage4_chunk_words,
        chunk_overlap_words=settings.stage4_chunk_overlap_words,
        include_decompiled_c=settings.stage4_include_decompiled_c,
        embedding_model=settings.stage4_embedding_model,
        embedding_device=settings.stage4_embedding_device,
        chroma_collection_name=settings.stage4_chroma_collection_name,
        embed_batch_size=settings.stage4_embed_batch_size,
        embed_max_seq_length=settings.stage4_embed_max_seq_length,
    )

    logger.info("rootfs: %s", rootfs_dir)
    logger.info("stage2 binaries dir: %s", stage2_binaries_dir)
    chunks: list[Chunk] = build_corpus_chunks(config)
    logger.info("%d chunks discovered", len(chunks))
    if not chunks:
        logger.warning("zero chunks discovered — check rootfs_dir/stage2_binaries_dir above")

    logger.info("loading embedding model: %s", config.embedding_model)
    embedder = _build_embedder(config)

    logger.info("embedding + upserting into Chroma collection %r", config.chroma_collection_name)
    collection = get_or_create_collection(
        persist_dir=chroma_dir_, collection_name=config.chroma_collection_name
    )
    embed_and_upsert(
        chunks=chunks,
        embedder=embedder,
        collection=collection,
        batch_size=config.embed_batch_size,
    )

    report = write_corpus_report(chunks=chunks, config=config, report_path=report_path)
    logger.info("corpus_report.json written: %s", report_path)

    return CorpusBuildReport(
        total_files=report["total_files"],
        total_chunks=report["total_chunks"],
        chunks_by_kind=report["chunks_by_kind"],
        embedding_model=config.embedding_model,
        chroma_dir=chroma_dir_,
        corpus_report_path=report_path,
    )


def _build_embedder(config: Stage4ColabConfig):
    """Factored out for tests to monkeypatch — avoids importing
    `Qwen3Embedder` (which lazily imports `sentence_transformers`) at
    `corpus_build` module import time."""
    from fw_audit.stage4_rag.colab.chunk_and_embed import Qwen3Embedder

    return Qwen3Embedder(
        config.embedding_model,
        device=config.embedding_device,
        max_seq_length=config.embed_max_seq_length,
    )


__all__ = ["CorpusBuildReport", "build_corpus"]
