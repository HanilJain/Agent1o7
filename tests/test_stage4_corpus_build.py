"""Tests for `fw_audit.stage4_rag.corpus_build` — the local C1+C2 wrapper.

Monkeypatches `_build_embedder`/`get_or_create_collection`/`embed_and_upsert`
so this never needs real `chromadb`/`sentence-transformers` — matches
`tests/test_stage4_colab_chunk_embed.py`'s "no heavy ML deps" convention.
Pure classify/chunk logic is already covered there; this file only tests
`build_corpus`'s own orchestration (paths, config wiring, report result).
"""

from __future__ import annotations

from pathlib import Path

from fw_audit.config.settings import Settings
from fw_audit.stage4_rag import corpus_build, layout


class _FakeEmbedder:
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [[0.0] for _ in texts]


def _make_inputs(tmp_path: Path) -> tuple[Path, Path]:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "login.asp").write_text("nvram_get(\"admin_password\")", encoding="utf-8")

    stage2_binaries = tmp_path / "stage2_binaries"
    bin_dir = stage2_binaries / "sbin_httpd__abc123" / "cleaned"
    bin_dir.mkdir(parents=True)
    (bin_dir / "whole.c").write_text("void f(void) {}", encoding="utf-8")
    return rootfs, stage2_binaries


def test_build_corpus_writes_to_stage4_dir_no_zip(tmp_path, monkeypatch):
    rootfs, stage2_binaries = _make_inputs(tmp_path)
    db_subfolder = tmp_path / "db" / "fw"

    monkeypatch.setattr(corpus_build, "_build_embedder", lambda config: _FakeEmbedder())

    upserted_calls = []

    def fake_upsert(*, chunks, embedder, collection, batch_size):
        upserted_calls.append(len(chunks))
        return len(chunks)

    monkeypatch.setattr(corpus_build, "embed_and_upsert", fake_upsert)
    monkeypatch.setattr(
        corpus_build, "get_or_create_collection", lambda *, persist_dir, collection_name: object()
    )

    settings = Settings(_env_file=None, stage4_embedding_model="Qwen/Qwen3-Embedding-0.6B")
    report = corpus_build.build_corpus(
        db_subfolder=db_subfolder,
        rootfs_dir=rootfs,
        stage2_binaries_dir=stage2_binaries,
        settings=settings,
    )

    # stage4_include_decompiled_c defaults to False — only the rootfs chunk
    # is ingested, the Stage 2 cleaned/whole.c is left out.
    assert report.total_chunks == 1
    assert report.chunks_by_kind == {"ROOTFS_TEXT": 1}
    assert report.embedding_model == "Qwen/Qwen3-Embedding-0.6B"
    stage4_dir = layout.stage4_dir(db_subfolder)
    assert report.chroma_dir == layout.chroma_dir(stage4_dir)
    assert report.corpus_report_path == layout.corpus_report_path(stage4_dir)
    assert report.corpus_report_path.is_file()
    # No zip artifact anywhere under stage4/ — the whole point of the local path.
    assert not list(stage4_dir.rglob("*.zip"))
    assert upserted_calls == [1]


def test_build_corpus_includes_decompiled_c_when_opted_in(tmp_path, monkeypatch):
    rootfs, stage2_binaries = _make_inputs(tmp_path)
    db_subfolder = tmp_path / "db" / "fw"

    monkeypatch.setattr(corpus_build, "_build_embedder", lambda config: _FakeEmbedder())

    upserted_calls = []

    def fake_upsert(*, chunks, embedder, collection, batch_size):
        upserted_calls.append(len(chunks))
        return len(chunks)

    monkeypatch.setattr(corpus_build, "embed_and_upsert", fake_upsert)
    monkeypatch.setattr(
        corpus_build, "get_or_create_collection", lambda *, persist_dir, collection_name: object()
    )

    settings = Settings(_env_file=None, stage4_include_decompiled_c=True)
    report = corpus_build.build_corpus(
        db_subfolder=db_subfolder,
        rootfs_dir=rootfs,
        stage2_binaries_dir=stage2_binaries,
        settings=settings,
    )

    assert report.total_chunks == 2  # one rootfs chunk + one decompiled-C chunk
    assert report.chunks_by_kind == {"ROOTFS_TEXT": 1, "DECOMPILED_C": 1}
    assert upserted_calls == [2]


def test_build_corpus_zero_chunks_still_writes_report(tmp_path, monkeypatch):
    empty_rootfs = tmp_path / "empty_rootfs"
    empty_rootfs.mkdir()
    empty_stage2 = tmp_path / "empty_stage2"
    empty_stage2.mkdir()
    db_subfolder = tmp_path / "db" / "fw"

    monkeypatch.setattr(corpus_build, "_build_embedder", lambda config: _FakeEmbedder())
    monkeypatch.setattr(
        corpus_build, "embed_and_upsert", lambda *, chunks, embedder, collection, batch_size: 0
    )
    monkeypatch.setattr(
        corpus_build, "get_or_create_collection", lambda *, persist_dir, collection_name: object()
    )

    report = corpus_build.build_corpus(
        db_subfolder=db_subfolder,
        rootfs_dir=empty_rootfs,
        stage2_binaries_dir=empty_stage2,
        settings=Settings(_env_file=None),
    )

    assert report.total_chunks == 0
    assert report.corpus_report_path.is_file()
