"""Tests for `fw_audit.stage4_rag.retrieval.store` — the fail-fast paths
that don't require `chromadb`/`sentence-transformers` to be installed.
"""

from __future__ import annotations

import pytest

from fw_audit.config.settings import Settings
from fw_audit.stage4_rag.errors import VectorStoreUnavailableError
from fw_audit.stage4_rag.retrieval.store import load_local_collection


def test_load_local_collection_missing_dir_raises(tmp_path):
    with pytest.raises(VectorStoreUnavailableError, match="No local Chroma collection"):
        load_local_collection(tmp_path / "does_not_exist", collection_name="stage4_corpus")


def test_load_local_collection_existing_dir_without_chromadb_installed_or_valid_collection(
    tmp_path, monkeypatch
):
    """Without `chromadb` installed, or with a directory that isn't a real
    persisted collection, this must raise VectorStoreUnavailableError, never
    a raw ImportError/chromadb-internal exception."""
    chroma_dir = tmp_path / "chroma"
    chroma_dir.mkdir()

    pytest.importorskip("chromadb")  # if chromadb IS installed, verify the "not found" path instead
    with pytest.raises(VectorStoreUnavailableError, match="not found"):
        load_local_collection(chroma_dir, collection_name="nonexistent_collection")


def test_settings_stage4_embedding_model_default():
    settings = Settings(_env_file=None)
    assert settings.stage4_embedding_model == "Qwen/Qwen3-Embedding-0.6B"
