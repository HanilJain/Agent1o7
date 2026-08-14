"""Tests for `fw_audit.stage4_rag.colab.chunk_and_embed` — Components 1+2's
file classifier and fixed-word chunker.

Deliberately does NOT test `Qwen3Embedder`/`get_or_create_collection`/
`embed_and_upsert` — those lazily import `sentence_transformers`/`chromadb`,
heavy ML dependencies this project's unit suite never requires (see the
module's own docstring on why those imports are inside the functions that
need them, not at module level). This file only exercises the pure,
dependency-free half: classification and chunking.
"""

from __future__ import annotations

from pathlib import Path

from fw_audit.stage4_rag.colab.chunk_and_embed import (
    CorpusKind,
    FixedWordChunker,
    Stage4ColabConfig,
    build_chunks_for_file,
    build_corpus_chunks,
    classify_rootfs_file,
    discover_cleaned_c_files,
    discover_rootfs_files,
)

# --------------------------------------------------------------------- #
# classify_rootfs_file / discover_rootfs_files
# --------------------------------------------------------------------- #


def test_classify_allows_known_text_extensions(tmp_path: Path) -> None:
    for name in ("index.asp", "app.js", "style.css", "wifi.conf", "run.sh", "page.html"):
        f = tmp_path / name
        f.write_text("hello world", encoding="utf-8")
        assert classify_rootfs_file(f) is True, name


def test_classify_skips_known_binary_and_image_extensions(tmp_path: Path) -> None:
    for name in ("lib.so", "wifi.ko", "logo.png", "photo.jpg", "icon.svg", "archive.zip"):
        f = tmp_path / name
        f.write_bytes(b"\x00\x01\x02\x03not really text")
        assert classify_rootfs_file(f) is False, name


def test_classify_skips_elf_even_with_text_like_extension(tmp_path: Path) -> None:
    # A real binary hiding under a misleading extension must still be skipped
    # via the magic-byte check, not just the extension allow-list.
    f = tmp_path / "renamed.txt"
    f.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert classify_rootfs_file(f) is False


def test_classify_extensionless_text_via_heuristic(tmp_path: Path) -> None:
    f = tmp_path / "captive_portal_passcode"
    f.write_text("nvram_get(\"captive_portal_passcode\")\n" * 10, encoding="utf-8")
    assert classify_rootfs_file(f) is True


def test_classify_extensionless_binary_rejected(tmp_path: Path) -> None:
    f = tmp_path / "some_device_node"
    f.write_bytes(bytes(range(256)) * 4)  # dense non-printable bytes
    assert classify_rootfs_file(f) is False


def test_discover_rootfs_files_skips_symlinks_and_unreadable(tmp_path: Path) -> None:
    (tmp_path / "real.html").write_text("<html></html>", encoding="utf-8")
    (tmp_path / "skip.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "nested.asp").write_text("<% response.write(1) %>", encoding="utf-8")

    found = sorted(p.name for p in discover_rootfs_files(tmp_path))
    assert found == ["nested.asp", "real.html"]


def test_discover_rootfs_files_on_missing_dir_yields_nothing(tmp_path: Path) -> None:
    assert list(discover_rootfs_files(tmp_path / "does_not_exist")) == []


# --------------------------------------------------------------------- #
# discover_cleaned_c_files
# --------------------------------------------------------------------- #


def test_discover_cleaned_c_files_finds_persisted_whole_c(tmp_path: Path) -> None:
    bin_dir = tmp_path / "sbin_httpd__abc123"
    (bin_dir / "cleaned").mkdir(parents=True)
    (bin_dir / "cleaned" / "whole.c").write_text("void f(void) {}", encoding="utf-8")
    # a binary Stage 2 skipped cleaning for (no cleaned/ dir) must be silently skipped
    (tmp_path / "sbin_other__def456").mkdir()

    found = list(discover_cleaned_c_files(tmp_path))
    assert len(found) == 1
    bin_id, path = found[0]
    assert bin_id == "sbin_httpd__abc123"
    assert path == bin_dir / "cleaned" / "whole.c"


def test_discover_cleaned_c_files_on_missing_dir_yields_nothing(tmp_path: Path) -> None:
    assert list(discover_cleaned_c_files(tmp_path / "does_not_exist")) == []


# --------------------------------------------------------------------- #
# FixedWordChunker
# --------------------------------------------------------------------- #


def test_fixed_word_chunker_splits_by_word_count() -> None:
    text = " ".join(f"word{i}" for i in range(1250))
    chunker = FixedWordChunker(words_per_chunk=500, overlap_words=0)
    pieces = chunker.chunk(text)

    assert len(pieces) == 3
    assert len(pieces[0].split()) == 500
    assert len(pieces[1].split()) == 500
    assert len(pieces[2].split()) == 250  # tail is shorter, never padded


def test_fixed_word_chunker_empty_text_yields_no_chunks() -> None:
    assert FixedWordChunker(words_per_chunk=500).chunk("") == []
    assert FixedWordChunker(words_per_chunk=500).chunk("   \n\t  ") == []


def test_fixed_word_chunker_never_infinite_loops_with_full_overlap() -> None:
    # overlap_words >= words_per_chunk would make `step` degenerate to 0
    # without the max(1, ...) guard — this must still terminate.
    text = " ".join(f"w{i}" for i in range(50))
    chunker = FixedWordChunker(words_per_chunk=10, overlap_words=10)
    pieces = chunker.chunk(text)
    assert len(pieces) > 0
    assert all(len(p.split()) <= 10 for p in pieces)


def test_fixed_word_chunker_respects_overlap() -> None:
    text = " ".join(f"w{i}" for i in range(20))
    chunker = FixedWordChunker(words_per_chunk=10, overlap_words=5)
    pieces = chunker.chunk(text)
    # step = 10 - 5 = 5, so piece 0 = words[0:10], piece 1 = words[5:15], ...
    assert pieces[0].split()[-5:] == pieces[1].split()[:5]


# --------------------------------------------------------------------- #
# build_chunks_for_file / build_corpus_chunks
# --------------------------------------------------------------------- #


def test_build_chunks_for_file_assigns_sequential_chunk_ids(tmp_path: Path) -> None:
    f = tmp_path / "weird name.asp"
    f.write_text(" ".join(f"w{i}" for i in range(1000)), encoding="utf-8")
    chunks = build_chunks_for_file(
        path=f,
        rel_id="weird name.asp",
        kind=CorpusKind.ROOTFS_TEXT,
        bin_id=None,
        chunker=FixedWordChunker(words_per_chunk=500),
    )
    assert [c.chunk_id for c in chunks] == ["weird_name.asp#0000", "weird_name.asp#0001"]
    assert all(c.kind is CorpusKind.ROOTFS_TEXT for c in chunks)
    assert all(c.bin_id is None for c in chunks)


def test_build_chunks_for_file_content_hash_is_stable(tmp_path: Path) -> None:
    f = tmp_path / "a.txt"
    f.write_text("stable content here", encoding="utf-8")
    chunks1 = build_chunks_for_file(
        path=f, rel_id="a.txt", kind=CorpusKind.ROOTFS_TEXT, bin_id=None,
        chunker=FixedWordChunker(words_per_chunk=500),
    )
    chunks2 = build_chunks_for_file(
        path=f, rel_id="a.txt", kind=CorpusKind.ROOTFS_TEXT, bin_id=None,
        chunker=FixedWordChunker(words_per_chunk=500),
    )
    assert chunks1[0].content_hash == chunks2[0].content_hash


def test_build_chunks_for_file_missing_path_returns_empty(tmp_path: Path) -> None:
    chunks = build_chunks_for_file(
        path=tmp_path / "nope.txt", rel_id="nope.txt", kind=CorpusKind.ROOTFS_TEXT,
        bin_id=None, chunker=FixedWordChunker(words_per_chunk=500),
    )
    assert chunks == []


def test_build_corpus_chunks_combines_rootfs_and_cleaned_c(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "login.asp").write_text(
        " ".join(f"w{i}" for i in range(50)) + " nvram_get(\"admin_password\")", encoding="utf-8"
    )
    (rootfs / "photo.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    stage2_bins = tmp_path / "stage2_binaries"
    bin_dir = stage2_bins / "sbin_httpd__abc123"
    (bin_dir / "cleaned").mkdir(parents=True)
    (bin_dir / "cleaned" / "whole.c").write_text(
        " ".join(f"tok{i}" for i in range(50)), encoding="utf-8"
    )

    config = Stage4ColabConfig(rootfs_dir=rootfs, stage2_binaries_dir=stage2_bins)
    chunks = build_corpus_chunks(config)

    kinds = {c.kind for c in chunks}
    assert kinds == {CorpusKind.ROOTFS_TEXT, CorpusKind.DECOMPILED_C}
    c_chunk = next(c for c in chunks if c.kind is CorpusKind.DECOMPILED_C)
    assert c_chunk.bin_id == "sbin_httpd__abc123"
    assert c_chunk.source_path == "stage2/sbin_httpd__abc123/cleaned/whole.c"
    web_chunk = next(c for c in chunks if c.kind is CorpusKind.ROOTFS_TEXT)
    assert web_chunk.source_path == "login.asp"


def test_build_corpus_chunks_empty_inputs_yield_no_chunks(tmp_path: Path) -> None:
    config = Stage4ColabConfig(
        rootfs_dir=tmp_path / "empty_rootfs", stage2_binaries_dir=tmp_path / "empty_stage2"
    )
    assert build_corpus_chunks(config) == []
