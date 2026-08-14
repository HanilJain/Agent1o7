"""Stage 4, Components 1+2 — Chunking + Embedding + Vector Store.

**This file is designed to be pasted directly into a Google Colab cell.**
It is deliberately dependency-light — stdlib plus `chromadb` and a sentence-
embedding library only, **zero `fw_audit.*` imports** — so the exact copy
committed here is also the exact copy that runs standalone in Colab with
no local package install. See `MASTERPLAN_STAGE4.md` §5-6 for the full
architecture and rationale; the companion `stage4_colab.ipynb` in this
directory wraps this same code in narrative cells (install/upload/run/
download).

Why `print()` instead of `logging` here (deliberate exception to the rest
of this repo's convention): this module's only "caller" is a human running
notebook cells top to bottom — Colab renders `print()` output inline under
each cell as it happens, which is exactly the progress feedback a manual
corpus-build run needs. Every other stage in this repo uses structured
logging/return values instead, because those run unattended; this one
doesn't.

Deployment split (see MASTERPLAN_STAGE4.md §2 for the full picture)
--------------------------------------------------------------------------
* **C1 (chunking)** and **C2 (embedding + vector store)** — this file —
  run once (or periodically) in Colab, given Stage 1's rootfs directory
  and Stage 2's `stage2/binaries/` directory as input.
* Output is a zip containing the persisted Chroma directory plus
  `corpus_report.json`. Download it, unzip under
  `<db_subfolder>/stage4/`, and Components 3-6 (local, elsewhere in this
  package) pick up from there.

v1 is deliberately basic
--------------------------------------------------------------------------
- Chunking is a single fixed-size strategy (~500 words/chunk, no overlap
  by default) applied uniformly to every included file, regardless of
  file type. A smarter, content-aware strategy is a documented future
  iteration — see the `ChunkStrategy` protocol below, which exists
  precisely so it can be swapped later without touching Components 3-6.
- Retrieval quality depends on embedding queries (Component 4, local) with
  the *exact* same recipe used here for documents — see `Qwen3Embedder`'s
  docstring for the instruction-template detail that a local port MUST
  mirror.

Colab quick start
--------------------------------------------------------------------------
```python
# Cell 1 — install (Colab-only; never added to this package's own extras)
!pip install -q chromadb sentence-transformers

# Cell 2 — paste this entire file's contents, or:
#   !wget -q <raw-github-url-to-this-file> -O chunk_and_embed.py
#   %run chunk_and_embed.py

# Cell 3 — configure and run
config = Stage4ColabConfig(
    rootfs_dir=Path("/content/squashfs-root"),          # Stage 1 output
    stage2_binaries_dir=Path("/content/stage2/binaries"),  # Stage 2 output
    output_dir=Path("/content/stage4_corpus_build"),
)
zip_path = run(config)

# Cell 4 — download
from google.colab import files
files.download(str(zip_path))
```
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol

# ============================================================================
# Configuration
# ============================================================================


@dataclass
class Stage4ColabConfig:
    """Every path is an input the user points at their uploaded/mounted
    Stage 1 and Stage 2 output. Nothing here is read from `fw_audit`'s own
    `Settings` — this script has no dependency on that package."""

    rootfs_dir: Path
    """Stage 1's extracted rootfs (e.g. `.../binwalk_1/_input.pkgtb.extracted/squashfs-root`)."""
    stage2_binaries_dir: Path
    """Stage 2's `<db_subfolder>/stage2/binaries/` directory."""
    output_dir: Path = Path("./stage4_corpus_build")
    chunk_words: int = 500
    chunk_overlap_words: int = 0
    # TODO: user specified the Qwen3-Embedding 3B-parameter tier — confirm
    # the exact Hugging Face repo id/tag under https://huggingface.co/Qwen
    # before running and update this default. Left as an explicit
    # placeholder rather than silently substituting a different size.
    embedding_model: str = "Qwen/Qwen3-Embedding-3B"  # TODO: verify this tag exists
    embedding_device: str | None = None  # None -> sentence-transformers auto-picks CUDA if present
    chroma_collection_name: str = "stage4_corpus"
    embed_batch_size: int = 32


# ============================================================================
# C1 — File classification (Stage 1 rootfs: human-readable vs needs-decompile)
# ============================================================================


class CorpusKind(str, Enum):  # noqa: UP042 — str+Enum (not StrEnum) matches this project's convention
    """Tagged into Chroma metadata only — v1 chunking treats every kind
    identically (see `FixedWordChunker`); this is for later filtering, not
    strategy dispatch."""

    DECOMPILED_C = "DECOMPILED_C"
    ROOTFS_TEXT = "ROOTFS_TEXT"


# Kept as plain, easily-edited module-level sets rather than buried in
# logic, per the brief: "make list of them easily parsing". Extend these
# two sets first if a corpus is misclassifying real files.
ALLOWED_TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".html", ".htm", ".asp", ".aspx", ".js", ".css", ".txt", ".xml",
        ".json", ".conf", ".cfg", ".ini", ".sh", ".php", ".cgi", ".lua",
    }
)
"""Extensions treated as human-readable text — embedded as-is."""

SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".so", ".ko", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".bin",
        ".o", ".a", ".gz", ".tar", ".zip", ".woff", ".ttf", ".ico",
    }
)
"""Extensions explicitly skipped: binaries needing Ghidra/IDA decompilation
first (`.so`/`.ko`/etc.), or non-text assets that are technically
"readable" by extension but not source/text (`.png`/`.svg`/`.jpg`)."""

ELF_MAGIC = b"\x7fELF"


def classify_rootfs_file(path: Path) -> bool:
    """True if `path` should be embedded, False if it should be skipped.

    Extension allow/deny lists are checked first (cheap); an ELF
    magic-byte check backstops both an allow-listed extension (firmware
    occasionally ships a real binary under a misleading name) and any
    extension not on either list, via a printable-byte heuristic.
    """
    suffix = path.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return False
    try:
        with path.open("rb") as f:
            head = f.read(4096)
    except OSError:
        return False
    if head.startswith(ELF_MAGIC):
        return False
    if suffix in ALLOWED_TEXT_EXTENSIONS:
        return True
    return _looks_like_text(head)


def _looks_like_text(sample: bytes) -> bool:
    """Crude printable-byte-ratio heuristic for extensionless or
    unrecognized-extension files. Not a substitute for the extension
    lists above — just a fallback so a stray text file with no/odd
    extension isn't silently dropped."""
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
    return (printable / len(sample)) > 0.85


def discover_rootfs_files(rootfs_dir: Path) -> Iterator[Path]:
    """Walks `rootfs_dir`, yielding every file `classify_rootfs_file`
    accepts. Skips symlinks outright (firmware rootfs symlinks routinely
    point at absolute paths meaningless outside the original device, and
    this script never needs to follow them to do its job).

    A real extracted rootfs on a Windows host routinely contains entries
    `stat()` cannot resolve at all (device nodes, dangling symlinks,
    reparse points the OS doesn't understand) — `Path.is_file()`/
    `.is_symlink()` raise `OSError` for these rather than returning
    `False`, so both are wrapped rather than trusted to fail closed.
    """
    if not rootfs_dir.is_dir():
        return
    for path in rootfs_dir.rglob("*"):
        try:
            if path.is_symlink() or not path.is_file():
                continue
        except OSError:
            continue
        if classify_rootfs_file(path):
            yield path


def discover_cleaned_c_files(stage2_binaries_dir: Path) -> Iterator[tuple[str, Path]]:
    """Yields `(bin_id, cleaned_whole_c_path)` for every binary with a
    persisted `cleaned/whole.c` — mirrors the path shape of
    `stage2_extraction.layout.cleaned_whole_c`
    (`stage2/binaries/<bin_id>/cleaned/whole.c`) without importing it, per
    this file's zero-`fw_audit`-dependency constraint. A binary Stage 2
    skipped cleaning for (e.g. the `stage2` extra wasn't installed there)
    simply has no `cleaned/` directory and is silently skipped here too —
    consistent with how every other stage treats that gap."""
    if not stage2_binaries_dir.is_dir():
        return
    for bin_dir in sorted(stage2_binaries_dir.iterdir()):
        if not bin_dir.is_dir():
            continue
        whole_c = bin_dir / "cleaned" / "whole.c"
        if whole_c.is_file():
            yield bin_dir.name, whole_c


# ============================================================================
# C1 — Chunking
# ============================================================================


class ChunkStrategy(Protocol):
    """Seam for a smarter strategy later (function-boundary-aware for C,
    template-block-aware for `.asp`, ...) — v1 ships exactly one
    implementation, `FixedWordChunker`, applied uniformly regardless of
    `CorpusKind`."""

    def chunk(self, text: str) -> list[str]: ...


@dataclass
class FixedWordChunker:
    """v1 chunking strategy: split on whitespace-delimited words, roughly
    `words_per_chunk` words per chunk. No function/AST/HTML-structure
    awareness — deliberately basic, see this module's docstring."""

    words_per_chunk: int = 500
    overlap_words: int = 0

    def chunk(self, text: str) -> list[str]:
        words = text.split()
        if not words:
            return []
        step = max(1, self.words_per_chunk - self.overlap_words)
        pieces: list[str] = []
        start = 0
        while start < len(words):
            piece = words[start : start + self.words_per_chunk]
            if not piece:
                break
            pieces.append(" ".join(piece))
            if start + self.words_per_chunk >= len(words):
                break
            start += step
        return pieces


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    """`<safe-source-id>#<ordinal:04d>` — mirrors Stage 3's chunk_id shape."""
    source_path: str
    """Forward-slash relative path: rootfs-relative for ROOTFS_TEXT, or
    `stage2/<bin_id>/cleaned/whole.c` for DECOMPILED_C."""
    kind: CorpusKind
    bin_id: str | None
    ordinal: int
    text: str
    content_hash: str
    """First 16 hex chars of sha256(text) — used to build a content-hash
    Chroma id, so re-running against unchanged input upserts identical ids
    with identical content rather than duplicating (idempotent re-index)."""


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


_UNSAFE_ID_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_id_component(value: str) -> str:
    return _UNSAFE_ID_RE.sub("_", value).strip("_")


def build_chunks_for_file(
    *,
    path: Path,
    rel_id: str,
    kind: CorpusKind,
    bin_id: str | None,
    chunker: ChunkStrategy,
) -> list[Chunk]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    safe_rel = _safe_id_component(rel_id)
    chunks: list[Chunk] = []
    for ordinal, piece in enumerate(chunker.chunk(text)):
        chunks.append(
            Chunk(
                chunk_id=f"{safe_rel}#{ordinal:04d}",
                source_path=rel_id,
                kind=kind,
                bin_id=bin_id,
                ordinal=ordinal,
                text=piece,
                content_hash=_content_hash(piece),
            )
        )
    return chunks


def build_corpus_chunks(config: Stage4ColabConfig) -> list[Chunk]:
    """Discovers + chunks the full corpus: Stage 1 rootfs text files plus
    Stage 2 cleaned decompiled C, one uniform chunking strategy across
    both (see this module's docstring for why)."""
    chunker = FixedWordChunker(
        words_per_chunk=config.chunk_words, overlap_words=config.chunk_overlap_words
    )
    chunks: list[Chunk] = []

    for path in discover_rootfs_files(config.rootfs_dir):
        rel = path.relative_to(config.rootfs_dir).as_posix()
        chunks.extend(
            build_chunks_for_file(
                path=path, rel_id=rel, kind=CorpusKind.ROOTFS_TEXT, bin_id=None, chunker=chunker
            )
        )

    for bin_id, whole_c in discover_cleaned_c_files(config.stage2_binaries_dir):
        rel = f"stage2/{bin_id}/cleaned/whole.c"
        chunks.extend(
            build_chunks_for_file(
                path=whole_c,
                rel_id=rel,
                kind=CorpusKind.DECOMPILED_C,
                bin_id=bin_id,
                chunker=chunker,
            )
        )

    return chunks


# ============================================================================
# C2 — Embedding (Qwen3) + ChromaDB
# ============================================================================

QWEN3_QUERY_INSTRUCTION = (
    "Given a security-relevant code search query, retrieve firmware source "
    "code or configuration text that is semantically relevant to the query."
)
"""Qwen3-Embedding's documented usage recipe instruction-templates QUERY
text (not document text) for retrieval tasks — `Instruct: {task}\\nQuery:
{text}`. Applied in `embed_query` below, never in `embed_documents`.
**Component 4 (local retrieval, not in this file) MUST embed its queries
with this exact same instruction string and template** — any drift here
silently degrades retrieval quality without raising an error, since
mismatched-but-valid-shaped vectors still "work", just badly."""


class Qwen3Embedder:
    """Thin wrapper around a Qwen3-Embedding checkpoint via
    `sentence-transformers`, which is what the official Qwen3-Embedding
    model cards recommend loading through — it handles the model's
    pooling internally, so this wrapper deliberately doesn't reimplement
    pooling logic that could drift from the model card.

    Imports `sentence_transformers` lazily (inside `__init__`, not at
    module level) so importing this *module* — e.g. for the classifier/
    chunker unit tests — never requires the heavy ML dependency to be
    installed.
    """

    def __init__(self, model_name: str, device: str | None = None):
        from sentence_transformers import SentenceTransformer

        self.model_name = model_name
        self._model = SentenceTransformer(model_name, device=device)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        vectors = self._model.encode(
            texts, batch_size=32, show_progress_bar=False, normalize_embeddings=True
        )
        return vectors.tolist()

    def embed_query(self, text: str) -> list[float]:
        instructed = f"Instruct: {QWEN3_QUERY_INSTRUCTION}\nQuery: {text}"
        vectors = self._model.encode([instructed], normalize_embeddings=True)
        return vectors[0].tolist()


def get_or_create_collection(*, persist_dir: Path, collection_name: str):
    """Lazy `chromadb` import — same reasoning as `Qwen3Embedder`."""
    import chromadb

    persist_dir.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(persist_dir))
    return client.get_or_create_collection(
        name=collection_name, metadata={"hnsw:space": "cosine"}
    )


def embed_and_upsert(
    *, chunks: list[Chunk], embedder: Qwen3Embedder, collection, batch_size: int = 32
) -> int:
    """Idempotent: ids are content-hash-derived (`<chunk_id>::<content_hash>`),
    so re-running against unchanged input upserts the same ids with the
    same content rather than duplicating."""
    upserted = 0
    for start in range(0, len(chunks), batch_size):
        batch = chunks[start : start + batch_size]
        ids = [f"{c.chunk_id}::{c.content_hash}" for c in batch]
        docs = [c.text for c in batch]
        metadatas = [
            {
                "source_path": c.source_path,
                "kind": c.kind.value,
                "bin_id": c.bin_id or "",
                "chunk_id": c.chunk_id,
                "ordinal": c.ordinal,
            }
            for c in batch
        ]
        embeddings = embedder.embed_documents(docs)
        collection.upsert(ids=ids, embeddings=embeddings, documents=docs, metadatas=metadatas)
        upserted += len(batch)
        print(f"  [C2] embedded+upserted {upserted}/{len(chunks)} chunks")
    return upserted


# ============================================================================
# Corpus report + packaging for download
# ============================================================================


def write_corpus_report(
    *, chunks: list[Chunk], config: Stage4ColabConfig, report_path: Path
) -> dict:
    by_kind: dict[str, int] = {}
    files_seen: set[str] = set()
    for c in chunks:
        by_kind[c.kind.value] = by_kind.get(c.kind.value, 0) + 1
        files_seen.add(c.source_path)
    report = {
        "schema_version": 1,
        "chunk_words": config.chunk_words,
        "chunk_overlap_words": config.chunk_overlap_words,
        "embedding_model": config.embedding_model,
        "chroma_collection_name": config.chroma_collection_name,
        "total_files": len(files_seen),
        "total_chunks": len(chunks),
        "chunks_by_kind": by_kind,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def package_for_download(
    *, chroma_persist_dir: Path, corpus_report_path: Path, zip_path: Path
) -> Path:
    """Zips the persisted Chroma directory + `corpus_report.json` into one
    archive. Local unzip target is `<db_subfolder>/stage4/` — the zip's
    internal layout (`chroma/...`, `corpus_report.json` at the root)
    matches that directly, so `unzip stage4_corpus.zip -d stage4/` is all
    a local run needs."""
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in chroma_persist_dir.rglob("*"):
            if path.is_file():
                zf.write(path, arcname=str(Path("chroma") / path.relative_to(chroma_persist_dir)))
        zf.write(corpus_report_path, arcname="corpus_report.json")
    return zip_path


# ============================================================================
# Entry point
# ============================================================================


def run(config: Stage4ColabConfig) -> Path:
    """Runs C1 (discover+chunk) then C2 (embed+index+package) end to end.
    Returns the path to the zip ready for download. See this module's
    docstring for the Colab cell-by-cell usage."""
    print(f"[C1] rootfs:              {config.rootfs_dir}")
    print(f"[C1] stage2 binaries dir: {config.stage2_binaries_dir}")
    chunks = build_corpus_chunks(config)
    print(f"[C1] {len(chunks)} chunks discovered")
    if not chunks:
        print("[C1] WARNING: zero chunks — check the two input paths above")

    config.output_dir.mkdir(parents=True, exist_ok=True)
    chroma_dir = config.output_dir / "chroma"
    report_path = config.output_dir / "corpus_report.json"

    print(f"[C2] loading embedding model: {config.embedding_model}")
    embedder = Qwen3Embedder(config.embedding_model, device=config.embedding_device)

    print(f"[C2] embedding + upserting into Chroma collection '{config.chroma_collection_name}'")
    collection = get_or_create_collection(
        persist_dir=chroma_dir, collection_name=config.chroma_collection_name
    )
    embed_and_upsert(
        chunks=chunks, embedder=embedder, collection=collection, batch_size=config.embed_batch_size
    )

    report = write_corpus_report(chunks=chunks, config=config, report_path=report_path)
    print(f"[C2] corpus_report.json: {json.dumps(report, indent=2)}")

    zip_path = config.output_dir / "stage4_corpus.zip"
    package_for_download(
        chroma_persist_dir=chroma_dir, corpus_report_path=report_path, zip_path=zip_path
    )
    print(f"[done] {zip_path} ready for download")
    return zip_path


if __name__ == "__main__":
    # Local convenience entry point (e.g. testing this file's C1+C2 logic
    # outside Colab, against a real on-disk run) — not how Colab itself
    # invokes this file; Colab pastes the cell and calls `run(config)`
    # directly (see the Colab quick start in this module's docstring).
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rootfs", required=True, type=Path, help="Stage 1 rootfs directory")
    parser.add_argument(
        "--stage2-binaries", required=True, type=Path, help="Stage 2 stage2/binaries/ directory"
    )
    parser.add_argument("--output", default=Path("./stage4_corpus_build"), type=Path)
    parser.add_argument("--chunk-words", default=500, type=int)
    parser.add_argument("--embedding-model", default="Qwen/Qwen3-Embedding-3B")
    args = parser.parse_args()

    run(
        Stage4ColabConfig(
            rootfs_dir=args.rootfs,
            stage2_binaries_dir=args.stage2_binaries,
            output_dir=args.output,
            chunk_words=args.chunk_words,
            embedding_model=args.embedding_model,
        )
    )
