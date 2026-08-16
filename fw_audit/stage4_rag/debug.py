"""Debug module — inspect and verify each Stage 4 component in isolation,
without re-running (or paying for) the whole pipeline.

Every function here reads from an already-built local corpus / already-run
driver output — none of them re-embed the corpus or persist anything back
into the pipeline's own `queries/`/`retrieval/`/`taint/` directories (the
one exception, `debug_corpus`, only reads). `debug_taint` runs a real
C3->C4->C5 pass but is explicitly a **dry run**: nothing it produces is
written to `stage4_dir`'s tracked output paths.

Wired into `runner.py debug {corpus,parity,sinks,query,retrieve,search,taint}`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from fw_audit.config.settings import Settings, get_settings
from fw_audit.stage4_rag import layout
from fw_audit.stage4_rag.query.planner import generate_queries
from fw_audit.stage4_rag.query.schemas import MultiQueryPlan, SearchQuery
from fw_audit.stage4_rag.retrieval.engine import RetrievalBundle, build_c5_prompt, retrieve
from fw_audit.stage4_rag.retrieval.store import load_embedder, load_local_collection
from fw_audit.stage4_rag.sink_index import (
    DEFAULT_DECISIONS,
    SinkCandidate,
    discover_sink_candidates,
)
from fw_audit.stage4_rag.taint.analyst import analyze_taint

logger = logging.getLogger("fw_audit.stage4_rag.debug")


@dataclass(frozen=True)
class CorpusStats:
    total_chunks: int
    chunks_by_kind: dict[str, int]
    sample_ids: list[str]
    embedding_dim: int | None


def debug_corpus(db_subfolder: Path, *, settings: Settings | None = None) -> CorpusStats:
    """Loads the local Chroma collection and reports its size, a kind
    breakdown, a handful of sample chunk ids, and the embedding
    dimensionality actually stored (cross-checked against what a fresh
    `stage4_embedding_model` load would produce, by the caller if desired —
    this function only reports what's IN the collection)."""
    settings = settings or get_settings()
    stage4_dir_ = layout.stage4_dir(db_subfolder)
    collection = load_local_collection(
        layout.chroma_dir(stage4_dir_), collection_name=settings.stage4_chroma_collection_name
    )
    count = collection.count()
    sample = collection.peek(limit=min(5, count)) if count else {"ids": [], "metadatas": []}
    kinds: dict[str, int] = {}
    for metadata in sample.get("metadatas") or []:
        kind = metadata.get("kind", "?")
        kinds[kind] = kinds.get(kind, 0) + 1
    embeddings = sample.get("embeddings")
    dim = len(embeddings[0]) if embeddings is not None and len(embeddings) else None
    return CorpusStats(
        total_chunks=count,
        chunks_by_kind=kinds,
        sample_ids=list(sample.get("ids") or [])[:5],
        embedding_dim=dim,
    )


@dataclass(frozen=True)
class EmbeddingParityCheck:
    doc_text: str
    query_text: str
    cosine_similarity: float


def debug_embedding_parity(*, settings: Settings | None = None) -> EmbeddingParityCheck:
    """Sanity-checks the query/document embedding parity requirement:
    embeds a sample document string and a semantically related query
    string, reports their cosine similarity. A healthy result is well above
    0 (typically > 0.3-0.5 for genuinely related text) — near-zero or
    negative similarity signals a broken/mismatched embedder setup."""
    settings = settings or get_settings()
    embedder = load_embedder(settings=settings)

    doc_text = 'nvram_get("admin_password")'
    query_text = "where does the admin password value come from"
    doc_vec = embedder.embed_documents([doc_text])[0]
    query_vec = embedder.embed_query(query_text)

    similarity = _cosine_similarity(doc_vec, query_vec)
    return EmbeddingParityCheck(
        doc_text=doc_text, query_text=query_text, cosine_similarity=similarity
    )


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def debug_sinks(
    db_subfolder: Path, *, decisions: frozenset = DEFAULT_DECISIONS
) -> list[SinkCandidate]:
    """Runs `sink_index.discover_sink_candidates` and returns the result —
    the caller (CLI) prints counts by decision."""
    stage3_dir = db_subfolder / "stage3"
    return discover_sink_candidates(stage3_dir, decisions=decisions)


def _find_candidate(db_subfolder: Path, global_id: str) -> SinkCandidate:
    # DEFAULT_DECISIONS may exclude the finding the caller wants to debug
    # (e.g. a DISCARD-decision finding) — debug tooling should never
    # silently hide an item the user explicitly asked for by id, so this
    # always scans every Decision value rather than reusing debug_sinks'
    # default filter.
    from fw_audit.common.findings import Decision

    all_candidates = discover_sink_candidates(
        db_subfolder / "stage3", decisions=frozenset(Decision)
    )
    for candidate in all_candidates:
        if candidate.global_id == global_id:
            return candidate
    raise ValueError(f"No finding with global_id {global_id!r} found under {db_subfolder}/stage3")


async def debug_query(
    db_subfolder: Path, global_id: str, *, settings: Settings | None = None
) -> MultiQueryPlan:
    """Runs Component 3 only, for one finding."""
    settings = settings or get_settings()
    candidate = _find_candidate(db_subfolder, global_id)
    return await generate_queries(candidate, settings=settings)


async def debug_retrieve(
    db_subfolder: Path, global_id: str, *, settings: Settings | None = None
) -> RetrievalBundle:
    """Runs Components 3+4 for one finding — does not call Component 5."""
    settings = settings or get_settings()
    candidate = _find_candidate(db_subfolder, global_id)
    plan = await generate_queries(candidate, settings=settings)

    stage4_dir_ = layout.stage4_dir(db_subfolder)
    collection = load_local_collection(
        layout.chroma_dir(stage4_dir_), collection_name=settings.stage4_chroma_collection_name
    )
    embedder = load_embedder(settings=settings)
    return retrieve(plan, collection=collection, embedder=embedder, top_k=settings.stage4_top_k)


def debug_search(
    db_subfolder: Path,
    queries: list[str],
    *,
    top_k: int | None = None,
    settings: Settings | None = None,
) -> RetrievalBundle:
    """Runs Component 4 directly against hand-written query strings —
    bypasses Component 3's LLM entirely (no `finding`/`--gid` needed, no
    LLM call, no cost). For testing retrieval quality/coverage against
    queries you write yourself before trusting C3 to generate similar ones.

    `top_k` overrides `settings.stage4_top_k` for this call only (results
    are merged/deduped across all `queries`, same as real retrieval — so
    passing more queries and/or a higher `top_k` widens the result set;
    see `retrieval.engine.retrieve`'s docstring for the merge/dedupe rule).
    """
    settings = settings or get_settings()
    plan = MultiQueryPlan(
        finding_id="ad-hoc-search",
        queries=[SearchQuery(query_text=q, focus="user-provided") for q in queries],
    )
    stage4_dir_ = layout.stage4_dir(db_subfolder)
    collection = load_local_collection(
        layout.chroma_dir(stage4_dir_), collection_name=settings.stage4_chroma_collection_name
    )
    embedder = load_embedder(settings=settings)
    effective_top_k = top_k if top_k is not None else settings.stage4_top_k
    return retrieve(plan, collection=collection, embedder=embedder, top_k=effective_top_k)


async def debug_taint(
    db_subfolder: Path, global_id: str, *, settings: Settings | None = None
):
    """Runs the full C3->C4->C5 pass for one finding as a **dry run** —
    prints/returns the `TaintPathReport` without writing it to
    `stage4/taint/<gid>.json` (use `fw-trace run` for the persisting
    version)."""
    settings = settings or get_settings()
    candidate = _find_candidate(db_subfolder, global_id)
    bundle = await debug_retrieve(db_subfolder, global_id, settings=settings)
    c5_prompt = build_c5_prompt(bundle, candidate)
    return await analyze_taint(c5_prompt, global_id=global_id, settings=settings)


__all__ = [
    "CorpusStats",
    "EmbeddingParityCheck",
    "debug_corpus",
    "debug_embedding_parity",
    "debug_query",
    "debug_retrieve",
    "debug_search",
    "debug_sinks",
    "debug_taint",
]
