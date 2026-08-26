"""Component 4's search + merge/dedupe + C5 prompt assembly.

v1: for each Component 3 query, embed it (via the parity-matched embedder
from `store.py`) and run a plain top-k similarity search against the
collection; merge results across all queries in a plan, deduping by chunk id
(keeping the best — lowest — distance and noting every query that matched
it). No RRF/hybrid fusion — see this package's `__init__.py` docstring.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fw_audit.observability import span
from fw_audit.stage4_rag.query.schemas import MultiQueryPlan
from fw_audit.stage4_rag.sink_index import SinkCandidate


@dataclass(frozen=True)
class RetrievedChunk:
    chunk_id: str
    source_path: str
    kind: str
    bin_id: str | None
    text: str
    distance: float
    """Cosine distance to the best-matching query (lower = more similar)."""
    matched_queries: tuple[str, ...]
    """`query_text` of every Component 3 query that retrieved this chunk in
    its own top-k — a chunk matched by multiple queries is a stronger
    signal than one matched by only one."""


@dataclass(frozen=True)
class RetrievalBundle:
    global_id: str
    chunks: tuple[RetrievedChunk, ...]


def retrieve(
    plan: MultiQueryPlan,
    *,
    collection: Any,
    embedder: Any,
    top_k: int,
) -> RetrievalBundle:
    """Runs one top-k similarity search per query in `plan`, merges and
    dedupes the results by `chunk_id`.

    Wrapped in a `run_type="retriever"` span (a no-op unless tracing is
    on): Chroma's `collection.query(...)` and the embedder are raw SDK
    calls, invisible to LangSmith's automatic LangChain instrumentation, so
    without this wrapping "was the right chunk even retrieved?" has no
    answer short of manually diffing `queries/<gid>.json` against
    `retrieval/<gid>.json`. Each query gets its own child span recording
    the returned chunk ids and distances — a uniformly high distance across
    every query is the signature of the embedder-parity drift
    `stage4_rag/CLAUDE.md` calls out as otherwise silent.
    """
    best: dict[str, RetrievedChunk] = {}
    matched_by: dict[str, list[str]] = {}

    with span(
        "stage4.c4.retrieve",
        run_type="retriever",
        inputs={"finding_id": plan.finding_id, "queries": [q.query_text for q in plan.queries]},
    ) as retrieve_run:
        for query in plan.queries:
            with span(
                "stage4.c4.embed_and_search",
                run_type="retriever",
                inputs={"query_text": query.query_text, "top_k": top_k},
            ) as query_run:
                query_vector = embedder.embed_query(query.query_text)
                results = collection.query(query_embeddings=[query_vector], n_results=top_k)
                if query_run is not None:
                    ids = (results.get("ids") or [[]])[0]
                    distances = (results.get("distances") or [[]])[0]
                    query_run.end(
                        outputs={
                            "chunk_ids": list(ids),
                            "distances": [float(d) for d in distances],
                        }
                    )
            _merge_query_results(results, query.query_text, best=best, matched_by=matched_by)

        merged = tuple(
            RetrievedChunk(
                chunk_id=chunk.chunk_id,
                source_path=chunk.source_path,
                kind=chunk.kind,
                bin_id=chunk.bin_id,
                text=chunk.text,
                distance=chunk.distance,
                matched_queries=tuple(matched_by[chunk.chunk_id]),
            )
            for chunk in sorted(best.values(), key=lambda c: c.distance)
        )

        if retrieve_run is not None:
            retrieve_run.end(
                outputs={
                    "chunk_ids": [c.chunk_id for c in merged],
                    "distances": [c.distance for c in merged],
                    "matched_queries": {c.chunk_id: list(c.matched_queries) for c in merged},
                }
            )

    return RetrievalBundle(global_id=plan.finding_id, chunks=merged)


def _merge_query_results(
    results: dict[str, Any],
    query_text: str,
    *,
    best: dict[str, RetrievedChunk],
    matched_by: dict[str, list[str]],
) -> None:
    ids = (results.get("ids") or [[]])[0]
    documents = (results.get("documents") or [[]])[0]
    metadatas = (results.get("metadatas") or [[]])[0]
    distances = (results.get("distances") or [[]])[0]

    # strict=False: Chroma's four parallel result lists should always be
    # equal length, but a malformed/partial response degrading retrieval
    # (fewer chunks) is preferable to a crash here.
    for doc_id, document, metadata, distance in zip(
        ids, documents, metadatas, distances, strict=False
    ):
        chunk_id = metadata.get("chunk_id", doc_id)
        matched_by.setdefault(chunk_id, []).append(query_text)
        existing = best.get(chunk_id)
        if existing is not None and existing.distance <= distance:
            continue
        best[chunk_id] = RetrievedChunk(
            chunk_id=chunk_id,
            source_path=metadata.get("source_path", ""),
            kind=metadata.get("kind", ""),
            bin_id=metadata.get("bin_id") or None,
            text=document,
            distance=float(distance),
            matched_queries=(),  # filled in by the caller once merging is done
        )


def build_c5_prompt(bundle: RetrievalBundle, candidate: SinkCandidate) -> str:
    """Assembles Component 5's input: retrieved context (C4) + the queries
    that found it (C3) + the original Stage 3 finding — the exact formula
    from `MASTERPLAN_STAGE4.md` §8."""
    finding = candidate.finding
    context_blocks = []
    for chunk in bundle.chunks:
        header = f"[{chunk.kind}] {chunk.source_path}"
        if chunk.bin_id:
            header += f" (bin_id={chunk.bin_id})"
        header += f" — matched by: {', '.join(chunk.matched_queries)}"
        context_blocks.append(f"{header}\n{chunk.text}")
    context = "\n\n---\n\n".join(context_blocks) if context_blocks else "(no chunks retrieved)"

    return (
        f"# Original Stage 3 finding ({candidate.global_id})\n"
        f"title: {finding.title}\n"
        f"sink: {finding.sink.expression} ({finding.sink.type})\n"
        f"source (guessed): {finding.source.expression} ({finding.source.type})\n"
        f"decision: {finding.decision.value}\n"
        f"missing_context: {finding.missing_context}\n"
        f"why_vulnerable: {finding.why_vulnerable}\n\n"
        f"# Retrieved context\n\n{context}\n"
    )


__all__ = ["RetrievalBundle", "RetrievedChunk", "build_c5_prompt", "retrieve"]
