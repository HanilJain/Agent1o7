"""Tests for `fw_audit.stage4_rag.retrieval.engine` — `retrieve()`'s
merge/dedupe and `build_c5_prompt()`. Uses a fake Chroma-shaped collection
and a fake deterministic embedder — no real `chromadb`/`sentence-transformers`
needed, matching this project's "no heavy ML deps for unit tests" convention.
"""

from __future__ import annotations

from fw_audit.common.findings import (
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.stage4_rag.query.schemas import MultiQueryPlan, SearchQuery
from fw_audit.stage4_rag.retrieval.engine import build_c5_prompt, retrieve
from fw_audit.stage4_rag.sink_index import SinkCandidate


class _FakeEmbedder:
    def embed_query(self, text: str) -> list[float]:
        return [float(len(text))]


class _FakeCollection:
    """`query()` returns canned results keyed by call order, mirroring
    chromadb's `query_embeddings`/`n_results` result dict shape:
    `{"ids": [[...]], "documents": [[...]], "metadatas": [[...]], "distances": [[...]]}`.
    """

    def __init__(self, responses: list[dict]) -> None:
        self._responses = list(responses)
        self.calls: list[dict] = []

    def query(self, *, query_embeddings, n_results):
        self.calls.append({"query_embeddings": query_embeddings, "n_results": n_results})
        return self._responses.pop(0)


def _plan(*queries: str) -> MultiQueryPlan:
    return MultiQueryPlan(
        finding_id="bin#0000::c1", queries=[SearchQuery(query_text=q, focus="f") for q in queries]
    )


def _candidate() -> SinkCandidate:
    finding = Finding(
        finding_id="c1",
        title="t",
        category="command_execution",
        severity=Severity(impact=3, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=Decision.CONTEXT_REQUIRED,
        evidence_span=EvidenceSpan(function_id="f", line_start=1, line_end=2, code="x"),
        source=FindingSource(expression="s", type="NVRAM", attacker_control="UNKNOWN"),
        sink=FindingSink(expression="system(s)", type="COMMAND_EXECUTION"),
        security_condition="c",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )
    return SinkCandidate(
        global_id="bin#0000::c1", chunk_id="bin#0000", bin_id="bin", finding=finding
    )


def _meta(chunk_id: str, source_path: str, kind: str, bin_id: str = "") -> dict:
    return {"chunk_id": chunk_id, "source_path": source_path, "kind": kind, "bin_id": bin_id}


def test_retrieve_single_query_returns_sorted_by_distance():
    collection = _FakeCollection(
        [
            {
                "ids": [["a", "b"]],
                "documents": [["doc a", "doc b"]],
                "metadatas": [
                    [
                        _meta("a", "a.c", "DECOMPILED_C", "bin"),
                        _meta("b", "b.asp", "ROOTFS_TEXT"),
                    ]
                ],
                "distances": [[0.5, 0.1]],
            }
        ]
    )

    bundle = retrieve(_plan("q1"), collection=collection, embedder=_FakeEmbedder(), top_k=8)

    assert [c.chunk_id for c in bundle.chunks] == ["b", "a"]  # sorted: 0.1 before 0.5
    assert bundle.chunks[0].matched_queries == ("q1",)
    assert bundle.chunks[0].bin_id is None  # empty string metadata normalized to None


def test_retrieve_merges_and_dedupes_across_queries_keeping_best_distance():
    collection = _FakeCollection(
        [
            {
                "ids": [["a"]],
                "documents": [["doc a"]],
                "metadatas": [[_meta("a", "a.c", "DECOMPILED_C", "bin")]],
                "distances": [[0.8]],
            },
            {
                "ids": [["a"]],
                "documents": [["doc a"]],
                "metadatas": [[_meta("a", "a.c", "DECOMPILED_C", "bin")]],
                "distances": [[0.2]],
            },
        ]
    )

    bundle = retrieve(_plan("q1", "q2"), collection=collection, embedder=_FakeEmbedder(), top_k=8)

    assert len(bundle.chunks) == 1
    assert bundle.chunks[0].distance == 0.2  # kept the better (lower) distance
    assert set(bundle.chunks[0].matched_queries) == {"q1", "q2"}  # matched by both


def test_build_c5_prompt_includes_finding_and_context():
    candidate = _candidate()
    collection = _FakeCollection(
        [
            {
                "ids": [["a"]],
                "documents": [['nvram_get("admin_password")']],
                "metadatas": [[_meta("a", "login.asp", "ROOTFS_TEXT")]],
                "distances": [[0.1]],
            }
        ]
    )
    bundle = retrieve(_plan("q1"), collection=collection, embedder=_FakeEmbedder(), top_k=8)

    prompt = build_c5_prompt(bundle, candidate)

    assert "bin#0000::c1" in prompt
    assert "system(s)" in prompt
    assert "login.asp" in prompt
    assert "nvram_get" in prompt


def test_build_c5_prompt_handles_empty_bundle():
    candidate = _candidate()
    empty_bundle = retrieve(
        _plan(),  # zero queries -> zero collection.query() calls -> empty chunks
        collection=_FakeCollection([]),
        embedder=_FakeEmbedder(),
        top_k=8,
    )
    prompt = build_c5_prompt(empty_bundle, candidate)
    assert "no chunks retrieved" in prompt
