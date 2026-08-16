"""Smoke tests for `fw_audit.stage4_rag.debug` — everything mocked, same
discipline as `test_stage4_driver.py`. Verifies each debug function reads
what it should and (for `debug_taint`) never writes into the pipeline's
tracked `stage4/{queries,retrieval,taint}` output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fw_audit.common.findings import (
    AnalysisReport,
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.common.taint import TaintPathReport
from fw_audit.config.settings import Settings
from fw_audit.stage4_rag import debug as debug_mod
from fw_audit.stage4_rag import layout
from fw_audit.stage4_rag.query.schemas import MultiQueryPlan, SearchQuery
from fw_audit.stage4_rag.retrieval.engine import RetrievalBundle, RetrievedChunk


def _finding(finding_id: str, decision: Decision = Decision.ESCALATE) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="t",
        category="command_execution",
        severity=Severity(impact=3, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=decision,
        evidence_span=EvidenceSpan(function_id="f", line_start=1, line_end=2, code="x"),
        source=FindingSource(expression="s", type="NVRAM", attacker_control="UNKNOWN"),
        sink=FindingSink(expression="system(s)", type="COMMAND_EXECUTION"),
        security_condition="c",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )


def _write_findings(db_subfolder: Path, chunk_id: str, finding_ids: list[str]) -> None:
    findings_dir = db_subfolder / "stage3" / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    report = AnalysisReport(
        chunk_id=chunk_id, findings=[_finding(fid) for fid in finding_ids], checked_categories=[]
    )
    filename = f"{chunk_id.replace('#', '__')}.json"
    (findings_dir / filename).write_text(report.model_dump_json(indent=2), encoding="utf-8")


def test_debug_sinks_lists_candidates(tmp_path):
    _write_findings(tmp_path, "bin#0000", ["c1", "c2"])

    candidates = debug_mod.debug_sinks(tmp_path)

    assert {c.finding.finding_id for c in candidates} == {"c1", "c2"}


def test_find_candidate_finds_by_global_id_even_outside_default_decisions(tmp_path):
    _write_findings(tmp_path, "bin#0000", [])
    findings_dir = tmp_path / "stage3" / "findings"
    from fw_audit.common.findings import AnalysisReport

    report = AnalysisReport(
        chunk_id="bin#0001",
        findings=[_finding("discarded", Decision.DISCARD)],
        checked_categories=[],
    )
    (findings_dir / "bin__0001.json").write_text(
        report.model_dump_json(indent=2), encoding="utf-8"
    )

    found = debug_mod._find_candidate(tmp_path, "bin#0001::discarded")

    assert found.finding.finding_id == "discarded"


def test_find_candidate_missing_raises_value_error(tmp_path):
    _write_findings(tmp_path, "bin#0000", ["c1"])

    with pytest.raises(ValueError, match="No finding with global_id"):
        debug_mod._find_candidate(tmp_path, "bin#0000::nonexistent")


async def test_debug_query_runs_c3_only(tmp_path, monkeypatch):
    _write_findings(tmp_path, "bin#0000", ["c1"])

    async def fake_generate_queries(candidate, *, settings):
        return MultiQueryPlan(
            finding_id=candidate.global_id, queries=[SearchQuery(query_text="q", focus="f")]
        )

    monkeypatch.setattr(debug_mod, "generate_queries", fake_generate_queries)

    plan = await debug_mod.debug_query(tmp_path, "bin#0000::c1")

    assert plan.finding_id == "bin#0000::c1"


async def test_debug_taint_is_a_dry_run_writes_nothing(tmp_path, monkeypatch):
    _write_findings(tmp_path, "bin#0000", ["c1"])

    async def fake_generate_queries(candidate, *, settings):
        return MultiQueryPlan(
            finding_id=candidate.global_id, queries=[SearchQuery(query_text="q", focus="f")]
        )

    def fake_retrieve(plan, *, collection, embedder, top_k):
        return RetrievalBundle(global_id=plan.finding_id, chunks=())

    async def fake_analyze_taint(prompt_text, *, global_id, settings):
        return TaintPathReport(finding_id=global_id, resolved=False, taint_paths=[])

    monkeypatch.setattr(debug_mod, "generate_queries", fake_generate_queries)
    monkeypatch.setattr(debug_mod, "retrieve", fake_retrieve)
    monkeypatch.setattr(debug_mod, "analyze_taint", fake_analyze_taint)
    monkeypatch.setattr(
        debug_mod, "load_local_collection", lambda chroma_dir, *, collection_name: object()
    )
    monkeypatch.setattr(debug_mod, "load_embedder", lambda *, settings: object())

    report = await debug_mod.debug_taint(tmp_path, "bin#0000::c1")

    assert report.finding_id == "bin#0000::c1"
    stage4_dir = layout.stage4_dir(tmp_path)
    assert not (layout.taint_dir(stage4_dir)).exists()
    assert not (layout.queries_dir(stage4_dir)).exists()
    assert not (layout.retrieval_dir(stage4_dir)).exists()


def test_debug_search_bypasses_c3_and_merges_across_raw_queries(tmp_path, monkeypatch):
    def fake_retrieve(plan, *, collection, embedder, top_k):
        assert [q.query_text for q in plan.queries] == ["q1", "q2"]
        assert plan.finding_id == "ad-hoc-search"
        assert top_k == 15
        return RetrievalBundle(
            global_id=plan.finding_id,
            chunks=(
                RetrievedChunk(
                    chunk_id="a",
                    source_path="a.c",
                    kind="DECOMPILED_C",
                    bin_id="bin",
                    text="void f(void) {}",
                    distance=0.1,
                    matched_queries=("q1", "q2"),
                ),
            ),
        )

    monkeypatch.setattr(debug_mod, "retrieve", fake_retrieve)
    monkeypatch.setattr(
        debug_mod, "load_local_collection", lambda chroma_dir, *, collection_name: object()
    )
    monkeypatch.setattr(debug_mod, "load_embedder", lambda *, settings: object())

    bundle = debug_mod.debug_search(tmp_path, ["q1", "q2"], top_k=15)

    assert len(bundle.chunks) == 1
    assert bundle.chunks[0].matched_queries == ("q1", "q2")


def test_debug_search_defaults_top_k_from_settings(tmp_path, monkeypatch):
    seen_top_k = {}

    def fake_retrieve(plan, *, collection, embedder, top_k):
        seen_top_k["value"] = top_k
        return RetrievalBundle(global_id=plan.finding_id, chunks=())

    monkeypatch.setattr(debug_mod, "retrieve", fake_retrieve)
    monkeypatch.setattr(
        debug_mod, "load_local_collection", lambda chroma_dir, *, collection_name: object()
    )
    monkeypatch.setattr(debug_mod, "load_embedder", lambda *, settings: object())

    debug_mod.debug_search(tmp_path, ["q1"], settings=Settings(_env_file=None, stage4_top_k=12))

    assert seen_top_k["value"] == 12


def test_cosine_similarity_identical_vectors_is_one():
    assert debug_mod._cosine_similarity([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)


def test_cosine_similarity_orthogonal_vectors_is_zero():
    assert debug_mod._cosine_similarity([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)


def test_cosine_similarity_zero_vector_returns_zero_not_nan():
    assert debug_mod._cosine_similarity([0.0, 0.0], [1.0, 1.0]) == 0.0
