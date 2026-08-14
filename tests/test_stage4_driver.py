"""Tests for `fw_audit.stage4_rag.driver` — the C6 worker-pool loop.
Mocks C3 (`generate_queries`), C4 (`retrieve`/store loading), and C5
(`analyze_taint`) so this never needs real chromadb/sentence-transformers/
LLM calls — same discipline as `tests/test_stage3_chunk_queue.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fw_audit.common.findings import (
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
from fw_audit.stage4_rag import driver, layout
from fw_audit.stage4_rag.errors import Stage4InputError
from fw_audit.stage4_rag.query.planner import QueryPlannerUnavailableError
from fw_audit.stage4_rag.query.schemas import MultiQueryPlan, SearchQuery
from fw_audit.stage4_rag.retrieval.engine import RetrievalBundle


def _finding(finding_id: str) -> Finding:
    return Finding(
        finding_id=finding_id,
        title="t",
        category="command_execution",
        severity=Severity(impact=3, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=Decision.ESCALATE,
        evidence_span=EvidenceSpan(function_id="f", line_start=1, line_end=2, code="x"),
        source=FindingSource(expression="s", type="NVRAM", attacker_control="UNKNOWN"),
        sink=FindingSink(expression="system(s)", type="COMMAND_EXECUTION"),
        security_condition="c",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )


def _write_findings(stage3_dir: Path, chunk_id: str, finding_ids: list[str]) -> None:
    from fw_audit.common.findings import AnalysisReport

    findings_dir = stage3_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    report = AnalysisReport(
        chunk_id=chunk_id, findings=[_finding(fid) for fid in finding_ids], checked_categories=[]
    )
    filename = f"{chunk_id.replace('#', '__')}.json"
    (findings_dir / filename).write_text(report.model_dump_json(indent=2), encoding="utf-8")


def _patch_pipeline(monkeypatch, *, query_side_effect=None, taint_side_effect=None):
    async def fake_generate_queries(candidate, *, settings):
        if query_side_effect is not None:
            result = query_side_effect(candidate)
            if isinstance(result, Exception):
                raise result
        return MultiQueryPlan(
            finding_id=candidate.global_id, queries=[SearchQuery(query_text="q", focus="f")]
        )

    def fake_retrieve(plan, *, collection, embedder, top_k):
        return RetrievalBundle(global_id=plan.finding_id, chunks=())

    async def fake_analyze_taint(prompt_text, *, global_id, settings):
        if taint_side_effect is not None:
            result = taint_side_effect(global_id)
            if isinstance(result, Exception):
                raise result
        return TaintPathReport(finding_id=global_id, resolved=False, taint_paths=[])

    monkeypatch.setattr(driver, "generate_queries", fake_generate_queries)
    monkeypatch.setattr(driver, "retrieve", fake_retrieve)
    monkeypatch.setattr(driver, "analyze_taint", fake_analyze_taint)
    monkeypatch.setattr(
        driver, "load_local_collection", lambda chroma_dir, *, collection_name: object()
    )
    monkeypatch.setattr(driver, "load_embedder", lambda *, settings: object())


async def test_run_queue_no_findings_dir_raises_input_error(tmp_path):
    with pytest.raises(Stage4InputError):
        await driver.run_queue(
            db_subfolder=tmp_path / "db" / "fw", settings=Settings(_env_file=None)
        )


async def test_run_queue_no_findings_yields_no_targets(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    (db_subfolder / "stage3" / "findings").mkdir(parents=True)
    _patch_pipeline(monkeypatch)

    summary = await driver.run_queue(db_subfolder=db_subfolder, settings=Settings(_env_file=None))

    assert summary.status == "no_targets"
    assert summary.total_findings == 0


async def test_run_queue_end_to_end_persists_all_three_outputs(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder / "stage3", "bin#0000", ["c1", "c2"])
    _patch_pipeline(monkeypatch)

    summary = await driver.run_queue(
        db_subfolder=db_subfolder, settings=Settings(_env_file=None, stage4_workers=2)
    )

    assert summary.status == "completed"
    assert summary.total_findings == 2
    assert summary.total_completed == 2
    assert summary.total_failed == 0

    stage4_dir = layout.stage4_dir(db_subfolder)
    for gid in ("bin#0000::c1", "bin#0000::c2"):
        assert (layout.queries_dir(stage4_dir) / layout.query_plan_filename(gid)).is_file()
        assert (layout.retrieval_dir(stage4_dir) / layout.retrieval_filename(gid)).is_file()
        assert (layout.taint_dir(stage4_dir) / layout.taint_filename(gid)).is_file()

    summary_path = layout.stage4_summary_path(stage4_dir)
    assert summary_path.is_file()
    written = json.loads(summary_path.read_text(encoding="utf-8"))
    assert written["total_completed"] == 2


async def test_run_queue_only_filters_to_selected_global_ids(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder / "stage3", "bin#0000", ["c1", "c2"])
    _patch_pipeline(monkeypatch)

    summary = await driver.run_queue(
        db_subfolder=db_subfolder,
        settings=Settings(_env_file=None),
        only_global_ids=frozenset({"bin#0000::c1"}),
    )

    assert summary.total_findings == 1
    assert summary.findings[0].global_id == "bin#0000::c1"


async def test_run_queue_permanent_failure_recorded_not_completed(tmp_path, monkeypatch):
    db_subfolder = tmp_path / "db" / "fw"
    _write_findings(db_subfolder / "stage3", "bin#0000", ["c1"])
    _patch_pipeline(
        monkeypatch,
        query_side_effect=lambda candidate: QueryPlannerUnavailableError("boom"),
    )

    summary = await driver.run_queue(
        db_subfolder=db_subfolder,
        settings=Settings(_env_file=None, stage4_queue_max_attempts=1, stage4_workers=1),
    )

    assert summary.total_completed == 0
    assert summary.total_failed == 1
    assert summary.findings[0].status == "failed"
    assert summary.findings[0].error is not None
