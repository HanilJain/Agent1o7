"""Tests for `fw_audit.stage4_rag.query.planner` — mirrors
`tests/test_stage3_analyst.py`'s mocking shape exactly."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from fw_audit.common.findings import (
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.config.settings import Settings
from fw_audit.stage4_rag.query.planner import QueryPlannerUnavailableError, generate_queries
from fw_audit.stage4_rag.query.schemas import MultiQueryPlan, SearchQuery
from fw_audit.stage4_rag.sink_index import SinkCandidate

_FINDING = Finding(
    finding_id="candidate_001",
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
_CANDIDATE = SinkCandidate(
    global_id="bin#0000::candidate_001", chunk_id="bin#0000", bin_id="bin", finding=_FINDING
)
_MINIMAL_PLAN = MultiQueryPlan(
    finding_id=_CANDIDATE.global_id,
    queries=[SearchQuery(query_text="q1", focus="f1")],
)


def _fake_llm(*, results=None, side_effect=None):
    if results is not None:
        structured = SimpleNamespace(ainvoke=AsyncMock(side_effect=list(results)))
    else:
        structured = SimpleNamespace(ainvoke=AsyncMock(side_effect=side_effect))
    return SimpleNamespace(with_structured_output=lambda schema: structured)


def _patch_get_llm(monkeypatch, fake_llm) -> None:
    monkeypatch.setattr(
        "fw_audit.stage4_rag.query.planner.get_llm_for_agent",
        lambda role, settings=None: fake_llm,
    )


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


async def test_generate_queries_happy_path(monkeypatch):
    fake_llm = _fake_llm(results=[_MINIMAL_PLAN])
    _patch_get_llm(monkeypatch, fake_llm)

    plan = await generate_queries(_CANDIDATE, settings=_settings())

    assert plan.finding_id == _CANDIDATE.global_id
    assert len(plan.queries) == 1


async def test_generate_queries_overwrites_hallucinated_finding_id(monkeypatch):
    wrong = MultiQueryPlan(finding_id="wrong", queries=[SearchQuery(query_text="q", focus="f")])
    fake_llm = _fake_llm(results=[wrong])
    _patch_get_llm(monkeypatch, fake_llm)

    plan = await generate_queries(_CANDIDATE, settings=_settings())

    assert plan.finding_id == _CANDIDATE.global_id


async def test_generate_queries_repair_retry_succeeds(monkeypatch):
    validation_error = ValidationError.from_exception_data(
        "MultiQueryPlan", [{"type": "missing", "loc": ("finding_id",), "input": {}}]
    )
    fake_llm = _fake_llm(side_effect=[validation_error, _MINIMAL_PLAN])
    _patch_get_llm(monkeypatch, fake_llm)

    plan = await generate_queries(_CANDIDATE, settings=_settings(stage4_repair_attempts=1))

    assert plan.finding_id == _CANDIDATE.global_id


async def test_generate_queries_repair_exhausted_raises(monkeypatch):
    validation_error = ValidationError.from_exception_data(
        "MultiQueryPlan", [{"type": "missing", "loc": ("finding_id",), "input": {}}]
    )
    fake_llm = _fake_llm(side_effect=[validation_error, validation_error])
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(QueryPlannerUnavailableError, match="doesn't match the expected schema"):
        await generate_queries(_CANDIDATE, settings=_settings(stage4_repair_attempts=1))


async def test_generate_queries_transport_error_no_repair(monkeypatch):
    fake_llm = _fake_llm(side_effect=[OSError("connection refused")])
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(QueryPlannerUnavailableError, match="LLM call failed"):
        await generate_queries(_CANDIDATE, settings=_settings(stage4_repair_attempts=1))
    assert fake_llm.with_structured_output(None).ainvoke.call_count == 1


async def test_generate_queries_missing_credential_raises(monkeypatch):
    def _raise(role, settings=None):
        raise ValueError("ANTHROPIC_API_KEY is not set.")

    monkeypatch.setattr("fw_audit.stage4_rag.query.planner.get_llm_for_agent", _raise)

    with pytest.raises(QueryPlannerUnavailableError, match="ANTHROPIC_API_KEY"):
        await generate_queries(_CANDIDATE, settings=_settings())
