"""Tests for `fw_audit.stage4_rag.taint.analyst` — mirrors
`tests/test_stage3_analyst.py`'s mocking shape exactly."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from fw_audit.common.taint import TaintPathReport
from fw_audit.config.settings import Settings
from fw_audit.stage4_rag.taint.analyst import TaintAnalystUnavailableError, analyze_taint

_GID = "bin#0000::candidate_001"
_MINIMAL_REPORT = TaintPathReport(finding_id=_GID, resolved=False, taint_paths=[])


def _fake_llm(*, results=None, side_effect=None):
    if results is not None:
        structured = SimpleNamespace(ainvoke=AsyncMock(side_effect=list(results)))
    else:
        structured = SimpleNamespace(ainvoke=AsyncMock(side_effect=side_effect))
    return SimpleNamespace(with_structured_output=lambda schema: structured)


def _patch_get_llm(monkeypatch, fake_llm) -> None:
    monkeypatch.setattr(
        "fw_audit.stage4_rag.taint.analyst.get_llm_for_agent",
        lambda role, settings=None: fake_llm,
    )


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


async def test_analyze_taint_happy_path(monkeypatch):
    fake_llm = _fake_llm(results=[_MINIMAL_REPORT])
    _patch_get_llm(monkeypatch, fake_llm)

    report = await analyze_taint("prompt text", global_id=_GID, settings=_settings())

    assert report.finding_id == _GID


async def test_analyze_taint_overwrites_hallucinated_finding_id(monkeypatch):
    wrong = TaintPathReport(finding_id="wrong", resolved=False, taint_paths=[])
    fake_llm = _fake_llm(results=[wrong])
    _patch_get_llm(monkeypatch, fake_llm)

    report = await analyze_taint("prompt text", global_id=_GID, settings=_settings())

    assert report.finding_id == _GID


async def test_analyze_taint_repair_retry_succeeds(monkeypatch):
    validation_error = ValidationError.from_exception_data(
        "TaintPathReport", [{"type": "missing", "loc": ("finding_id",), "input": {}}]
    )
    fake_llm = _fake_llm(side_effect=[validation_error, _MINIMAL_REPORT])
    _patch_get_llm(monkeypatch, fake_llm)

    report = await analyze_taint(
        "prompt text", global_id=_GID, settings=_settings(stage4_repair_attempts=1)
    )

    assert report.finding_id == _GID


async def test_analyze_taint_repair_exhausted_raises(monkeypatch):
    validation_error = ValidationError.from_exception_data(
        "TaintPathReport", [{"type": "missing", "loc": ("finding_id",), "input": {}}]
    )
    fake_llm = _fake_llm(side_effect=[validation_error, validation_error])
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(TaintAnalystUnavailableError, match="doesn't match the expected schema"):
        await analyze_taint(
            "prompt text", global_id=_GID, settings=_settings(stage4_repair_attempts=1)
        )


async def test_analyze_taint_transport_error_no_repair(monkeypatch):
    fake_llm = _fake_llm(side_effect=[OSError("connection refused")])
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(TaintAnalystUnavailableError, match="LLM call failed"):
        await analyze_taint(
            "prompt text", global_id=_GID, settings=_settings(stage4_repair_attempts=1)
        )
    assert fake_llm.with_structured_output(None).ainvoke.call_count == 1


async def test_analyze_taint_missing_credential_raises(monkeypatch):
    def _raise(role, settings=None):
        raise ValueError("ANTHROPIC_API_KEY is not set.")

    monkeypatch.setattr("fw_audit.stage4_rag.taint.analyst.get_llm_for_agent", _raise)

    with pytest.raises(TaintAnalystUnavailableError, match="ANTHROPIC_API_KEY"):
        await analyze_taint("prompt text", global_id=_GID, settings=_settings())
