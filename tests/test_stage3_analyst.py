"""Tests for fw_audit.stage3_analysis.agent.analyst."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from langchain_core.exceptions import OutputParserException
from pydantic import ValidationError

from fw_audit.common.findings import AnalysisReport
from fw_audit.config.settings import Settings
from fw_audit.stage3_analysis.agent.analyst import AnalysisUnavailableError, analyze_chunk

_MINIMAL_REPORT = AnalysisReport(chunk_id="test_bin#0000", findings=[], checked_categories=[])


def _fake_llm(*, results=None, side_effect=None):
    """Build a fake `BaseChatModel` stand-in matching the
    `with_structured_output(...).ainvoke(...)` call shape `analyst.py` uses.
    `results`, if given, is a list consumed in order across successive
    `ainvoke` calls (for repair-retry tests)."""
    if results is not None:
        structured = SimpleNamespace(ainvoke=AsyncMock(side_effect=list(results)))
    else:
        structured = SimpleNamespace(ainvoke=AsyncMock(side_effect=side_effect))
    return SimpleNamespace(with_structured_output=lambda schema: structured)


def _patch_get_llm(monkeypatch, fake_llm) -> None:
    """`get_llm_for_agent(role, *, settings=None)` — the fake must accept
    (and ignore) the `settings` kwarg `analyze_chunk` now passes through."""
    monkeypatch.setattr(
        "fw_audit.stage3_analysis.agent.analyst.get_llm_for_agent",
        lambda role, settings=None: fake_llm,
    )


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


async def test_analyze_chunk_happy_path(monkeypatch):
    fake_llm = _fake_llm(results=[_MINIMAL_REPORT])
    _patch_get_llm(monkeypatch, fake_llm)

    report = await analyze_chunk(
        "int main() {}",
        chunk_id="test_bin#0000",
        rootfs_path="bin/test",
        settings=_settings(),
    )
    assert report.chunk_id == "test_bin#0000"


async def test_analyze_chunk_overwrites_hallucinated_chunk_id(monkeypatch):
    wrong_id_report = AnalysisReport(
        chunk_id="totally_wrong_id", findings=[], checked_categories=[]
    )
    fake_llm = _fake_llm(results=[wrong_id_report])
    _patch_get_llm(monkeypatch, fake_llm)

    report = await analyze_chunk(
        "int main() {}",
        chunk_id="test_bin#0007",
        rootfs_path="bin/test",
        settings=_settings(),
    )
    assert report.chunk_id == "test_bin#0007"


async def test_analyze_chunk_repair_retry_succeeds_on_second_call(monkeypatch):
    validation_error = ValidationError.from_exception_data(
        "AnalysisReport", [{"type": "missing", "loc": ("chunk_id",), "input": {}}]
    )
    fake_llm = _fake_llm(side_effect=[validation_error, _MINIMAL_REPORT])
    _patch_get_llm(monkeypatch, fake_llm)

    report = await analyze_chunk(
        "int main() {}",
        chunk_id="test_bin#0000",
        rootfs_path="bin/test",
        settings=_settings(stage3_repair_attempts=1),
    )
    assert report.chunk_id == "test_bin#0000"


async def test_analyze_chunk_repair_exhausted_raises(monkeypatch):
    validation_error = ValidationError.from_exception_data(
        "AnalysisReport", [{"type": "missing", "loc": ("chunk_id",), "input": {}}]
    )
    fake_llm = _fake_llm(side_effect=[validation_error, validation_error])
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(AnalysisUnavailableError, match="doesn't match the expected schema"):
        await analyze_chunk(
            "int main() {}",
            chunk_id="test_bin#0000",
            rootfs_path="bin/test",
            settings=_settings(stage3_repair_attempts=1),
        )


async def test_analyze_chunk_zero_repair_attempts_raises_immediately(monkeypatch):
    validation_error = ValidationError.from_exception_data(
        "AnalysisReport", [{"type": "missing", "loc": ("chunk_id",), "input": {}}]
    )
    fake_llm = _fake_llm(side_effect=[validation_error])
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(AnalysisUnavailableError):
        await analyze_chunk(
            "int main() {}",
            chunk_id="test_bin#0000",
            rootfs_path="bin/test",
            settings=_settings(stage3_repair_attempts=0),
        )
    assert fake_llm.with_structured_output(None).ainvoke.call_count == 1


async def test_analyze_chunk_output_parser_error_repair_retry_succeeds(monkeypatch):
    """A model that returns text that isn't valid JSON at all (Ollama's
    `OUTPUT_PARSING_FAILURE`) gets the same repair-retry treatment as a
    `ValidationError`, not a blind fall-through to the queue-level retry."""
    parse_error = OutputParserException("Invalid json output: not json")
    fake_llm = _fake_llm(side_effect=[parse_error, _MINIMAL_REPORT])
    _patch_get_llm(monkeypatch, fake_llm)

    report = await analyze_chunk(
        "int main() {}",
        chunk_id="test_bin#0000",
        rootfs_path="bin/test",
        settings=_settings(stage3_repair_attempts=1),
    )
    assert report.chunk_id == "test_bin#0000"


async def test_analyze_chunk_output_parser_error_repair_exhausted_raises(monkeypatch):
    parse_error = OutputParserException("Invalid json output: not json")
    fake_llm = _fake_llm(side_effect=[parse_error, parse_error])
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(AnalysisUnavailableError, match="doesn't match the expected schema"):
        await analyze_chunk(
            "int main() {}",
            chunk_id="test_bin#0000",
            rootfs_path="bin/test",
            settings=_settings(stage3_repair_attempts=1),
        )


async def test_analyze_chunk_transport_error_propagates_without_repair(monkeypatch):
    fake_llm = _fake_llm(side_effect=[OSError("connection refused")])
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(AnalysisUnavailableError, match="LLM call failed"):
        await analyze_chunk(
            "int main() {}",
            chunk_id="test_bin#0000",
            rootfs_path="bin/test",
            settings=_settings(stage3_repair_attempts=1),
        )
    # No repair attempt for a transport error — exactly one call.
    assert fake_llm.with_structured_output(None).ainvoke.call_count == 1


async def test_analyze_chunk_missing_credential_raises_unavailable(monkeypatch):
    def _raise(role, settings=None):
        raise ValueError("ANTHROPIC_API_KEY is not set.")

    monkeypatch.setattr("fw_audit.stage3_analysis.agent.analyst.get_llm_for_agent", _raise)

    with pytest.raises(AnalysisUnavailableError, match="ANTHROPIC_API_KEY"):
        await analyze_chunk(
            "int main() {}",
            chunk_id="test_bin#0000",
            rootfs_path="bin/test",
            settings=_settings(),
        )


async def test_analyze_chunk_unexpected_return_type_raises(monkeypatch):
    fake_llm = _fake_llm(results=[{"not": "a report"}])
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(AnalysisUnavailableError, match="unexpected result type"):
        await analyze_chunk(
            "int main() {}",
            chunk_id="test_bin#0000",
            rootfs_path="bin/test",
            settings=_settings(),
        )
