"""Tests for `fw_audit.stage3b_claims.agent.converter.extract_claims`.

Mirrors `tests/test_stage3_analyst.py`'s fake-LLM/patch pattern exactly."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from langchain_core.exceptions import OutputParserException
from pydantic import ValidationError

from fw_audit.common.claims import ClaimExtractionBatch
from fw_audit.config.settings import Settings
from fw_audit.stage3b_claims.agent.converter import extract_claims
from fw_audit.stage3b_claims.errors import ClaimExtractionUnavailableError
from fw_audit.stage3b_claims.models import ClaimBlock

_EMPTY_BATCH = ClaimExtractionBatch(claims=[], not_a_finding=True)


def _block() -> ClaimBlock:
    return ClaimBlock(block_id="block_0000", page_numbers=(1, 2), text="CVE-2024-1: something")


def _fake_llm(*, results=None, side_effect=None):
    if results is not None:
        structured = SimpleNamespace(ainvoke=AsyncMock(side_effect=list(results)))
    else:
        structured = SimpleNamespace(ainvoke=AsyncMock(side_effect=side_effect))
    return SimpleNamespace(with_structured_output=lambda schema, **kwargs: structured)


def _patch_get_llm(monkeypatch, fake_llm) -> None:
    monkeypatch.setattr(
        "fw_audit.stage3b_claims.agent.converter.get_llm_for_agent",
        lambda role, settings=None: fake_llm,
    )


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


async def test_extract_claims_happy_path(monkeypatch):
    fake_llm = _fake_llm(results=[_EMPTY_BATCH])
    _patch_get_llm(monkeypatch, fake_llm)

    batch = await extract_claims(_block(), doc_stem="doc", settings=_settings())
    assert batch is _EMPTY_BATCH


async def test_extract_claims_passes_structured_output_method_from_settings(monkeypatch):
    captured = {}

    class _Structured:
        async def ainvoke(self, messages, config=None):
            return _EMPTY_BATCH

    def _with_structured_output(schema, method=None, **kwargs):
        captured["method"] = method
        return _Structured()

    fake_llm = SimpleNamespace(with_structured_output=_with_structured_output)
    _patch_get_llm(monkeypatch, fake_llm)

    await extract_claims(
        _block(),
        doc_stem="doc",
        settings=_settings(stage3b_structured_output_method="function_calling"),
    )
    assert captured["method"] == "function_calling"


async def test_extract_claims_repairs_once_on_validation_error(monkeypatch):
    validation_error = ValidationError.from_exception_data("ClaimExtractionBatch", [])
    fake_llm = _fake_llm(results=[validation_error, _EMPTY_BATCH])
    # AsyncMock side_effect list: exceptions must be raised, not returned.
    fake_llm.with_structured_output(ClaimExtractionBatch).ainvoke.side_effect = [
        validation_error,
        _EMPTY_BATCH,
    ]
    _patch_get_llm(monkeypatch, fake_llm)

    batch = await extract_claims(
        _block(), doc_stem="doc", settings=_settings(stage3b_repair_attempts=1)
    )
    assert batch is _EMPTY_BATCH


async def test_extract_claims_exhausts_repair_budget_and_raises(monkeypatch):
    validation_error = ValidationError.from_exception_data("ClaimExtractionBatch", [])
    fake_llm = _fake_llm(side_effect=validation_error)
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(ClaimExtractionUnavailableError):
        await extract_claims(
            _block(), doc_stem="doc", settings=_settings(stage3b_repair_attempts=1)
        )


async def test_extract_claims_output_parser_exception_gets_repair(monkeypatch):
    parser_error = OutputParserException("not valid json")
    fake_llm = _fake_llm(results=[parser_error, _EMPTY_BATCH])
    fake_llm.with_structured_output(ClaimExtractionBatch).ainvoke.side_effect = [
        parser_error,
        _EMPTY_BATCH,
    ]
    _patch_get_llm(monkeypatch, fake_llm)

    batch = await extract_claims(
        _block(), doc_stem="doc", settings=_settings(stage3b_repair_attempts=1)
    )
    assert batch is _EMPTY_BATCH


async def test_extract_claims_transport_failure_gets_no_repair(monkeypatch):
    fake_llm = _fake_llm(side_effect=OSError("connection reset"))
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(ClaimExtractionUnavailableError, match="LLM call failed"):
        await extract_claims(
            _block(), doc_stem="doc", settings=_settings(stage3b_repair_attempts=3)
        )
    # Only ONE call should have been made — no repair attempt for a
    # transport failure.
    assert fake_llm.with_structured_output(ClaimExtractionBatch).ainvoke.call_count == 1


async def test_extract_claims_credential_resolution_failure(monkeypatch):
    def _raise_value_error(role, settings=None):
        raise ValueError("no usable credential")

    monkeypatch.setattr(
        "fw_audit.stage3b_claims.agent.converter.get_llm_for_agent", _raise_value_error
    )

    with pytest.raises(ClaimExtractionUnavailableError):
        await extract_claims(_block(), doc_stem="doc", settings=_settings())


async def test_extract_claims_wrong_return_type_raises(monkeypatch):
    fake_llm = _fake_llm(results=[object()])
    _patch_get_llm(monkeypatch, fake_llm)

    with pytest.raises(ClaimExtractionUnavailableError, match="unexpected result type"):
        await extract_claims(_block(), doc_stem="doc", settings=_settings())
