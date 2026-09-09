"""Tests for fw_audit.observability.usage."""

from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult, LLMResult

from fw_audit.config.settings import Settings
from fw_audit.observability.context import trace_context
from fw_audit.observability.usage import (
    UsageBudgetExceededError,
    UsageTrackingCallbackHandler,
    format_usage_summary,
    usage_registry,
)


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def _llm_result(
    *,
    input_tokens: int = 100,
    output_tokens: int = 20,
    cache_read: int = 0,
    cache_creation: int = 0,
    reasoning: int = 0,
    model_name: str | None = "claude-sonnet-4-5-20250929",
) -> LLMResult:
    usage_metadata = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
    }
    details = {}
    if cache_read or cache_creation:
        details["input_token_details"] = {
            "cache_read": cache_read,
            "cache_creation": cache_creation,
        }
    if reasoning:
        details["output_token_details"] = {"reasoning": reasoning}
    usage_metadata.update(details)

    response_metadata = {"model_name": model_name} if model_name else {}
    msg = AIMessage(
        content="hi", usage_metadata=usage_metadata, response_metadata=response_metadata
    )
    return LLMResult(generations=[[ChatGeneration(message=msg)]])


class FakeChatModel(BaseChatModel):
    """Minimal real `BaseChatModel` — used for the one end-to-end test
    that exercises LangChain's actual callback dispatch, not a hand-built
    `LLMResult`."""

    usage: dict = {}

    @property
    def _llm_type(self) -> str:
        return "fake"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        msg = AIMessage(
            content="hi",
            usage_metadata=self.usage
            or {"input_tokens": 50, "output_tokens": 10, "total_tokens": 60},
            response_metadata={"model_name": "claude-sonnet-4-5-20250929"},
        )
        return ChatResult(generations=[ChatGeneration(message=msg)])


# ---------------------------------------------------------------------- #
# Core extraction / attribution
# ---------------------------------------------------------------------- #


def test_on_llm_end_records_measured_usage():
    settings = _settings()
    handler = UsageTrackingCallbackHandler(
        role="stage3_vuln_analyst",
        provider="anthropic",
        model="claude-sonnet-4-5",
        settings=settings,
    )
    with usage_registry() as reg:
        run_id = uuid4()
        handler.on_chat_model_start({}, [[]], run_id=run_id)
        handler.on_llm_end(_llm_result(input_tokens=1000, output_tokens=200), run_id=run_id)

    records = reg.records()
    assert len(records) == 1
    rec = records[0]
    assert rec.measured is True
    assert rec.input_tokens == 1000
    assert rec.output_tokens == 200
    assert rec.total_tokens == 1200
    assert rec.role == "stage3_vuln_analyst"
    assert rec.cost_usd is not None


def test_attribution_reads_trace_context_at_call_time():
    """The linchpin of the attribution design: on_llm_end reads
    current_context(), not anything captured at handler construction."""
    settings = _settings()
    handler = UsageTrackingCallbackHandler(
        role="stage3_vuln_analyst",
        provider="anthropic",
        model="claude-sonnet-4-5",
        settings=settings,
    )
    with usage_registry() as reg, trace_context(stage="3", run_id="r1", chunk_id="c7"):
        run_id = uuid4()
        handler.on_llm_end(_llm_result(), run_id=run_id)

    rec = reg.records()[0]
    assert rec.stage == "3"
    assert rec.run_id == "r1"
    assert rec.chunk_id == "c7"


def test_fragmentation_two_handlers_different_roles_one_registry_sums_correctly():
    """Mirrors FVVW building 4 model objects (4 handler instances) per
    candidate — usage must still roll up into ONE registry's totals."""
    settings = _settings()
    handler_a = UsageTrackingCallbackHandler(
        role="stage5_strategy_agent",
        provider="anthropic",
        model="claude-sonnet-4-5",
        settings=settings,
    )
    handler_b = UsageTrackingCallbackHandler(
        role="stage5_report_writer",
        provider="anthropic",
        model="claude-sonnet-4-5",
        settings=settings,
    )

    with usage_registry() as reg:
        handler_a.on_llm_end(_llm_result(input_tokens=100, output_tokens=10), run_id=uuid4())
        handler_b.on_llm_end(_llm_result(input_tokens=200, output_tokens=20), run_id=uuid4())

    by_role = reg.by_role()
    assert set(by_role) == {"stage5_strategy_agent", "stage5_report_writer"}
    assert by_role["stage5_strategy_agent"].total_tokens == 110
    assert by_role["stage5_report_writer"].total_tokens == 220

    totals = reg.totals()
    assert totals.calls == 2
    assert totals.total_tokens == 330


def test_missing_usage_metadata_records_unmeasured_row_not_a_crash():
    settings = _settings()
    handler = UsageTrackingCallbackHandler(
        role="stage1_binary_identifier",
        provider="ollama",
        model="qwen2.5-coder:1.5b",
        settings=settings,
    )
    result = LLMResult(generations=[[ChatGeneration(message=AIMessage(content="hi"))]])
    with usage_registry() as reg:
        handler.on_llm_end(result, run_id=uuid4())

    records = reg.records()
    assert len(records) == 1
    assert records[0].measured is False
    assert records[0].total_tokens == 0


def test_missing_model_name_falls_back_to_constructor_model():
    """Divergence from langchain_core's UsageMetadataCallbackHandler, which
    silently DROPS usage entirely when model_name is falsy."""
    settings = _settings()
    handler = UsageTrackingCallbackHandler(
        role="stage3_vuln_analyst", provider="ollama", model="qwen2.5-coder:1.5b", settings=settings
    )
    with usage_registry() as reg:
        handler.on_llm_end(_llm_result(model_name=None), run_id=uuid4())

    rec = reg.records()[0]
    assert rec.measured is True
    assert rec.model == "qwen2.5-coder:1.5b"


def test_llm_output_token_usage_fallback_path():
    settings = _settings()
    handler = UsageTrackingCallbackHandler(
        role="stage3_vuln_analyst", provider="openai", model="gpt-4.1", settings=settings
    )
    result = LLMResult(
        generations=[[ChatGeneration(message=AIMessage(content="hi"))]],
        llm_output={"token_usage": {"prompt_tokens": 40, "completion_tokens": 5}},
    )
    with usage_registry() as reg:
        handler.on_llm_end(result, run_id=uuid4())

    rec = reg.records()[0]
    assert rec.measured is True
    assert rec.input_tokens == 40
    assert rec.output_tokens == 5
    assert rec.total_tokens == 45


def test_cache_and_reasoning_token_details_are_extracted():
    settings = _settings()
    handler = UsageTrackingCallbackHandler(
        role="stage3_vuln_analyst",
        provider="anthropic",
        model="claude-sonnet-4-5",
        settings=settings,
    )
    with usage_registry() as reg:
        handler.on_llm_end(
            _llm_result(
                input_tokens=1000,
                output_tokens=300,
                cache_read=800,
                cache_creation=50,
                reasoning=100,
            ),
            run_id=uuid4(),
        )

    rec = reg.records()[0]
    assert rec.cache_read_tokens == 800
    assert rec.cache_creation_tokens == 50
    assert rec.reasoning_tokens == 100


# ---------------------------------------------------------------------- #
# JSONL artifact / broken-disk handling
# ---------------------------------------------------------------------- #


def test_jsonl_artifact_round_trips(tmp_path):
    settings = _settings()
    handler = UsageTrackingCallbackHandler(
        role="stage3_vuln_analyst",
        provider="anthropic",
        model="claude-sonnet-4-5",
        settings=settings,
    )
    jsonl_path = tmp_path / "usage" / "3.run1.jsonl"
    with usage_registry(jsonl_path=jsonl_path):
        handler.on_llm_end(_llm_result(), run_id=uuid4())
        handler.on_llm_end(_llm_result(), run_id=uuid4())

    lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        obj = json.loads(line)
        assert obj["role"] == "stage3_vuln_analyst"
        assert obj["measured"] is True


def test_broken_disk_latches_quiet_after_first_failure(tmp_path, monkeypatch, caplog):
    from fw_audit.observability.usage import UsageRegistry

    registry = UsageRegistry()
    jsonl_path = tmp_path / "usage.jsonl"
    registry.attach_jsonl(jsonl_path)

    def _boom(self, *args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("pathlib.Path.open", _boom)

    with caplog.at_level("WARNING"):
        registry.record({"ts": "", "role": "x", "provider": "y", "model": "z", "measured": True})
        registry.record({"ts": "", "role": "x", "provider": "y", "model": "z", "measured": True})

    warnings = [r for r in caplog.records if "disabling JSONL log" in r.message]
    assert len(warnings) == 1  # latched — only warned once
    # Both records still landed in memory even though the disk write failed.
    assert len(registry.records()) == 2


# ---------------------------------------------------------------------- #
# format_usage_summary
# ---------------------------------------------------------------------- #


def test_format_usage_summary_empty_report_returns_empty_string():
    with usage_registry() as reg:
        text = format_usage_summary(reg.snapshot())
    assert text == ""


def test_format_usage_summary_populated_report_has_key_fields():
    settings = _settings()
    handler = UsageTrackingCallbackHandler(
        role="stage3_vuln_analyst",
        provider="anthropic",
        model="claude-sonnet-4-5",
        settings=settings,
    )
    with usage_registry() as reg:
        handler.on_llm_end(_llm_result(input_tokens=1000, output_tokens=200), run_id=uuid4())
        text = format_usage_summary(reg.snapshot())

    assert "LLM usage" in text
    assert "calls:   1" in text
    assert "stage3_vuln_analyst" in text


def test_format_usage_summary_flags_unmeasured_calls():
    settings = _settings()
    handler = UsageTrackingCallbackHandler(
        role="stage1_binary_identifier",
        provider="ollama",
        model="qwen2.5-coder:1.5b",
        settings=settings,
    )
    result = LLMResult(generations=[[ChatGeneration(message=AIMessage(content="hi"))]])
    with usage_registry() as reg:
        handler.on_llm_end(result, run_id=uuid4())
        text = format_usage_summary(reg.snapshot())

    assert "unmeasured" in text


# ---------------------------------------------------------------------- #
# Budget enforcement
# ---------------------------------------------------------------------- #


def test_budget_warn_mode_latches_one_log_and_does_not_raise(caplog):
    settings = _settings(llm_max_total_tokens=100, llm_budget_action="warn")
    handler = UsageTrackingCallbackHandler(
        role="stage3_vuln_analyst",
        provider="anthropic",
        model="claude-sonnet-4-5",
        settings=settings,
    )
    with usage_registry() as reg:
        with caplog.at_level("WARNING"):
            for _ in range(3):
                handler.on_llm_end(_llm_result(input_tokens=100, output_tokens=50), run_id=uuid4())
        assert reg.budget_exceeded is True

    budget_warnings = [r for r in caplog.records if "budget exceeded" in r.message]
    assert len(budget_warnings) == 1


def test_budget_action_stop_is_rejected_by_settings():
    """ "stop" mode was prototyped and pulled after a reproducible hang
    (see UsageBudgetExceededError's docstring) — Settings must reject it
    rather than silently accepting a value nothing wires up anymore."""
    with pytest.raises(ValueError, match="FWA_LLM_BUDGET_ACTION"):
        _settings(llm_budget_action="stop")


def test_handler_never_sets_raise_error_warn_mode_only():
    settings = _settings(llm_max_total_tokens=100, llm_budget_action="warn")
    handler = UsageTrackingCallbackHandler(
        role="stage3_vuln_analyst",
        provider="anthropic",
        model="claude-sonnet-4-5",
        settings=settings,
    )
    assert handler.raise_error is False

    # Crossing the budget in warn mode must never raise.
    with usage_registry():
        handler.on_llm_end(_llm_result(input_tokens=200, output_tokens=50), run_id=uuid4())


def test_usage_budget_exceeded_error_is_base_exception_not_exception_subclass():
    """Kept for a future hard-stop mode's design (see the class's
    docstring): if ever raised, it must NOT be caught by a driver's
    `except Exception` retry loop — it must derive from BaseException
    directly so it would abort the run instead of being retried."""
    assert issubclass(UsageBudgetExceededError, BaseException)
    assert not issubclass(UsageBudgetExceededError, Exception)


def test_cost_budget_triggers_same_as_token_budget():
    settings = _settings(llm_max_cost_usd=0.0001, llm_budget_action="warn")
    handler = UsageTrackingCallbackHandler(
        role="stage3_vuln_analyst",
        provider="anthropic",
        model="claude-sonnet-4-5",
        settings=settings,
    )
    with usage_registry() as reg:
        handler.on_llm_end(_llm_result(input_tokens=100000, output_tokens=50000), run_id=uuid4())
    assert reg.budget_exceeded is True


# ---------------------------------------------------------------------- #
# End-to-end: real LangChain callback dispatch (not a hand-built LLMResult)
# ---------------------------------------------------------------------- #


def test_end_to_end_callback_dispatch_through_real_ainvoke():
    settings = _settings()
    handler = UsageTrackingCallbackHandler(
        role="stage3_vuln_analyst",
        provider="anthropic",
        model="claude-sonnet-4-5",
        settings=settings,
    )
    model = FakeChatModel(callbacks=[handler])

    with usage_registry() as reg:
        asyncio.run(model.ainvoke("hello"))

    records = reg.records()
    assert len(records) == 1
    assert records[0].measured is True
    assert records[0].input_tokens == 50
    assert records[0].output_tokens == 10
