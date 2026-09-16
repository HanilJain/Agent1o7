"""Tests for `fw_audit.stage5_verification.llm_logging.LoggingChatModel` —
the transparent wrapper giving before/after-parser visibility into every
Stage 5 LLM call, with zero edits to any node/prompt file."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from fw_audit.stage5_verification.cmdlog import CommandLog
from fw_audit.stage5_verification.llm_logging import LoggingChatModel


@dataclass
class _FakeChatModel:
    """Duck-types the one method every Stage 5 call site actually uses
    (`ainvoke`) plus a `.model` attribute, mirroring the fakes already used
    throughout `tests/test_fvvw_*.py`/`tests/test_stage5_*.py`."""

    response_text: str = "the raw completion"
    model: str = "fake:model"
    calls: list = field(default_factory=list)

    async def ainvoke(self, messages, config=None, **kwargs):
        self.calls.append((messages, config))
        return AIMessage(content=self.response_text)


def _run(coro):
    return asyncio.run(coro)


def test_ainvoke_forwards_and_returns_response_unchanged():
    inner = _FakeChatModel(response_text="hello world")
    log = CommandLog.disabled()
    wrapped = LoggingChatModel(inner, role="generator", command_log=log)

    messages = [SystemMessage(content="sys"), HumanMessage(content="hi")]
    response = _run(wrapped.ainvoke(messages, config={"foo": "bar"}))

    assert response.content == "hello world"
    assert inner.calls == [(messages, {"foo": "bar"})]


def test_getattr_proxies_to_inner_model():
    inner = _FakeChatModel(model="anthropic:claude")
    wrapped = LoggingChatModel(inner, role="evaluator", command_log=CommandLog.disabled())
    assert wrapped.model == "anthropic:claude"


def test_ainvoke_records_prompt_and_raw_response_before_and_after(tmp_path):
    inner = _FakeChatModel(response_text="RAW_COMPLETION_TEXT")
    path = tmp_path / "gid.static.jsonl"
    log = CommandLog(path, track="static")
    wrapped = LoggingChatModel(inner, role="generator", command_log=log)

    messages = [SystemMessage(content="you are a generator"), HumanMessage(content="do it")]
    _run(wrapped.ainvoke(messages))

    records = log.read_all()
    assert len(records) == 1
    record = records[0]
    assert record["kind"] == "llm_call"
    assert record["command"] == "llm:generator"
    # "before parser" — the exact rendered prompt.
    assert "you are a generator" in record["payload"]
    assert "do it" in record["payload"]
    # "after LLM, before downstream parsing" — the raw completion text.
    assert record["stdout"] == "RAW_COMPLETION_TEXT"
    assert record["notes"]["role"] == "generator"


def test_ainvoke_never_truncates_the_persisted_record(tmp_path):
    long_text = "y" * 10_000
    inner = _FakeChatModel(response_text=long_text)
    path = tmp_path / "gid.dynamic.jsonl"
    log = CommandLog(path, track="dynamic")
    wrapped = LoggingChatModel(inner, role="bringup_agent", command_log=log)

    _run(wrapped.ainvoke([HumanMessage(content="x")]))

    record = log.read_all()[0]
    assert len(record["stdout"]) == 10_000


def test_disabled_command_log_means_no_write_but_call_still_works(tmp_path):
    inner = _FakeChatModel()
    wrapped = LoggingChatModel(inner, role="trigger_agent", command_log=CommandLog.disabled())
    response = _run(wrapped.ainvoke([HumanMessage(content="x")]))
    assert response.content == "the raw completion"
