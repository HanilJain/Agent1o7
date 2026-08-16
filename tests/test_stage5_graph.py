"""Tests for `fw_audit.stage5_verification.agent.graph` — routing and the
iteration cap, using a duck-typed fake LLM (not a real `BaseChatModel`
subclass — `build_verifier_graph` only ever calls `.bind_tools()` and
`.with_structured_output()` on `llm`, so a minimal stand-in exercising
exactly that surface is enough, and keeps this test independent of any
provider SDK)."""

from __future__ import annotations

from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from fw_audit.common.verification import VerificationVerdict, VerifierVerdict
from fw_audit.stage5_verification.agent.graph import build_verifier_graph


@tool
async def fake_tool(x: str) -> str:
    """A trivial tool for routing tests."""
    return f"handled {x}"


class _ScriptedRunnable:
    """Returns/raises each item of `outputs` in turn on successive
    `ainvoke` calls — an `Exception` instance in the sequence is raised
    instead of returned."""

    def __init__(self, outputs: list) -> None:
        self._outputs = list(outputs)
        self.calls: list = []

    async def ainvoke(self, messages):
        self.calls.append(messages)
        item = self._outputs.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class _FakeLLM:
    def __init__(
        self,
        *,
        tool_call_outputs: list,
        verdict: VerifierVerdict,
        structured_outputs: list | None = None,
    ) -> None:
        self._tool_call_outputs = tool_call_outputs
        # `structured_outputs`, when given, overrides the single-verdict
        # default — lets a test script a ValidationError followed by a
        # real verdict, to exercise the finalize node's repair retry.
        self._structured_outputs = (
            structured_outputs if structured_outputs is not None else [verdict]
        )
        self.bound_runnable: _ScriptedRunnable | None = None
        self.structured_runnable: _ScriptedRunnable | None = None

    def bind_tools(self, tools):
        self.bound_runnable = _ScriptedRunnable(self._tool_call_outputs)
        return self.bound_runnable

    def with_structured_output(self, schema):
        self.structured_runnable = _ScriptedRunnable(self._structured_outputs)
        return self.structured_runnable


def _tool_call_message(tool_name: str, call_id: str = "call_1") -> AIMessage:
    return AIMessage(
        content="",
        tool_calls=[{"name": tool_name, "args": {"x": "1"}, "id": call_id}],
    )


def _final_message() -> AIMessage:
    return AIMessage(content="done, no more tools needed.")


def _verdict(verdict: VerificationVerdict = VerificationVerdict.CONFIRMED) -> VerifierVerdict:
    return VerifierVerdict(
        verdict=verdict,
        confidence="HIGH",
        summary="s",
        evidence="e",
        recommended_next_steps=[],
    )


async def test_agent_stops_when_llm_calls_no_tools():
    llm = _FakeLLM(tool_call_outputs=[_final_message()], verdict=_verdict())
    graph = build_verifier_graph(llm=llm, tools=[fake_tool], max_iterations=5)

    result = await graph.ainvoke({"messages": [], "iterations": 0, "verdict": None})

    assert result["verdict"] == VerificationVerdict.CONFIRMED
    assert result["iterations"] == 1
    assert len(llm.bound_runnable.calls) == 1  # only one agent turn


async def test_agent_loops_through_tool_call_then_finalizes():
    llm = _FakeLLM(
        tool_call_outputs=[_tool_call_message("fake_tool"), _final_message()],
        verdict=_verdict(VerificationVerdict.REFUTED),
    )
    graph = build_verifier_graph(llm=llm, tools=[fake_tool], max_iterations=5)

    result = await graph.ainvoke({"messages": [], "iterations": 0, "verdict": None})

    assert result["verdict"] == VerificationVerdict.REFUTED
    assert result["iterations"] == 2  # one turn that called a tool, one final turn
    # the ToolMessage from fake_tool should be present in the transcript
    tool_messages = [m for m in result["messages"] if getattr(m, "type", None) == "tool"]
    assert any("handled 1" in m.content for m in tool_messages)


async def test_iteration_cap_forces_finalize_even_with_pending_tool_call():
    # The LLM always wants to call a tool — without the cap this would loop forever.
    llm = _FakeLLM(
        tool_call_outputs=[_tool_call_message("fake_tool", f"call_{i}") for i in range(10)],
        verdict=_verdict(VerificationVerdict.INCONCLUSIVE),
    )
    graph = build_verifier_graph(llm=llm, tools=[fake_tool], max_iterations=2)

    result = await graph.ainvoke({"messages": [], "iterations": 0, "verdict": None})

    assert result["verdict"] == VerificationVerdict.INCONCLUSIVE
    assert result["iterations"] == 2


async def test_dangling_tool_call_gets_placeholder_before_finalize():
    """Regression test: if the cap is hit right as the agent requests a
    tool call, finalize must not send a dangling tool_calls entry."""
    llm = _FakeLLM(
        tool_call_outputs=[_tool_call_message("fake_tool")],
        verdict=_verdict(),
    )
    graph = build_verifier_graph(llm=llm, tools=[fake_tool], max_iterations=1)

    await graph.ainvoke({"messages": [], "iterations": 0, "verdict": None})

    finalize_messages = llm.structured_runnable.calls[0]
    # The AIMessage with the tool call must be immediately followed by a
    # ToolMessage response before any later HumanMessage.
    ai_idx = next(
        i for i, m in enumerate(finalize_messages) if getattr(m, "tool_calls", None)
    )
    assert getattr(finalize_messages[ai_idx + 1], "type", None) == "tool"


async def test_repair_retry_on_validation_error():
    """A structured-output call that raises ValidationError once should be
    retried with the error fed back, per stage3's established pattern."""
    from pydantic import ValidationError

    try:
        VerifierVerdict.model_validate({"verdict": "not-a-real-verdict"})
        raise AssertionError("expected ValidationError")
    except ValidationError as exc:
        validation_error = exc

    llm = _FakeLLM(
        tool_call_outputs=[_final_message()],
        verdict=_verdict(),
        structured_outputs=[validation_error, _verdict()],
    )
    graph = build_verifier_graph(llm=llm, tools=[fake_tool], max_iterations=5, repair_attempts=1)

    result = await graph.ainvoke({"messages": [], "iterations": 0, "verdict": None})

    assert len(llm.structured_runnable.calls) == 2
    assert result["verdict"] == VerificationVerdict.CONFIRMED
    # the second call's messages must include the repair-request feedback
    second_call_text = " ".join(str(m.content) for m in llm.structured_runnable.calls[1])
    assert "failed schema validation" in second_call_text


async def test_repair_attempts_exhausted_raises():
    from pydantic import ValidationError

    try:
        VerifierVerdict.model_validate({"verdict": "not-a-real-verdict"})
        raise AssertionError("expected ValidationError")
    except ValidationError as exc:
        validation_error = exc

    llm = _FakeLLM(
        tool_call_outputs=[_final_message()],
        verdict=_verdict(),
        structured_outputs=[validation_error, validation_error],
    )
    graph = build_verifier_graph(llm=llm, tools=[fake_tool], max_iterations=5, repair_attempts=1)

    import pytest

    with pytest.raises(ValidationError):
        await graph.ainvoke({"messages": [], "iterations": 0, "verdict": None})
