"""LangGraph wiring for the Stage 5 verification agent — the repo's first
genuine multi-turn tool-calling loop (contrast `stage1_ingestion.graph`,
whose `StateGraph` wires deterministic control flow with a single one-shot
LLM node, never a tool-calling loop).

Shape:

    agent (LLM bound to [build_cpg, run_joern_script])
      ├─ tool_calls pending, under the iteration cap -> tools
      └─ no tool_calls, OR iteration cap hit          -> finalize
    tools (ToolNode)  -> back to agent
    finalize (with_structured_output(VerifierVerdict), bounded schema-repair
              retry — same pattern as stage3_analysis.agent.analyst.analyze_chunk)
      -> END

Unlike `stage1_ingestion.graph.get_graph()`, this graph is NOT built once
and cached: `llm`/`tools` are bound fresh per candidate (a fresh workspace,
a fresh pair of closure-bound tools — see `tools.joern_tool.build_joern_tools`),
so `build_verifier_graph()` is called once per `verify_candidate()` call,
not once per process.
"""

from __future__ import annotations

from typing import Annotated, TypedDict

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.tools import BaseTool
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from pydantic import ValidationError

from fw_audit.common.verification import ToolCallRecord, TranscriptEntry, VerifierVerdict

_FINALIZE_INSTRUCTION = (
    "You have reached the end of your verification attempts (either you chose to "
    "stop, or the attempt limit was reached). Based on everything above, give your "
    "final verdict now."
)


class VerifierState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    iterations: int
    verdict: VerifierVerdict | None
    verdict_confidence: str
    verdict_summary: str
    verdict_evidence: str
    verdict_next_steps: list[str]


def build_verifier_graph(
    *,
    llm: BaseChatModel,
    tools: list[BaseTool],
    max_iterations: int,
    repair_attempts: int = 1,
):
    """Construct (uncompiled -> compiled) one candidate's verifier graph."""
    llm_with_tools = llm.bind_tools(tools)
    structured_llm = llm.with_structured_output(VerifierVerdict)

    async def agent_node(state: VerifierState) -> dict:
        response = await llm_with_tools.ainvoke(state["messages"])
        return {"messages": [response], "iterations": state["iterations"] + 1}

    def _route_after_agent(state: VerifierState) -> str:
        last = state["messages"][-1]
        at_cap = state["iterations"] >= max_iterations
        has_tool_calls = isinstance(last, AIMessage) and bool(last.tool_calls)
        if has_tool_calls and not at_cap:
            return "tools"
        return "finalize"

    async def finalize_node(state: VerifierState) -> dict:
        messages = [
            *_close_dangling_tool_calls(state["messages"]),
            HumanMessage(content=_FINALIZE_INSTRUCTION),
        ]
        attempts_allowed = repair_attempts + 1
        last_error: ValidationError | None = None
        for attempt in range(attempts_allowed):
            try:
                parsed = await structured_llm.ainvoke(messages)
            except (OSError, TimeoutError):
                # No repair attempt for a transport failure — mirrors
                # stage3_analysis.agent.analyst.analyze_chunk's exact
                # reasoning: re-prompting a dead socket wastes time.
                raise
            except ValidationError as exc:
                last_error = exc
                if attempt < attempts_allowed - 1:
                    messages = [*messages, HumanMessage(content=_repair_request(exc))]
                    continue
                raise
            return {
                "verdict": parsed.verdict,
                "verdict_confidence": parsed.confidence,
                "verdict_summary": parsed.summary,
                "verdict_evidence": parsed.evidence,
                "verdict_next_steps": parsed.recommended_next_steps,
            }
        raise RuntimeError(f"finalize produced no result: {last_error}")  # pragma: no cover

    graph = StateGraph(VerifierState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", ToolNode(tools))
    graph.add_node("finalize", finalize_node)

    graph.set_entry_point("agent")
    graph.add_conditional_edges(
        "agent", _route_after_agent, {"tools": "tools", "finalize": "finalize"}
    )
    graph.add_edge("tools", "agent")
    graph.add_edge("finalize", END)

    return graph.compile()


def _close_dangling_tool_calls(messages: list[BaseMessage]) -> list[BaseMessage]:
    """If the agent hit `max_iterations` right as it requested a tool call,
    that last `AIMessage.tool_calls` entry never got a matching
    `ToolMessage` (the graph routed straight to `finalize` instead of
    `tools`). Some providers (OpenAI-style APIs) reject a request whose
    message history has a tool call with no matching response — so
    synthesize a placeholder `ToolMessage` for each pending call rather
    than sending a broken/inconsistent history to the finalize call."""
    if not messages:
        return messages
    last = messages[-1]
    if not (isinstance(last, AIMessage) and last.tool_calls):
        return messages
    placeholders = [
        ToolMessage(
            content="(not executed — the verification attempt limit was reached before this "
            "tool call could run)",
            tool_call_id=call["id"],
        )
        for call in last.tool_calls
    ]
    return [*messages, *placeholders]


def _message_text(content: object) -> str:
    """Flatten a `BaseMessage.content` value to plain text.

    Usually already a `str`, but some providers (Anthropic in particular)
    return a LIST of content blocks (`[{"type": "text", "text": "..."},
    {"type": "tool_use", ...}]`) when a message mixes reasoning text with a
    tool call. Only the text blocks are kept here — tool-call blocks are
    already captured structurally via `AIMessage.tool_calls`, so including
    their raw dict form again would just duplicate that information as
    noise in the transcript's `content` field.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
            else:
                parts.append(str(block))
        return "\n".join(p for p in parts if p)
    return str(content) if content else ""


def messages_to_transcript(
    messages: list[BaseMessage], *, start_turn: int = 0
) -> list[TranscriptEntry]:
    """Serialize a graph run's raw message list into the "chat with tools"
    transcript `VerificationReport.transcript` persists — every message the
    LLM produced (its reasoning, each tool call with arguments) and every
    tool response it read, in order. Called on the FINAL state's `messages`
    after a graph run completes (see `agent.verifier.verify_candidate`), or
    incrementally on each new SLICE of messages while streaming — `start_turn`
    is for the latter: pass the number of messages already transcribed so
    far so a streamed slice's `TranscriptEntry.turn` values continue the
    same numbering the final, complete transcript will use, rather than
    each restarting at 0.

    Placeholder `ToolMessage`s `_close_dangling_tool_calls` synthesizes are
    included like any other tool response (their content already says
    "not executed" — no special-casing needed here).
    """
    entries: list[TranscriptEntry] = []
    for offset, message in enumerate(messages):
        turn = start_turn + offset
        if isinstance(message, SystemMessage):
            entries.append(
                TranscriptEntry(turn=turn, role="system", content=_message_text(message.content))
            )
        elif isinstance(message, HumanMessage):
            entries.append(
                TranscriptEntry(turn=turn, role="human", content=_message_text(message.content))
            )
        elif isinstance(message, AIMessage):
            tool_calls = [
                ToolCallRecord(name=call["name"], args=call.get("args", {}), id=call.get("id", ""))
                for call in message.tool_calls
            ]
            entries.append(
                TranscriptEntry(
                    turn=turn,
                    role="ai",
                    content=_message_text(message.content),
                    tool_calls=tool_calls,
                )
            )
        elif isinstance(message, ToolMessage):
            entries.append(
                TranscriptEntry(
                    turn=turn,
                    role="tool",
                    content=_message_text(message.content),
                    tool_call_id=message.tool_call_id,
                )
            )
        # Any other BaseMessage subtype is skipped rather than guessed at —
        # none of the four above are ever unrecognized in practice, since
        # every message this graph produces or consumes is one of them.
    return entries


def _repair_request(error: ValidationError) -> str:
    return (
        f"Your previous response failed schema validation:\n{error}\n\n"
        "Return a corrected verdict that fully satisfies the required schema."
    )


__all__ = ["VerifierState", "build_verifier_graph", "messages_to_transcript"]
