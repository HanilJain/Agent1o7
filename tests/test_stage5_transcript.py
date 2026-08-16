"""Tests for the agent transcript feature: `agent.graph.messages_to_transcript`,
`agent.verifier.verify_candidate`'s `on_step` streaming, and
`report_writer`'s "Agent transcript" section."""

from __future__ import annotations

from datetime import UTC, datetime

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from fw_audit.common.findings import (
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.common.verification import (
    CpgBuildRecord,
    VerificationReport,
    VerificationVerdict,
)
from fw_audit.stage5_verification.agent.graph import messages_to_transcript
from fw_audit.stage5_verification.report_writer import render_report


def test_messages_to_transcript_maps_each_role():
    messages = [
        SystemMessage(content="be a verifier"),
        HumanMessage(content="verify this finding"),
        AIMessage(
            content="I'll build the CPG first.",
            tool_calls=[{"name": "build_cpg", "args": {}, "id": "call_1"}],
        ),
        ToolMessage(content="CPG built successfully in 2.0s.", tool_call_id="call_1"),
        AIMessage(content="CONFIRMED, based on the query output."),
    ]

    entries = messages_to_transcript(messages)

    assert [e.role for e in entries] == ["system", "human", "ai", "tool", "ai"]
    assert entries[0].turn == 0
    assert entries[1].content == "verify this finding"
    assert entries[2].content == "I'll build the CPG first."
    assert entries[2].tool_calls[0].name == "build_cpg"
    assert entries[2].tool_calls[0].id == "call_1"
    assert entries[3].tool_call_id == "call_1"
    assert entries[3].content == "CPG built successfully in 2.0s."
    assert entries[4].tool_calls == []


def test_messages_to_transcript_start_turn_continues_numbering():
    messages = [AIMessage(content="second batch")]
    entries = messages_to_transcript(messages, start_turn=5)
    assert entries[0].turn == 5


def test_messages_to_transcript_flattens_anthropic_style_content_blocks():
    """Anthropic-style content is a list of blocks mixing text and tool_use
    — only the text blocks should surface in `content`; the tool_use block
    is redundant with `AIMessage.tool_calls` and would just duplicate noise."""
    message = AIMessage(
        content=[
            {"type": "text", "text": "Let me check the CPG."},
            {"type": "tool_use", "name": "run_joern_script", "input": {"script": "cpg.method.l"}},
        ],
        tool_calls=[{"name": "run_joern_script", "args": {"script": "cpg.method.l"}, "id": "c1"}],
    )
    entries = messages_to_transcript([message])
    assert entries[0].content == "Let me check the CPG."
    assert "tool_use" not in entries[0].content


async def test_verify_candidate_on_step_receives_incremental_new_turns(tmp_path, monkeypatch):
    from fw_audit.stage5_verification.agent import verifier as verifier_mod
    from fw_audit.stage5_verification.candidate_index import VerificationCandidate

    finding = Finding(
        finding_id="c1",
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
    source = tmp_path / "whole.c"
    source.write_text("int main(){}", encoding="utf-8")
    candidate = VerificationCandidate(
        global_id="bin#0000::c1",
        chunk_id="bin#0000",
        bin_id="bin",
        finding=finding,
        source_path=source,
    )

    class _FakeAvailableExecutor:
        def available(self) -> bool:
            return True

    class _FakeStreamGraph:
        """Mimics LangGraph's `astream(..., stream_mode='values')`: yields
        the FULL accumulated state after each step."""

        async def astream(self, initial_state, stream_mode):
            assert stream_mode == "values"
            messages = list(initial_state["messages"])
            yield {**initial_state, "messages": messages}

            messages = [
                *messages,
                AIMessage(
                    content="calling build_cpg",
                    tool_calls=[{"name": "build_cpg", "args": {}, "id": "c1"}],
                ),
            ]
            yield {**initial_state, "messages": messages, "iterations": 1}

            messages = [*messages, ToolMessage(content="CPG built.", tool_call_id="c1")]
            yield {**initial_state, "messages": messages, "iterations": 1}

            messages = [*messages, AIMessage(content="done")]
            yield {
                **initial_state,
                "messages": messages,
                "iterations": 2,
                "verdict": VerificationVerdict.CONFIRMED,
                "verdict_confidence": "HIGH",
                "verdict_summary": "s",
                "verdict_evidence": "e",
                "verdict_next_steps": [],
            }

    from fw_audit.config.settings import Settings

    monkeypatch.setattr(verifier_mod, "joern_executor", lambda settings: _FakeAvailableExecutor())
    monkeypatch.setattr(verifier_mod, "get_llm_for_agent", lambda role, settings=None: object())
    monkeypatch.setattr(verifier_mod, "build_joern_tools", lambda **kwargs: [])
    monkeypatch.setattr(verifier_mod, "build_verifier_graph", lambda **kwargs: _FakeStreamGraph())

    received_batches: list[list] = []

    def on_step(entries):
        received_batches.append(entries)

    report = await verifier_mod.verify_candidate(
        candidate,
        db_subfolder=tmp_path,
        settings=Settings(_env_file=None),
        on_step=on_step,
    )

    # LangGraph's stream_mode="values" yields the initial input state as its
    # first value too (system+human, the task handed to the agent), so that
    # counts as one batch; the following 3 steps each add exactly one new
    # message -> 4 callbacks total.
    assert len(received_batches) == 4
    assert [e.role for e in received_batches[0]] == ["system", "human"]
    assert received_batches[1][0].role == "ai"
    assert received_batches[1][0].tool_calls[0].name == "build_cpg"
    assert received_batches[2][0].role == "tool"
    assert received_batches[2][0].content == "CPG built."
    assert received_batches[3][0].role == "ai"

    # turn numbers must continue correctly across callback batches, matching
    # the final transcript's own numbering (not restarted per batch).
    assert received_batches[1][0].turn == received_batches[0][-1].turn + 1
    assert received_batches[2][0].turn == received_batches[1][0].turn + 1
    assert received_batches[3][0].turn == received_batches[2][0].turn + 1

    # and the returned report's full transcript must match what was streamed.
    assert report.verdict == VerificationVerdict.CONFIRMED
    non_system_roles = [e.role for e in report.transcript if e.role != "system"]
    assert non_system_roles == ["human", "ai", "tool", "ai"]


def _report_with_transcript() -> VerificationReport:
    from fw_audit.common.verification import ToolCallRecord, TranscriptEntry

    return VerificationReport(
        global_id="bin#0000::c1",
        bin_id="bin",
        model="anthropic:claude-sonnet-4-5",
        cpg_build=CpgBuildRecord(command="joern-parse", ok=True, duration_seconds=1.0),
        transcript=[
            TranscriptEntry(turn=0, role="system", content="be a verifier"),
            TranscriptEntry(turn=1, role="human", content="verify this finding"),
            TranscriptEntry(
                turn=2,
                role="ai",
                content="I'll check the CPG first.",
                tool_calls=[ToolCallRecord(name="build_cpg", args={}, id="c1")],
            ),
            TranscriptEntry(turn=3, role="tool", content="CPG built.", tool_call_id="c1"),
            TranscriptEntry(turn=4, role="ai", content="CONFIRMED based on evidence."),
        ],
        verdict=VerificationVerdict.CONFIRMED,
        confidence="HIGH",
        summary="s",
        evidence="e",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )


def test_render_report_includes_transcript_section_and_omits_system():
    report = _report_with_transcript()
    md = render_report(report)

    assert "## Agent transcript" in md
    assert "be a verifier" not in md  # system prompt omitted
    assert "I'll check the CPG first." in md
    assert "calls `build_cpg()`" in md
    assert "CPG built." in md
    assert "CONFIRMED based on evidence." in md


def test_render_report_handles_empty_transcript():
    report = _report_with_transcript().model_copy(update={"transcript": []})
    md = render_report(report)
    assert "no transcript recorded" in md
