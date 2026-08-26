"""Tests for the transcript feature: `agent.transcript`'s entry builders,
`agent.verifier.verify_candidate`'s `on_step` streaming, and
`report_writer`'s "Agent transcript" section."""

from __future__ import annotations

from datetime import UTC, datetime

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
    EvaluationVerdict,
    EvaluatorVerdict,
    JoernScriptAttempt,
    VerificationReport,
    VerificationVerdict,
)
from fw_audit.stage5_verification.agent import transcript as tx
from fw_audit.stage5_verification.report_writer import render_report

# --------------------------------------------------------------------- #
# agent.transcript emitter functions
# --------------------------------------------------------------------- #


def test_next_turn_is_current_transcript_length():
    assert tx.next_turn({}) == 0
    assert tx.next_turn({"transcript": []}) == 0
    assert tx.next_turn({"transcript": [1, 2, 3]}) == 3


def test_initial_transcript_maps_system_and_human_roles():
    entries = tx.initial_transcript(system_prompt="be a verifier", brief="verify this finding")
    assert [e.role for e in entries] == ["system", "human"]
    assert entries[0].turn == 0
    assert entries[0].content == "be a verifier"
    assert entries[1].turn == 1
    assert entries[1].content == "verify this finding"


def test_cpg_build_entry_ok():
    record = CpgBuildRecord(command="joern-parse", ok=True, duration_seconds=2.0)
    entry = tx.cpg_build_entry(2, record)
    assert entry.role == "tool"
    assert entry.tool_call_id == "build_cpg"
    assert "successfully" in entry.content


def test_cpg_build_entry_failure_includes_stderr():
    record = CpgBuildRecord(command="joern-parse", ok=False, duration_seconds=1.0, stderr="boom")
    entry = tx.cpg_build_entry(2, record)
    assert "FAILED" in entry.content
    assert "boom" in entry.content


def test_generator_entry_synthesizes_tool_call():
    entry = tx.generator_entry(3, script="println(1)", attempt_index=0, iteration=1)
    assert entry.role == "ai"
    assert entry.tool_calls[0].name == "run_joern_script"
    assert entry.tool_calls[0].args == {"script": "println(1)"}
    assert entry.tool_calls[0].id == "attempt_000"


def test_execution_entry_ok_uses_stdout():
    attempt = JoernScriptAttempt(
        attempt_index=0, script="s", stdout="output", ok=True, returncode=0
    )
    entry = tx.execution_entry(4, attempt)
    assert entry.role == "tool"
    assert entry.tool_call_id == "attempt_000"
    assert entry.content == "output"


def test_execution_entry_failure_includes_stderr():
    attempt = JoernScriptAttempt(
        attempt_index=2, script="s", stderr="syntax error", ok=False, returncode=1
    )
    entry = tx.execution_entry(4, attempt)
    assert "FAILED" in entry.content
    assert "syntax error" in entry.content
    assert entry.tool_call_id == "attempt_002"


def test_evaluator_entry_includes_verdict_and_feedback():
    verdict = EvaluatorVerdict(
        verdict=EvaluationVerdict.FAIL_RETRY,
        confidence="LOW",
        reasoning="broken script",
        feedback_for_retry="add println",
    )
    entry = tx.evaluator_entry(5, verdict)
    assert entry.role == "ai"
    assert "FAIL_RETRY" in entry.content
    assert "broken script" in entry.content
    assert "add println" in entry.content


def test_conclusion_entry():
    entry = tx.conclusion_entry(6, verdict=VerificationVerdict.CONFIRMED, summary="looks good")
    assert entry.role == "ai"
    assert "CONFIRMED" in entry.content
    assert "looks good" in entry.content


# --------------------------------------------------------------------- #
# verify_candidate on_step streaming
# --------------------------------------------------------------------- #


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
            transcript = list(initial_state["transcript"])
            yield {**initial_state, "transcript": transcript}

            transcript = [*transcript, tx.cpg_build_entry(len(transcript), CpgBuildRecord(ok=True))]
            yield {**initial_state, "transcript": transcript}

            attempt = JoernScriptAttempt(attempt_index=0, script="s", stdout="CPG built.", ok=True)
            transcript = [*transcript, tx.execution_entry(len(transcript), attempt)]
            yield {**initial_state, "transcript": transcript}

            verdict = EvaluatorVerdict(
                verdict=EvaluationVerdict.PASS, confidence="HIGH", reasoning="done"
            )
            transcript = [*transcript, tx.evaluator_entry(len(transcript), verdict)]
            yield {
                **initial_state,
                "transcript": transcript,
                "verdict": VerificationVerdict.CONFIRMED,
                "verdict_confidence": "HIGH",
                "verdict_summary": "s",
                "verdict_evidence": "e",
                "verdict_next_steps": [],
            }

    from fw_audit.config.settings import Settings

    monkeypatch.setattr(verifier_mod, "joern_executor", lambda settings: _FakeAvailableExecutor())
    monkeypatch.setattr(verifier_mod, "get_llm_for_agent", lambda role, settings=None: object())
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

    # stream_mode="values" yields the initial input state as its first
    # value too (system+human, the task handed to the pipeline), so that
    # counts as one batch; the following 3 steps each add exactly one new
    # entry -> 4 callbacks total.
    assert len(received_batches) == 4
    assert [e.role for e in received_batches[0]] == ["system", "human"]
    assert received_batches[1][0].role == "tool"
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
    assert non_system_roles == ["human", "tool", "tool", "ai"]


# --------------------------------------------------------------------- #
# report_writer's transcript rendering (unchanged behaviour, still exercised)
# --------------------------------------------------------------------- #


def _report_with_transcript() -> VerificationReport:
    from fw_audit.common.verification import ToolCallRecord, TranscriptEntry

    return VerificationReport(
        global_id="bin#0000::c1",
        bin_id="bin",
        model="generator=anthropic:claude-sonnet-4-5, evaluator=anthropic:claude-sonnet-4-5",
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
