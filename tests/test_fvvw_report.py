"""Tests for `stage5_verification.fvvw.report` — Stage 5 FVVW v3 Phase 6.
Same duck-typed `_ScriptedLLM` mechanics as the other FVVW LLM-node tests."""

from __future__ import annotations

from langchain_core.messages import AIMessage

from fw_audit.common.findings import (
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.common.verification import Agreement, TrackResult, VerificationVerdict
from fw_audit.config.settings import Settings
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.fvvw.report import render_report_brief, write_report


class _ScriptedLLM:
    def __init__(self, responses: list) -> None:
        self._responses = list(responses)
        self.calls: list = []

    async def ainvoke(self, messages, config=None):
        self.calls.append(messages)
        return AIMessage(content=self._responses.pop(0))


def _finding() -> Finding:
    return Finding(
        finding_id="candidate_001",
        title="Command injection via argv[1]",
        category="command_execution",
        cwe=["CWE-78"],
        severity=Severity(impact=4, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=Decision.ESCALATE,
        evidence_span=EvidenceSpan(function_id="f", line_start=1, line_end=2, code="x"),
        source=FindingSource(
            expression="argv[1]", type="FUNCTION_PARAMETER", attacker_control="YES"
        ),
        sink=FindingSink(expression="system(cmd)", type="COMMAND_EXECUTION"),
        security_condition="argv[1] reaches system() without sanitization",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )


def _candidate() -> VerificationCandidate:
    return VerificationCandidate(
        global_id="vulnbin#0000::candidate_001",
        chunk_id="vulnbin#0000",
        bin_id="vulnbin",
        finding=_finding(),
        source_path=None,
    )


def test_render_report_brief_includes_finding_both_tracks_and_reconciliation():
    static_result = TrackResult(
        verdict=VerificationVerdict.CONFIRMED,
        proved_hypothesis="A",
        evidence={
            "summary": "flow found",
            "confidence": "HIGH",
            "attempts": [
                {
                    "attempt_index": 0,
                    "script": "cpg.method...",
                    "stdout": "RESULT: FLOW_FOUND",
                }
            ],
        },
    )
    dynamic_result = TrackResult(
        verdict=VerificationVerdict.CONFIRMED, proved_hypothesis="A", evidence={"reason": ""}
    )

    brief = render_report_brief(
        candidate=_candidate(),
        finding=_finding(),
        static_result=static_result,
        dynamic_result=dynamic_result,
        agreement=Agreement.CONCORDANT_CONFIRM,
        mechanism_confidence="confirmed_strong",
        reachability_confidence="confirmed",
        residual_unknowns=["guard X was forced"],
        dynamic_gdb_transcript="Breakpoint 1, 0x1000 in main ()",
    )

    assert "Command injection via argv[1]" in brief
    assert "RESULT: FLOW_FOUND" in brief  # raw Joern output, verbatim
    assert "Breakpoint 1, 0x1000 in main ()" in brief  # raw GDB transcript, verbatim
    assert "agreement: concordant_confirm" in brief
    assert "mechanism_confidence: confirmed_strong" in brief
    assert "guard X was forced" in brief


def test_render_report_brief_handles_missing_dynamic_transcript():
    brief = render_report_brief(
        candidate=_candidate(),
        finding=_finding(),
        static_result=TrackResult(verdict=VerificationVerdict.CONFIRMED),
        dynamic_result=TrackResult(verdict=VerificationVerdict.ERROR),
        agreement=Agreement.ONE_SIDED,
        mechanism_confidence="confirmed_single_track",
        reachability_confidence="conditional",
        residual_unknowns=[],
    )
    assert "did not run to completion" in brief


async def test_write_report_returns_llm_output_verbatim():
    llm = _ScriptedLLM(["# Disclosure Report\n\nExecutive summary here."])
    report_md = await write_report(
        candidate=_candidate(),
        finding=_finding(),
        static_result=TrackResult(verdict=VerificationVerdict.CONFIRMED),
        dynamic_result=TrackResult(verdict=VerificationVerdict.CONFIRMED),
        agreement=Agreement.CONCORDANT_CONFIRM,
        mechanism_confidence="confirmed_strong",
        reachability_confidence="confirmed",
        residual_unknowns=[],
        dynamic_gdb_transcript="",
        llm=llm,
        settings=Settings(_env_file=None),
    )
    assert report_md == "# Disclosure Report\n\nExecutive summary here."
    assert len(llm.calls) == 1


async def test_write_report_honors_system_prompt_override():
    llm = _ScriptedLLM(["report"])
    await write_report(
        candidate=_candidate(),
        finding=_finding(),
        static_result=TrackResult(verdict=VerificationVerdict.CONFIRMED),
        dynamic_result=TrackResult(verdict=VerificationVerdict.CONFIRMED),
        agreement=Agreement.CONCORDANT_CONFIRM,
        mechanism_confidence="confirmed_strong",
        reachability_confidence="confirmed",
        residual_unknowns=[],
        dynamic_gdb_transcript="",
        llm=llm,
        settings=Settings(_env_file=None),
        system_prompt="custom report prompt",
    )
    assert llm.calls[0][0].content == "custom report prompt"


async def test_write_report_strips_whitespace():
    llm = _ScriptedLLM(["  \n# Report\n\n  "])
    report_md = await write_report(
        candidate=_candidate(),
        finding=_finding(),
        static_result=TrackResult(verdict=VerificationVerdict.CONFIRMED),
        dynamic_result=TrackResult(verdict=VerificationVerdict.CONFIRMED),
        agreement=Agreement.CONCORDANT_CONFIRM,
        mechanism_confidence="confirmed_strong",
        reachability_confidence="confirmed",
        residual_unknowns=[],
        dynamic_gdb_transcript="",
        llm=llm,
        settings=Settings(_env_file=None),
    )
    assert report_md == "# Report"
