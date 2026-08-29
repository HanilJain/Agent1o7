"""Tests for `stage5_verification.fvvw.static_track` — Stage 5 FVVW v3
Phase 3. The key thing this guards: the EXISTING `build_verifier_graph` is
invoked completely unmodified — these tests exercise `run_static_track`
through the same `FakeExecutor` + `_ScriptedLLM` mechanics
`tests/test_stage5_graph.py` already uses against the real graph, so any
accidental behavior drift between the two call paths shows up here."""

from __future__ import annotations

import json
from pathlib import Path

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
from fw_audit.common.verification import StaticPlan, VerificationVerdict
from fw_audit.config.settings import Settings
from fw_audit.executors.base import ExecutionResult
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.fvvw.static_track import (
    render_static_brief,
    run_static_track,
)


class _ScriptedLLM:
    def __init__(self, responses: list) -> None:
        self._responses = list(responses)
        self.calls: list = []

    async def ainvoke(self, messages, config=None):
        self.calls.append(messages)
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return AIMessage(content=item)


def _finding() -> Finding:
    return Finding(
        finding_id="candidate_001",
        title="t",
        category="command_execution",
        severity=Severity(impact=3, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=Decision.ESCALATE,
        evidence_span=EvidenceSpan(
            function_id="FUN_00026938", line_start=1, line_end=2, code="x"
        ),
        source=FindingSource(
            expression="argv[1]", type="FUNCTION_PARAMETER", attacker_control="YES"
        ),
        sink=FindingSink(expression="system(cmd)", type="COMMAND_EXECUTION"),
        security_condition="c",
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


def _static_plan() -> StaticPlan:
    return StaticPlan(
        target_function="FUN_00026938",
        expected_intermediate_calls=["strcpy", "snprintf"],
        sanitizer_patterns=["escapeshellarg"],
        decisive_observable="metacharacter present unmodified in the sink arg",
    )


def _verdict_json(verdict: str, *, confidence: str = "HIGH", reasoning: str = "ok") -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": reasoning,
            "feedback_for_retry": "",
        }
    )


def _make_executor(fake_executor_cls, *, script_outputs: list[str]):
    outputs = list(script_outputs)

    def on_run(command, files):
        if command.startswith("joern-parse"):
            (files / "cpg.bin").write_bytes(b"cpg")
            return ExecutionResult(
                command=command, returncode=0, stdout="", stderr="", timed_out=False
            )
        stdout = outputs.pop(0) if outputs else ""
        return ExecutionResult(
            command=command, returncode=0, stdout=stdout, stderr="", timed_out=False
        )

    return fake_executor_cls(on_run)


def test_render_static_brief_layers_plan_onto_existing_finding_brief():
    brief = render_static_brief(_candidate(), _static_plan())
    # The existing render_finding_brief's own output is present unchanged...
    assert "global_id: vulnbin#0000::candidate_001" in brief
    assert "## Finding:" in brief
    # ...plus the new strategy-plan section layered on top.
    assert "## Strategy plan" in brief
    assert "expected_intermediate_calls: strcpy, snprintf" in brief
    assert "decisive_observable: metacharacter present unmodified in the sink arg" in brief


async def test_run_static_track_confirmed_maps_to_hypothesis_a(fake_executor, tmp_path: Path):
    executor = _make_executor(fake_executor, script_outputs=["RESULT: FLOW_FOUND (1 path(s))"])
    generator = _ScriptedLLM(['println("RESULT: FLOW_FOUND (1 path(s))")'])
    evaluator = _ScriptedLLM([_verdict_json("PASS", reasoning="found it")])

    result = await run_static_track(
        _candidate(),
        _static_plan(),
        generator_llm=generator,
        evaluator_llm=evaluator,
        workspace_dir=tmp_path,
        executor=executor,
        settings=Settings(_env_file=None),
    )

    assert result.verdict == VerificationVerdict.CONFIRMED
    assert result.proved_hypothesis == "A"
    assert result.evidence["attempts"]
    assert result.evidence["cpg_build"]["ok"] is True


async def test_run_static_track_refuted_maps_to_hypothesis_b(fake_executor, tmp_path: Path):
    executor = _make_executor(fake_executor, script_outputs=["RESULT: FLOW_NOT_FOUND"])
    generator = _ScriptedLLM(['println("RESULT: FLOW_NOT_FOUND")'])
    evaluator = _ScriptedLLM([_verdict_json("PASS", reasoning="clean not-found")])

    result = await run_static_track(
        _candidate(),
        _static_plan(),
        generator_llm=generator,
        evaluator_llm=evaluator,
        workspace_dir=tmp_path,
        executor=executor,
        settings=Settings(_env_file=None),
    )

    assert result.verdict == VerificationVerdict.REFUTED
    assert result.proved_hypothesis == "B"


async def test_run_static_track_inconclusive_maps_to_no_hypothesis(
    fake_executor, tmp_path: Path
):
    executor = _make_executor(fake_executor, script_outputs=["no result marker printed"])
    generator = _ScriptedLLM(['println("no result marker printed")'])
    evaluator = _ScriptedLLM([_verdict_json("PASS", reasoning="ran but inconclusive")])

    result = await run_static_track(
        _candidate(),
        _static_plan(),
        generator_llm=generator,
        evaluator_llm=evaluator,
        workspace_dir=tmp_path,
        executor=executor,
        settings=Settings(_env_file=None),
    )

    assert result.verdict == VerificationVerdict.INCONCLUSIVE
    assert result.proved_hypothesis == "none"


async def test_run_static_track_cpg_failure_yields_error_track_result(
    fake_executor, tmp_path: Path
):
    def on_run(command, files):
        if command.startswith("joern-parse"):
            return ExecutionResult(
                command=command, returncode=1, stdout="", stderr="parse error", timed_out=False
            )
        return None

    executor = fake_executor(on_run)
    generator = _ScriptedLLM([])
    evaluator = _ScriptedLLM([])

    result = await run_static_track(
        _candidate(),
        _static_plan(),
        generator_llm=generator,
        evaluator_llm=evaluator,
        workspace_dir=tmp_path,
        executor=executor,
        settings=Settings(_env_file=None),
    )

    assert result.verdict == VerificationVerdict.ERROR
    assert result.proved_hypothesis == "none"
    # generator/evaluator never called — build_cpg -> conclude short-circuit
    assert len(generator.calls) == 0
    assert len(evaluator.calls) == 0
