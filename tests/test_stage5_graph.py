"""Tests for `fw_audit.stage5_verification.agent.graph` — the
generate/run/evaluate loop. Uses a duck-typed fake LLM (the graph only ever
calls `.ainvoke(messages) -> AIMessage` — no `bind_tools`, no
`with_structured_output`; that IS the point of this design) and the shared
`FakeExecutor` fixture for Joern (no real Docker/Joern involved)."""

from __future__ import annotations

import json
from pathlib import Path

from langchain_core.messages import AIMessage

from fw_audit.common.verification import EvaluationVerdict, VerificationVerdict
from fw_audit.config.settings import Settings
from fw_audit.executors.base import ExecutionResult
from fw_audit.stage5_verification.agent.graph import build_verifier_graph, final_status


class _ScriptedLLM:
    """The new graph only ever calls `.ainvoke(messages) -> AIMessage` —
    that is the whole surface. No bind_tools, no with_structured_output."""

    def __init__(self, responses: list) -> None:
        self._responses = list(responses)
        self.calls: list = []

    async def ainvoke(self, messages, config=None):
        # config=... is graph.py's LangSmith run_config passthrough (see
        # fw_audit.observability) — accepted and ignored here, same as a
        # real BaseChatModel would.
        self.calls.append(messages)
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return AIMessage(content=item)


def _make_executor(fake_executor_cls, *, script_outputs: list[str] | None = None):
    """A FakeExecutor that succeeds `joern-parse` (writing cpg.bin) and
    returns each of `script_outputs` in turn for successive `joern --script`
    calls (defaulting to empty stdout if exhausted)."""
    script_outputs = list(script_outputs or [])

    def on_run(command, files):
        if command.startswith("joern-parse"):
            (files / "cpg.bin").write_bytes(b"cpg")
            return ExecutionResult(
                command=command, returncode=0, stdout="", stderr="", timed_out=False
            )
        stdout = script_outputs.pop(0) if script_outputs else ""
        return ExecutionResult(
            command=command, returncode=0, stdout=stdout, stderr="", timed_out=False
        )

    return fake_executor_cls(on_run)


def _verdict_json(
    verdict: str,
    *,
    hypothesis_proved: str = "none",
    confidence: str = "HIGH",
    reasoning: str = "ok",
    feedback: str = "",
) -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "hypothesis_proved": hypothesis_proved,
            "confidence": confidence,
            "reasoning": reasoning,
            "feedback_for_retry": feedback,
        }
    )


def _failing_cpg_executor(fake_executor_cls):
    def on_run(command, files):
        if command.startswith("joern-parse"):
            return ExecutionResult(
                command=command, returncode=1, stdout="", stderr="parse error", timed_out=False
            )
        return None

    return fake_executor_cls(on_run)


async def _run_graph(
    *,
    workspace_dir: Path,
    executor,
    generator_responses: list,
    evaluator_responses: list,
    max_iterations: int = 5,
    repair_attempts: int = 1,
):
    cpg_build_holder: list = []
    attempts: list = []
    generator = _ScriptedLLM(generator_responses)
    evaluator = _ScriptedLLM(evaluator_responses)
    settings = Settings(_env_file=None, stage5_repair_attempts=repair_attempts)

    graph = build_verifier_graph(
        llm=generator,
        evaluator_llm=evaluator,
        workspace_dir=workspace_dir,
        executor=executor,
        settings=settings,
        max_iterations=max_iterations,
        cpg_build_holder=cpg_build_holder,
        attempts=attempts,
    )
    initial_state = {
        "brief": "brief text",
        "system_prompt": "system prompt text",
        "max_iterations": max_iterations,
        "transcript": [],
    }
    result = await graph.ainvoke(initial_state)
    return result, generator, evaluator, cpg_build_holder, attempts


async def test_pass_with_flow_found_marker_and_hypothesis_a_yields_confirmed(
    fake_executor, tmp_path
):
    executor = _make_executor(fake_executor, script_outputs=["RESULT: FLOW_FOUND (1 path(s))"])
    result, generator, evaluator, cpg_holder, attempts = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=['println("RESULT: FLOW_FOUND (1 path(s))")'],
        evaluator_responses=[
            _verdict_json("PASS", hypothesis_proved="A", reasoning="found it")
        ],
    )
    assert result["verdict"] == VerificationVerdict.CONFIRMED
    assert len(generator.calls) == 1
    assert len(attempts) == 1
    assert attempts[0].evaluator_verdict == "PASS"


async def test_pass_with_flow_not_found_marker_and_hypothesis_b_yields_refuted(
    fake_executor, tmp_path
):
    # REFUTED requires a POSITIVELY PROVED hypothesis B, not just a clean
    # FLOW_NOT_FOUND marker -- see the "none" case below, which is the
    # regression test for the reported bug (an empty flow result alone must
    # never mint a refutation).
    executor = _make_executor(fake_executor, script_outputs=["RESULT: FLOW_NOT_FOUND"])
    result, *_ = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=['println("RESULT: FLOW_NOT_FOUND")'],
        evaluator_responses=[
            _verdict_json("PASS", hypothesis_proved="B", reasoning="located sanitizer")
        ],
    )
    assert result["verdict"] == VerificationVerdict.REFUTED


async def test_pass_with_flow_not_found_and_hypothesis_none_retries_not_refutes(
    fake_executor, tmp_path
):
    # THE regression test for the reported bug: a script that prints a clean
    # RESULT: FLOW_NOT_FOUND but positively proves NOTHING (hypothesis_proved
    # == "none", e.g. the evaluator correctly recognized an unmodeled
    # sprintf-style propagator or a CPG-skipped method) must be RETRIED, not
    # accepted as a refutation. Round 2 then positively proves A.
    executor = _make_executor(
        fake_executor,
        script_outputs=["RESULT: FLOW_NOT_FOUND", "RESULT: FLOW_FOUND (1 path(s), two-legged)"],
    )
    result, generator, evaluator, _, attempts = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=[
            'println("RESULT: FLOW_NOT_FOUND")',
            'println("RESULT: FLOW_FOUND (1 path(s), two-legged)")',
        ],
        evaluator_responses=[
            _verdict_json(
                "PASS",
                hypothesis_proved="none",
                reasoning="empty reachableByFlows across an unmodeled sprintf propagator",
            ),
            _verdict_json("PASS", hypothesis_proved="A", reasoning="bridged two-legged"),
        ],
    )
    assert len(generator.calls) == 2
    assert result["verdict"] == VerificationVerdict.CONFIRMED
    # The first (converted) round is recorded as FAIL_RETRY, not PASS --
    # confirming the conversion actually happened, not just a lucky retry.
    assert attempts[0].evaluator_verdict == "FAIL_RETRY"
    assert attempts[1].evaluator_verdict == "PASS"


async def test_pass_without_any_marker_at_cap_yields_error(fake_executor, tmp_path):
    # A script that prints NO marker at all (nothing to even judge) is a
    # broken script, not an honest-but-unproven round -- it exhausts to
    # ERROR, never INCONCLUSIVE. Contrast with the "marker printed, cap
    # reached, nothing proved" case below, which IS INCONCLUSIVE.
    executor = _make_executor(fake_executor, script_outputs=["some output with no marker"])
    result, *_ = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=["println(cpg.method.name.l)"],
        evaluator_responses=[
            _verdict_json("PASS", hypothesis_proved="none", confidence="LOW", reasoning="no marker")
        ],
        max_iterations=1,
    )
    assert result["verdict"] == VerificationVerdict.ERROR


async def test_pass_with_marker_but_nothing_proved_at_cap_yields_inconclusive(
    fake_executor, tmp_path
):
    # A script that DID print a well-formed marker but never positively
    # proved either hypothesis, at the iteration cap, is INCONCLUSIVE --
    # "queries ran, nothing settled" -- not ERROR ("no evidence obtained at
    # all"). This is also what tags budget_exhausted for HITL.
    executor = _make_executor(fake_executor, script_outputs=["RESULT: FLOW_NOT_FOUND"])
    result, *_ = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=['println("RESULT: FLOW_NOT_FOUND")'],
        evaluator_responses=[
            _verdict_json(
                "PASS", hypothesis_proved="none", confidence="LOW", reasoning="engine health check failed"
            )
        ],
        max_iterations=1,
    )
    assert result["verdict"] == VerificationVerdict.INCONCLUSIVE


async def test_fail_stop_yields_error(fake_executor, tmp_path):
    executor = _make_executor(fake_executor, script_outputs=["RESULT: QUERY_ERROR"])
    result, *_ = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=["broken script"],
        evaluator_responses=[
            _verdict_json("FAIL_STOP", confidence="LOW", reasoning="unrecoverable")
        ],
    )
    assert result["verdict"] == VerificationVerdict.ERROR


async def test_fail_retry_regenerates_with_feedback_in_prompt(fake_executor, tmp_path):
    executor = _make_executor(
        fake_executor, script_outputs=["broken", "RESULT: FLOW_FOUND (1 path(s))"]
    )
    result, generator, evaluator, _, attempts = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=["bad script v1", "fixed script v2"],
        evaluator_responses=[
            _verdict_json(
                "FAIL_RETRY", confidence="LOW", reasoning="broken", feedback="you forgot println"
            ),
            _verdict_json("PASS", hypothesis_proved="A", reasoning="found it"),
        ],
    )
    assert result["verdict"] == VerificationVerdict.CONFIRMED
    assert len(generator.calls) == 2
    assert len(attempts) == 2
    second_call_text = " ".join(str(m.content) for m in generator.calls[1])
    assert "you forgot println" in second_call_text
    assert "bad script v1" in second_call_text


async def test_fail_retry_at_cap_downgrades_to_fail_stop_and_errors(fake_executor, tmp_path):
    executor = _make_executor(fake_executor, script_outputs=["broken", "still broken"])
    result, generator, *_ = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=["bad v1", "bad v2"],
        evaluator_responses=[
            _verdict_json("FAIL_RETRY", confidence="LOW", reasoning="broken v1", feedback="fix it"),
            _verdict_json(
                "FAIL_RETRY", confidence="LOW", reasoning="broken v2", feedback="fix more"
            ),
        ],
        max_iterations=2,
    )
    assert len(generator.calls) == 2
    assert result["verdict"] == VerificationVerdict.ERROR
    assert "max_iterations" in result["verdict_summary"]


async def test_cpg_build_failure_short_circuits_to_error_without_calling_llm(
    fake_executor, tmp_path
):
    executor = _failing_cpg_executor(fake_executor)
    result, generator, evaluator, cpg_holder, attempts = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=[],
        evaluator_responses=[],
    )
    assert result["verdict"] == VerificationVerdict.ERROR
    assert len(generator.calls) == 0
    assert len(evaluator.calls) == 0
    assert len(attempts) == 0
    assert cpg_holder[0].ok is False


async def test_evaluator_think_block_and_fences_are_stripped(fake_executor, tmp_path):
    executor = _make_executor(fake_executor, script_outputs=["RESULT: FLOW_FOUND (1 path(s))"])
    result, *_ = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=['println("RESULT: FLOW_FOUND (1 path(s))")'],
        evaluator_responses=[
            "<think>let me consider this</think>```json\n"
            + _verdict_json("PASS", hypothesis_proved="A")
            + "\n```"
        ],
    )
    assert result["verdict"] == VerificationVerdict.CONFIRMED


async def test_unparseable_evaluator_response_becomes_fail_stop(fake_executor, tmp_path):
    # Behaviour INVERTS from the old tool-calling graph: that graph RAISED
    # when repair attempts were exhausted on a bad structured-output call.
    # This graph never raises -- it degrades to FAIL_STOP -> ERROR, since a
    # local model's evaluator response failing to parse is an expected,
    # recoverable-at-the-report-level outcome, not a program bug.
    executor = _make_executor(fake_executor, script_outputs=["some output"])
    result, generator, evaluator, *_ = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=["a script"],
        evaluator_responses=["not json at all", "still not json"],
        repair_attempts=1,
    )
    assert len(evaluator.calls) == 2
    assert result["verdict"] == VerificationVerdict.ERROR


async def test_evaluator_json_repair_retry_succeeds_on_second_attempt(fake_executor, tmp_path):
    executor = _make_executor(fake_executor, script_outputs=["RESULT: FLOW_NOT_FOUND"])
    result, generator, evaluator, *_ = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=["a script"],
        evaluator_responses=[
            "garbage, not json",
            _verdict_json("PASS", hypothesis_proved="B", reasoning="clean, sanitizer located"),
        ],
        repair_attempts=1,
    )
    assert len(evaluator.calls) == 2
    assert result["verdict"] == VerificationVerdict.REFUTED


async def test_attempts_list_records_evaluator_verdict_per_attempt(fake_executor, tmp_path):
    executor = _make_executor(
        fake_executor, script_outputs=["broken", "RESULT: FLOW_FOUND (1 path(s))"]
    )
    result, generator, evaluator, _, attempts = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=["v1", "v2"],
        evaluator_responses=[
            _verdict_json("FAIL_RETRY", confidence="LOW", reasoning="broken", feedback="fix"),
            _verdict_json("PASS", hypothesis_proved="A", reasoning="found"),
        ],
    )
    assert len(attempts) == 2
    assert attempts[0].evaluator_verdict == "FAIL_RETRY"
    assert attempts[0].iteration == 1
    assert attempts[1].evaluator_verdict == "PASS"
    assert attempts[1].iteration == 2
    assert attempts[1].result_marker == "FLOW_FOUND"


async def test_transcript_entries_emitted_in_order_with_contiguous_turns(fake_executor, tmp_path):
    executor = _make_executor(fake_executor, script_outputs=["RESULT: FLOW_FOUND (1 path(s))"])
    result, *_ = await _run_graph(
        workspace_dir=tmp_path,
        executor=executor,
        generator_responses=['println("RESULT: FLOW_FOUND (1 path(s))")'],
        evaluator_responses=[_verdict_json("PASS", hypothesis_proved="A", reasoning="found it")],
    )
    transcript = result["transcript"]
    turns = [e.turn for e in transcript]
    assert turns == list(range(len(transcript)))
    roles = [e.role for e in transcript]
    assert roles == ["tool", "ai", "tool", "ai", "ai"]


# ---------------------------------------------------------------------- #
# final_status — direct unit coverage of the hypothesis-gated mapping.
# This is the regression test for the reported bug at its narrowest,
# fastest-to-run point: a marker/verdict combination alone must never
# produce CONFIRMED/REFUTED without a positively-proved hypothesis.
# ---------------------------------------------------------------------- #


def test_final_status_pass_with_hypothesis_a_is_confirmed():
    assert (
        final_status(EvaluationVerdict.PASS, "FLOW_FOUND", "A")
        == VerificationVerdict.CONFIRMED
    )


def test_final_status_pass_with_hypothesis_b_is_refuted():
    assert (
        final_status(EvaluationVerdict.PASS, "FLOW_NOT_FOUND", "B")
        == VerificationVerdict.REFUTED
    )


def test_final_status_pass_with_hypothesis_none_is_inconclusive():
    assert (
        final_status(EvaluationVerdict.PASS, "FLOW_NOT_FOUND", "none")
        == VerificationVerdict.INCONCLUSIVE
    )


def test_final_status_flow_not_found_alone_is_never_refuted():
    # THE narrowest regression test for the reported bug: a clean
    # FLOW_NOT_FOUND marker, with no hypothesis judgement supplied at all
    # (the empty-string default `final_status` uses when no evaluator round
    # produced one), must NOT fall back to marker-only REFUTED unless that's
    # the deliberate legacy/operator-injected path -- and even that path
    # requires the CALLER to have explicitly decided a human vouched for it.
    # Here we assert the hypothesis-aware branch takes priority: passing
    # hypothesis_proved="none" alongside the marker must win over the marker.
    assert (
        final_status(EvaluationVerdict.PASS, "FLOW_NOT_FOUND", "none")
        != VerificationVerdict.REFUTED
    )


def test_final_status_non_pass_is_always_error():
    assert final_status(EvaluationVerdict.FAIL_STOP, "FLOW_FOUND", "A") == (
        VerificationVerdict.ERROR
    )


def test_final_status_legacy_marker_only_path_for_operator_injected_scripts():
    # When hypothesis_proved is omitted entirely (the default ""), this is
    # the operator-injected-script path (fvvw.static_track.
    # run_injected_static_script) -- no evaluator round exists to source a
    # judgement from, so the legacy marker mapping applies.
    assert final_status(EvaluationVerdict.PASS, "FLOW_FOUND") == VerificationVerdict.CONFIRMED
    assert final_status(EvaluationVerdict.PASS, "FLOW_NOT_FOUND") == VerificationVerdict.REFUTED
    assert final_status(EvaluationVerdict.PASS, "FLOW_BLOCKED") == VerificationVerdict.REFUTED
    assert final_status(EvaluationVerdict.PASS, "QUERY_ERROR") == VerificationVerdict.INCONCLUSIVE
    assert final_status(EvaluationVerdict.PASS, None) == VerificationVerdict.INCONCLUSIVE
