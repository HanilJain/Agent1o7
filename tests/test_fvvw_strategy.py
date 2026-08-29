"""Tests for `stage5_verification.fvvw.strategy` — Stage 5 FVVW v3 Phase 2.
Uses the same duck-typed `_ScriptedLLM` pattern as
`tests/test_stage5_graph.py` — the strategy agent only ever calls
`.ainvoke(messages) -> AIMessage`, no tool-calling/structured-output."""

from __future__ import annotations

import json

import pytest
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
from fw_audit.common.verification import StrategyPlan, TargetMeta
from fw_audit.config.settings import Settings
from fw_audit.stage5_verification.candidate_index import VerificationCandidate
from fw_audit.stage5_verification.errors import Stage5InputError
from fw_audit.stage5_verification.fvvw.strategy import (
    build_strategy_messages,
    parse_strategy_response,
    render_strategy_brief,
    strategy_agent,
    validate_decisive_observable,
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
        data_flow=["strcpy(buf, argv[1])", "snprintf(cmd, ..., buf)", "system(cmd)"],
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


def _target() -> TargetMeta:
    return TargetMeta(
        arch="arm",
        endianness="little",
        is_64bit=False,
        pie=False,
        stripped=True,
        func_offset="0x00026938",
        dispatch_resolvable=True,
    )


def _valid_plan_json(observable: str = "metacharacter present unmodified in the sink arg") -> str:
    return json.dumps(
        {
            "threat_model": {"trust_boundary": "argv[1]", "access_requirement": "local_shell"},
            "hypotheses": {
                "a": "attacker-controlled argv[1] reaches system() unsanitized",
                "b": "the value is always escaped first",
                "decisive_observable": observable,
            },
            "static_plan": {
                "target_function": "FUN_00026938",
                "source_fields": ["argv[1]"],
                "sink_names": ["system"],
                "expected_intermediate_calls": ["strcpy", "snprintf"],
                "sanitizer_patterns": ["escapeshellarg"],
                "crosscheck_required": True,
                "decisive_observable": observable,
            },
            "dynamic_plan": {
                "reach_strategy": "inferior_call",
                "entry_addr": "0x00022594",
                "target_addr": "0x00026938",
                "sink_addr": "0x00020ba8",
                "guards": [],
                "argv_template": ["rc", "vuln_path"],
                "payload_marker": ";touch /tmp/claim_001_proof;",
                "required_signals": [
                    "sink_argument_capture",
                    "target_self_report",
                    "filesystem_artifact",
                ],
                "decisive_observable": observable,
            },
            "static_runnable": True,
            "dynamic_runnable": True,
        }
    )


# ---------------------------------------------------------------------- #
# render_strategy_brief / build_strategy_messages
# ---------------------------------------------------------------------- #


def test_render_strategy_brief_includes_finding_and_target_facts():
    brief = render_strategy_brief(_candidate(), _target())
    assert "candidate_001" in brief or "vulnbin#0000::candidate_001" in brief
    assert "argv[1] reaches system()" in brief
    assert "arch: arm" in brief
    assert "func_offset (validated entry point" in brief
    assert "0x00026938" in brief


def test_build_strategy_messages_returns_system_and_human():
    messages = build_strategy_messages(brief="test brief")
    assert len(messages) == 2
    assert messages[0].type == "system"
    assert messages[1].type == "human"
    assert "test brief" in messages[1].content


def test_build_strategy_messages_honors_system_prompt_override():
    messages = build_strategy_messages(brief="b", system_prompt="custom prompt")
    assert messages[0].content == "custom prompt"


# ---------------------------------------------------------------------- #
# validate_decisive_observable
# ---------------------------------------------------------------------- #


def test_validate_decisive_observable_true_when_all_nonempty():
    plan = StrategyPlan.model_validate_json(_valid_plan_json())
    assert validate_decisive_observable(plan) is True


def test_validate_decisive_observable_false_when_one_is_empty():
    payload = json.loads(_valid_plan_json())
    payload["static_plan"]["decisive_observable"] = ""
    plan = StrategyPlan.model_validate(payload)
    assert validate_decisive_observable(plan) is False


def test_validate_decisive_observable_false_when_whitespace_only():
    payload = json.loads(_valid_plan_json())
    payload["dynamic_plan"]["decisive_observable"] = "   "
    plan = StrategyPlan.model_validate(payload)
    assert validate_decisive_observable(plan) is False


# ---------------------------------------------------------------------- #
# parse_strategy_response
# ---------------------------------------------------------------------- #


def test_parse_strategy_response_valid_json():
    plan = parse_strategy_response(_valid_plan_json())
    assert isinstance(plan, StrategyPlan)
    assert plan.static_plan.target_function == "FUN_00026938"


def test_parse_strategy_response_none_on_garbage():
    assert parse_strategy_response("not json at all") is None


def test_parse_strategy_response_strips_think_and_fences():
    wrapped = f"<think>reasoning here</think>```json\n{_valid_plan_json()}\n```"
    plan = parse_strategy_response(wrapped)
    assert isinstance(plan, StrategyPlan)


# ---------------------------------------------------------------------- #
# strategy_agent (end-to-end with the scripted LLM)
# ---------------------------------------------------------------------- #


async def test_strategy_agent_returns_plan_on_first_valid_response():
    llm = _ScriptedLLM([_valid_plan_json()])
    plan = await strategy_agent(
        _candidate(), _target(), llm=llm, settings=Settings(_env_file=None)
    )
    assert isinstance(plan, StrategyPlan)
    assert len(llm.calls) == 1


async def test_strategy_agent_retries_on_invalid_json_then_succeeds():
    llm = _ScriptedLLM(["not json", _valid_plan_json()])
    plan = await strategy_agent(
        _candidate(), _target(), llm=llm, settings=Settings(_env_file=None)
    )
    assert isinstance(plan, StrategyPlan)
    assert len(llm.calls) == 2
    # second call includes the nudge as an added HumanMessage
    assert len(llm.calls[1]) == 3


async def test_strategy_agent_retries_on_mismatched_observable_then_succeeds():
    payload = json.loads(_valid_plan_json())
    payload["dynamic_plan"]["decisive_observable"] = ""
    broken = json.dumps(payload)
    llm = _ScriptedLLM([broken, _valid_plan_json()])
    plan = await strategy_agent(
        _candidate(), _target(), llm=llm, settings=Settings(_env_file=None)
    )
    assert isinstance(plan, StrategyPlan)
    assert len(llm.calls) == 2


async def test_strategy_agent_raises_stage5_input_error_after_exhausting_attempts():
    llm = _ScriptedLLM(["garbage 1", "garbage 2", "garbage 3"])
    with pytest.raises(Stage5InputError):
        await strategy_agent(
            _candidate(),
            _target(),
            llm=llm,
            settings=Settings(_env_file=None),
            max_regenerate_attempts=2,
        )
    assert len(llm.calls) == 3


async def test_strategy_agent_never_calls_more_than_max_attempts_plus_one():
    llm = _ScriptedLLM(["g1", "g2"])
    with pytest.raises(Stage5InputError):
        await strategy_agent(
            _candidate(),
            _target(),
            llm=llm,
            settings=Settings(_env_file=None),
            max_regenerate_attempts=1,
        )
    assert len(llm.calls) == 2
