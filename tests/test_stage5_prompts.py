"""Tests for `fw_audit.stage5_verification.agent.prompts`.

The generator-prompt assertions are the highest-value cheap regression
guard in this integration: the ported pipeline's original prompt taught a
CPG-loading contract (`--param cpgPath=`) that `tools/joern_tool.py`
documents as broken here — these tests fail loudly if that mistake is ever
reintroduced.
"""

from __future__ import annotations

from fw_audit.common.findings import (
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.stage5_verification.agent.prompts import (
    EVALUATOR_SYSTEM_PROMPT,
    GENERATOR_SYSTEM_PROMPT,
    build_evaluator_messages,
    build_generator_messages,
    render_finding_brief,
)
from fw_audit.stage5_verification.candidate_index import VerificationCandidate


def _candidate() -> VerificationCandidate:
    finding = Finding(
        finding_id="c1",
        title="OS command injection via argv[2]",
        category="command_execution",
        cwe=["CWE-78"],
        severity=Severity(impact=5, exploitability=4, reachability=3),
        confidence=Confidence.CONFIRMED,
        decision=Decision.ESCALATE,
        evidence_span=EvidenceSpan(
            function_id="FUN_00026938", line_start=1, line_end=5, code="system(buf);"
        ),
        source=FindingSource(
            expression="argv[2]", type="FUNCTION_PARAMETER", attacker_control="YES"
        ),
        sink=FindingSink(expression="system(buf)", type="COMMAND_EXECUTION"),
        data_flow=["argv[2] -> buf via strcpy", "buf -> system()"],
        security_condition="unsanitized argv reaches system()",
        exploitability="attacker controls argv[2]",
        impact="remote command execution",
        why_vulnerable="no sanitization before system()",
        why_not_false_positive="direct unguarded call",
    )
    return VerificationCandidate(
        global_id="sbin_rc__FUN_00026938#0000::c1",
        chunk_id="sbin_rc__FUN_00026938#0000",
        bin_id="sbin_rc",
        finding=finding,
        source_path=None,
    )


def test_generator_prompt_teaches_println_requirement():
    assert "println" in GENERATOR_SYSTEM_PROMPT
    assert "RESULT:" in GENERATOR_SYSTEM_PROMPT


def test_generator_prompt_does_not_teach_broken_cpgpath_contract():
    # The ported pipeline's prompt told the model to LOAD the CPG via a
    # `cpgPath` parameter -- verified BROKEN against this repo's actual
    # joern invocation (see tools/joern_tool.py's docstring). The rewritten
    # prompt may still mention "cpgPath" but only to say "never reference
    # this" -- it must never instruct the model to use it.
    lowered = GENERATOR_SYSTEM_PROMPT.lower()
    assert "load the cpg from the path passed in via" not in lowered
    assert "never reference a `cpgpath`" in lowered or "never reference a cpgpath" in lowered
    # It should instead teach the positional/auto-imported contract.
    assert "positionally" in lowered or "auto-import" in lowered
    assert "never call `importcpg`" in lowered or "never call importcpg" in lowered


def test_generator_prompt_forbids_shell_and_exploit_content():
    lowered = GENERATOR_SYSTEM_PROMPT.lower()
    assert "shell" in lowered
    assert "exploit" in lowered or "payload" in lowered


def test_evaluator_prompt_covers_both_failure_modes():
    assert "PASS" in EVALUATOR_SYSTEM_PROMPT
    assert "FAIL_RETRY" in EVALUATOR_SYSTEM_PROMPT
    assert "don't loop" in EVALUATOR_SYSTEM_PROMPT.lower()


def test_evaluator_prompt_treats_empty_stdout_as_broken_script():
    lowered = EVALUATOR_SYSTEM_PROMPT.lower()
    assert "empty" in lowered
    assert "forgot" in lowered or "println" in lowered


def test_render_finding_brief_includes_key_fields():
    brief = render_finding_brief(_candidate())
    assert "unsanitized argv reaches system()" in brief
    assert "argv[2]" in brief
    assert "system(buf)" in brief
    assert "argv[2] -> buf via strcpy" in brief
    assert "buf -> system()" in brief
    assert "FUN_00026938" in brief


def test_build_generator_messages_default_system_prompt():
    brief = render_finding_brief(_candidate())
    messages = build_generator_messages(brief=brief)
    assert messages[0].content == GENERATOR_SYSTEM_PROMPT
    assert brief in messages[1].content


def test_build_generator_messages_system_prompt_override():
    brief = render_finding_brief(_candidate())
    messages = build_generator_messages(brief=brief, system_prompt="CUSTOM PROMPT")
    assert messages[0].content == "CUSTOM PROMPT"


def test_build_generator_messages_embeds_retry_feedback_and_previous_script():
    brief = render_finding_brief(_candidate())
    messages = build_generator_messages(
        brief=brief,
        feedback="you forgot println",
        previous_script="cpg.method.l",
        previous_stdout="",
        previous_stderr="",
    )
    user_text = messages[1].content
    assert "you forgot println" in user_text
    assert "cpg.method.l" in user_text


def test_build_generator_messages_no_retry_suffix_when_no_feedback():
    brief = render_finding_brief(_candidate())
    messages = build_generator_messages(brief=brief)
    assert "Your previous attempt failed evaluation" not in messages[1].content


def test_build_evaluator_messages_includes_script_and_output():
    brief = render_finding_brief(_candidate())
    messages = build_evaluator_messages(
        brief=brief, script="println(1)", stdout="1", stderr="", returncode=0
    )
    assert messages[0].content == EVALUATOR_SYSTEM_PROMPT
    assert "println(1)" in messages[1].content
    assert "exit_code: 0" in messages[1].content
