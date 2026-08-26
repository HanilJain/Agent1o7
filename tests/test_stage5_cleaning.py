"""Tests for `fw_audit.stage5_verification.agent.cleaning` — response
sanitation for a local (qwen3-class) generator/evaluator pair."""

from __future__ import annotations

from fw_audit.stage5_verification.agent.cleaning import (
    clean_json_payload,
    clean_script,
    extract_json_object,
    message_text,
    strip_code_fence,
    strip_think,
)

# --------------------------------------------------------------------- #
# message_text (moved from the old graph._message_text)
# --------------------------------------------------------------------- #


def test_message_text_passes_through_plain_string():
    assert message_text("hello") == "hello"


def test_message_text_flattens_anthropic_style_content_blocks():
    content = [
        {"type": "text", "text": "Let me check the CPG."},
        {"type": "tool_use", "name": "run_joern_script", "input": {"script": "cpg.method.l"}},
    ]
    assert message_text(content) == "Let me check the CPG."


def test_message_text_handles_empty_and_none():
    assert message_text("") == ""
    assert message_text(None) == ""


# --------------------------------------------------------------------- #
# strip_think
# --------------------------------------------------------------------- #


def test_strip_think_removes_closed_block():
    text = "<think>reasoning about the finding</think>final answer"
    assert strip_think(text) == "final answer"


def test_strip_think_removes_multiple_closed_blocks():
    text = "<think>a</think>middle<think>b</think>end"
    assert strip_think(text) == "middleend"


def test_strip_think_handles_orphan_leading_close_tag():
    # Some Ollama chat templates emit the opening <think> as part of the
    # template, so the model's own text starts mid-thought with only a
    # closing tag visible.
    text = "still reasoning here...</think>the real answer"
    assert strip_think(text) == "the real answer"


def test_strip_think_returns_unchanged_when_block_never_closes():
    # num_predict ran out mid-reasoning -- returning "" would be worse than
    # leaving the (unusable) text as-is for the caller to fail on normally.
    text = "<think>reasoning that never finishes because the budget ran out"
    assert strip_think(text) == text


def test_strip_think_returns_unchanged_when_no_think_tags_present():
    text = "println(cpg.method.name.l)"
    assert strip_think(text) == text


def test_strip_think_is_case_and_whitespace_tolerant():
    text = "<THINK >hmm</THINK  >answer"
    assert strip_think(text) == "answer"


# --------------------------------------------------------------------- #
# strip_code_fence
# --------------------------------------------------------------------- #


def test_strip_code_fence_removes_language_tagged_fence():
    text = "```scala\nprintln(1)\n```"
    assert strip_code_fence(text) == "println(1)"


def test_strip_code_fence_removes_bare_fence():
    text = "```\n{\"verdict\": \"PASS\"}\n```"
    assert strip_code_fence(text) == '{"verdict": "PASS"}'


def test_strip_code_fence_leaves_unfenced_text_alone():
    text = "println(cpg.method.name.l)"
    assert strip_code_fence(text) == text


def test_strip_code_fence_leaves_partial_fence_alone():
    # A fence only at the start (no matching close) is not a "whole text is
    # fenced" case -- leave it as-is rather than mangling it.
    text = "```scala\nprintln(1)"
    assert strip_code_fence(text) == text


# --------------------------------------------------------------------- #
# extract_json_object
# --------------------------------------------------------------------- #


def test_extract_json_object_pure_json():
    text = '{"verdict": "PASS", "confidence": "HIGH"}'
    assert extract_json_object(text) == text


def test_extract_json_object_with_leading_prose():
    text = 'Sure, here is my judgement:\n{"verdict": "PASS"}'
    assert extract_json_object(text) == '{"verdict": "PASS"}'


def test_extract_json_object_with_trailing_prose():
    text = '{"verdict": "PASS"}\nLet me know if you need anything else.'
    assert extract_json_object(text) == '{"verdict": "PASS"}'


def test_extract_json_object_ignores_braces_inside_string_literals():
    text = '{"reasoning": "the flow uses cpg.call(\\"foo{bar}\\")", "verdict": "PASS"}'
    assert extract_json_object(text) == text


def test_extract_json_object_handles_nested_objects():
    text = '{"outer": {"inner": 1}, "verdict": "PASS"}'
    assert extract_json_object(text) == text


def test_extract_json_object_returns_none_when_no_json_present():
    assert extract_json_object("no json here at all") is None


def test_extract_json_object_returns_none_on_unbalanced_braces():
    assert extract_json_object('{"verdict": "PASS"') is None


# --------------------------------------------------------------------- #
# clean_script / clean_json_payload (full pipelines)
# --------------------------------------------------------------------- #


def test_clean_script_strips_think_and_fence_and_whitespace():
    raw = "<think>let me write a query</think>```scala\nprintln(\"RESULT: FLOW_FOUND\")\n```  "
    assert clean_script(raw) == 'println("RESULT: FLOW_FOUND")'


def test_clean_script_handles_plain_unwrapped_script():
    raw = 'println("RESULT: FLOW_NOT_FOUND")'
    assert clean_script(raw) == raw


def test_clean_json_payload_strips_think_and_fence_and_extracts_object():
    raw = (
        "<think>evaluating the output</think>```json\n"
        '{"verdict": "PASS", "confidence": "HIGH", "reasoning": "ok", "feedback_for_retry": ""}'
        "\n```"
    )
    result = clean_json_payload(raw)
    assert result == (
        '{"verdict": "PASS", "confidence": "HIGH", "reasoning": "ok", "feedback_for_retry": ""}'
    )


def test_clean_json_payload_returns_none_for_pure_prose():
    assert clean_json_payload("I think this looks fine, no JSON needed.") is None
