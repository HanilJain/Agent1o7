"""Tests for fw_audit.stage3_analysis.agent.prompts."""

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage

from fw_audit.stage3_analysis.agent.prompts import SYSTEM_PROMPT, build_messages


def test_system_prompt_contains_required_sections():
    headings = [
        "# ROLE",
        "# CONTEXT",
        "# OBJECTIVE",
        "# ANALYSIS METHOD",
        "# EVIDENCE",
        "# RANKING",
    ]
    for heading in headings:
        assert heading in SYSTEM_PROMPT


def test_system_prompt_contains_ranking_vocabulary():
    terms = [
        "CONFIRMED",
        "HIGH",
        "MEDIUM",
        "LOW",
        "ESCALATE",
        "CONTEXT_REQUIRED",
        "MERGE",
        "DISCARD",
    ]
    for term in terms:
        assert term in SYSTEM_PROMPT


def test_build_messages_returns_system_and_human():
    messages = build_messages(
        "int main(void) { return 0; }", chunk_id="test#0000", rootfs_path="bin/test"
    )
    assert len(messages) == 2
    assert isinstance(messages[0], SystemMessage)
    assert isinstance(messages[1], HumanMessage)
    assert messages[0].content == SYSTEM_PROMPT


def test_build_messages_adds_line_markers():
    messages = build_messages("line one\nline two", chunk_id="test#0000", rootfs_path="bin/test")
    human_content = messages[1].content
    assert "[L1] line one" in human_content
    assert "[L2] line two" in human_content


def test_build_messages_includes_chunk_metadata_header():
    messages = build_messages(
        "int f(void) {}",
        chunk_id="test_bin#0003",
        rootfs_path="bin/test",
        function_names=["f", "g"],
    )
    human_content = messages[1].content
    assert "chunk_id: test_bin#0003" in human_content
    assert "rootfs_path: bin/test" in human_content
    assert "functions: f, g" in human_content


def test_build_messages_without_function_names_omits_functions_line():
    messages = build_messages("int f(void) {}", chunk_id="test#0000", rootfs_path="bin/test")
    human_content = messages[1].content
    assert "functions:" not in human_content
