"""Tests for `fw_audit.stage5_verification.live_console` — the gid-tagged
console echo `cmdlog.CommandLog.record()` calls on every kind of record."""

from __future__ import annotations

from fw_audit.common.verification import TranscriptEntry
from fw_audit.stage5_verification.cmdlog import CommandRecord
from fw_audit.stage5_verification.live_console import (
    LiveConsole,
    make_transcript_on_step,
    print_transcript_entries,
)


def _record(**overrides) -> CommandRecord:
    base = dict(
        seq=1,
        track="dynamic",
        node="bringup_agent",
        kind="llm_call",
        command="llm:bringup_agent",
        exit_code=None,
        ok=True,
        duration_ms=0,
        stdout="",
        stderr="",
        payload="",
        payload_path="",
        notes={},
        ts="2026-01-01T00:00:00Z",
    )
    base.update(overrides)
    return CommandRecord(**base)


def test_echo_llm_call_prints_prompt_and_raw_response(capsys):
    console = LiveConsole()
    console.echo(
        _record(
            kind="llm_call",
            payload="[system]\nyou are...\n\n[human]\ndo the thing",
            stdout="here is my raw completion",
            notes={"role": "bringup_agent"},
        ),
        gid="chunk::f1",
    )
    out = capsys.readouterr().out
    assert "[chunk::f1]" in out
    assert "PROMPT (before parse)" in out
    assert "do the thing" in out
    assert "RAW RESPONSE (before parse)" in out
    assert "here is my raw completion" in out


def test_echo_parsed_action_shows_after_parser_payload(capsys):
    console = LiveConsole()
    console.echo(
        _record(kind="parsed_action", payload='{"tool": "done", "args": {}}'), gid="g1"
    )
    out = capsys.readouterr().out
    assert "PARSED (after parse)" in out
    assert '"tool": "done"' in out


def test_echo_parse_failed_shows_raw_text(capsys):
    console = LiveConsole()
    console.echo(_record(kind="parse_failed", payload="not json at all", ok=False), gid="g1")
    out = capsys.readouterr().out
    assert "PARSE FAILED" in out
    assert "not json at all" in out


def test_echo_node_update_shows_repr(capsys):
    console = LiveConsole()
    console.echo(
        _record(node="health_gate", kind="node_update", payload="{'_health_ok': True}"),
        gid="g1",
    )
    out = capsys.readouterr().out
    assert "node 'health_gate'" in out
    assert "_health_ok" in out


def test_echo_generic_tool_call_shows_command_and_streams(capsys):
    console = LiveConsole()
    console.echo(
        _record(
            node="reach_target",
            kind="gdb_batch",
            command="gdb-multiarch -batch -x r.gdb t",
            stdout="Breakpoint 1 hit",
            stderr="",
            ok=True,
        ),
        gid="g1",
    )
    out = capsys.readouterr().out
    assert "reach_target/gdb_batch" in out
    assert "gdb-multiarch" in out
    assert "Breakpoint 1 hit" in out


def test_echo_truncates_long_text_for_console_only():
    console = LiveConsole(truncate_chars=20)
    long_text = "x" * 100
    record = _record(kind="llm_call", payload=long_text, stdout="short")
    truncated = console._t(record.payload)
    assert len(truncated) < len(long_text)
    assert "more chars" in truncated
    # The record itself (what would be persisted to JSONL) is untouched.
    assert record.payload == long_text


def test_print_transcript_entries_tags_lines_with_gid(capsys):
    entries = [TranscriptEntry(turn=1, role="ai", content="reasoning here")]
    print_transcript_entries("chunk::f1", entries)
    out = capsys.readouterr().out
    assert "[chunk::f1]" in out
    assert "reasoning here" in out


def test_make_transcript_on_step_binds_gid(capsys):
    on_step = make_transcript_on_step("chunk::f2")
    on_step([TranscriptEntry(turn=0, role="human", content="brief")])
    out = capsys.readouterr().out
    assert "[chunk::f2]" in out
