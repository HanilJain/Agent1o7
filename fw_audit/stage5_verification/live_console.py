"""Live, gid-tagged console echo for Stage 5's chain-of-thought visibility.

Deliberately separate from `cmdlog.py` (the JSONL sink of record) and from
`observability/` (LangSmith, cloud-only) — this is the THIRD, purely local
sink: a human watching a terminal. `LiveConsole.echo()` is the single entry
point `cmdlog.CommandLog.record()` calls after building a `CommandRecord`,
so every kind of Stage 5 I/O (LLM call, tool/sandbox call, a dynamic-graph
node's produced update, a parsed agentic action/decision, a parse failure)
flows through the SAME formatter, keyed off `CommandRecord.kind`.

Every line is prefixed `[gid]` so several concurrent `stage5_workers`
printing at once stay attributable to the right candidate — unlike HITL's
blocking prompt (which forces `stage5_workers=1`), this is non-blocking
output, so no such restriction is needed here. Console text is truncated at
`truncate_chars` for readability; the JSONL `cmdlog` writes is never
truncated, so it stays the source of truth for anything cut off here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fw_audit.common.verification import TranscriptEntry

if TYPE_CHECKING:
    from fw_audit.stage5_verification.cmdlog import CommandRecord

DEFAULT_TRUNCATE_CHARS = 3000

_PARSED_KINDS = {"parsed_action", "parsed_decision", "parsed_result"}


class LiveConsole:
    """A tiny, always-safe (never raises) console printer. Construct one per
    run/debug invocation when `--live`/`Settings.stage5_live_console` is on;
    pass `None` everywhere else — every consumer (`cmdlog.CommandLog`,
    `llm_logging.LoggingChatModel`) treats a missing `LiveConsole` as "stay
    silent," so this is purely additive.
    """

    def __init__(self, *, truncate_chars: int = DEFAULT_TRUNCATE_CHARS) -> None:
        self._truncate_chars = truncate_chars

    def _t(self, text: str) -> str:
        if len(text) <= self._truncate_chars:
            return text
        cut = len(text) - self._truncate_chars
        return (
            text[: self._truncate_chars]
            + f"\n   …({cut} more chars — full text in the command-log JSONL)"
        )

    def echo(self, record: CommandRecord, *, gid: str = "") -> None:
        """Format and print one `CommandRecord` — the single entry point
        `cmdlog.CommandLog.record()` calls. Branches on `record.kind` since
        an LLM call, a parsed agentic action, and a plain tool/sandbox call
        each read best in a different shape."""
        prefix = f"[{gid}]" if gid else "[?]"
        if record.kind == "llm_call":
            role = record.notes.get("role", record.node) if record.notes else record.node
            print(f"{prefix} >> LLM {role} PROMPT (before parse):\n{self._t(record.payload)}")
            print(f"{prefix} << LLM {role} RAW RESPONSE (before parse):\n{self._t(record.stdout)}")
        elif record.kind in _PARSED_KINDS:
            print(f"{prefix} == {record.node} PARSED (after parse): {self._t(record.payload)}")
        elif record.kind == "parse_failed":
            print(f"{prefix} == {record.node} PARSE FAILED, raw text: {self._t(record.payload)}")
        elif record.kind == "node_update":
            print(f"{prefix} >>> node {record.node!r} produced: {self._t(record.payload)}")
        else:
            status = "ok" if record.ok else "FAILED"
            print(f"{prefix} $ [{record.node}/{record.kind}] {record.command} ({status})")
            if record.payload:
                print(f"{prefix}   payload: {self._t(record.payload)}")
            if record.stdout:
                print(f"{prefix}   stdout: {self._t(record.stdout)}")
            if record.stderr:
                print(f"{prefix}   stderr: {self._t(record.stderr)}")
        print()


def print_transcript_entries(gid: str, entries: list[TranscriptEntry]) -> None:
    """Live console renderer for `agent.verifier.verify_candidate`'s
    `on_step` callback (relocated from `runner._print_transcript_entries`
    so both `runner.py` and `driver.py` can use it without a backwards
    import) — prints each newly-produced turn as it happens: the agent's
    reasoning, which tool(s) it decided to call and with what arguments,
    and each tool's response."""
    for entry in entries:
        if entry.role == "system":
            print(f"[{gid}] [turn {entry.turn}] (system prompt sent)")
        elif entry.role == "human":
            print(f"[{gid}] [turn {entry.turn}] >> task given to agent")
        elif entry.role == "ai":
            if entry.content.strip():
                print(f"[{gid}] [turn {entry.turn}] agent: {entry.content.strip()}")
            for call in entry.tool_calls:
                args_str = ", ".join(f"{k}={v!r}" for k, v in call.args.items())
                print(f"[{gid}] [turn {entry.turn}] agent calls {call.name}({args_str})")
        elif entry.role == "tool":
            snippet = entry.content.strip()
            if len(snippet) > 500:
                snippet = snippet[:500] + " …(truncated)"
            print(f"[{gid}] [turn {entry.turn}] tool response: {snippet or '(empty)'}")
        print()


def make_transcript_on_step(gid: str):
    """Bind `print_transcript_entries` to one candidate's `gid`, returning a
    callable matching `agent.verifier.OnStep`'s shape — the wiring
    `driver.py`/`fvvw/graph.py`/`fvvw/static_track.py` pass as `on_step`
    when live console output is enabled."""

    def _on_step(entries: list[TranscriptEntry]) -> None:
        print_transcript_entries(gid, entries)

    return _on_step


__all__ = [
    "DEFAULT_TRUNCATE_CHARS",
    "LiveConsole",
    "make_transcript_on_step",
    "print_transcript_entries",
]
