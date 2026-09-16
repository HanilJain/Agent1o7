"""`LoggingChatModel` — a transparent, composition-based wrapper that gives
full before/after visibility into every LLM call Stage 5 makes, without
editing a single node/prompt/parsing file.

Mirrors `cmdlog.LoggingSessionExecutor`'s exact shape: wrap the thing by
composition, forward every attribute access via `__getattr__` (so
`agent.verifier._model_label`'s `getattr(llm, "model", None)` and friends
keep working unchanged), and override only the one method call sites
actually use (`ainvoke`). This is what lets the pre-FVVW static loop
(`agent/graph.py`) — which this codebase's own hard constraints forbid
editing for feature work — gain full LLM-call logging with ZERO edits to
that file, the same way `cmdlog.JsonlRecordingList` already does for its
`attempts`/`cpg_build_holder` lists.

What gets captured, every call, via ONE `CommandLog.record(kind="llm_call")`:

    payload  = the exact rendered prompt (every message, role + content) —
               the BEFORE-parser input.
    stdout   = the raw `response.content` text — the AFTER-the-LLM,
               BEFORE-any-downstream-parsing output. Whatever the caller's
               own `clean_script`/`clean_json_payload`/`parse_evaluator_
               response` does to this text afterward is invisible to this
               wrapper by design — that "after parser" half is captured
               separately, at each call site that already has (or gains) a
               `command_log`, right after its own parse step succeeds/fails
               (see `fvvw/strategy.py`, `fvvw/dynamic_agents.py`, and the
               existing `JsonlRecordingList`-wrapped `attempts`/
               `cpg_build_holder` for the static loop).

Never truncates (same discipline as every other `cmdlog` record) — console
truncation, when a `LiveConsole` is attached to the `CommandLog`, happens
downstream in `LiveConsole.echo`, never here.
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage

from fw_audit.stage5_verification.cmdlog import CommandLog, current_phase


def _render_messages(messages: Any) -> str:
    """Best-effort plain-text rendering of whatever `ainvoke`'s first
    positional argument turns out to be — every Stage 5 call site passes a
    `list[BaseMessage]`, but this degrades gracefully (`str(messages)`)
    rather than raising if a future call site passes something else."""
    if isinstance(messages, list) and all(isinstance(m, BaseMessage) for m in messages):
        lines = []
        for msg in messages:
            role = getattr(msg, "type", msg.__class__.__name__)
            lines.append(f"[{role}]\n{msg.content}")
        return "\n\n".join(lines)
    return str(messages)


class LoggingChatModel:
    """Wraps a `BaseChatModel` for exactly one Stage 5 role (e.g.
    `"strategy_agent"`, `"generator"`, `"bringup_agent"`) and one
    `CommandLog` (the static or dynamic track's — whichever this role
    belongs to). `command_log` already carries its own `gid`/`live` console
    (see `cmdlog.CommandLog`), so this class needs no console-specific
    parameter of its own.

    `command_log.record(..., node=current_phase() or role)` — inside a
    dynamic-graph node body (wrapped in `cmdlog.phase()`/`aphase()`), the
    record is tagged with the active node name, exactly like every other
    dynamic-track command; outside one (e.g. `strategy_agent`, which runs
    before the dynamic graph even starts), it falls back to the role name
    itself.
    """

    def __init__(self, inner: BaseChatModel, *, role: str, command_log: CommandLog) -> None:
        self._inner = inner
        self._role = role
        self._log = command_log

    async def ainvoke(self, messages: Any, config: Any = None, **kwargs: Any) -> Any:
        prompt_text = _render_messages(messages)
        response = await self._inner.ainvoke(messages, config=config, **kwargs)
        raw_output = getattr(response, "content", None)
        raw_text = raw_output if isinstance(raw_output, str) else str(raw_output)
        self._log.record(
            node=current_phase() or self._role,
            kind="llm_call",
            command=f"llm:{self._role}",
            payload=prompt_text,
            stdout=raw_text,
            ok=True,
            notes={"role": self._role},
        )
        return response

    def __getattr__(self, name: str) -> Any:
        # Anything beyond `ainvoke` (`.model`/`.model_name` for
        # `agent.verifier._model_label`, `.invoke`/`.bind_tools`/etc. if a
        # future call site ever needs them) falls through to the wrapped
        # model unlogged — every Stage 5 LLM call site today uses only
        # `ainvoke`, per this stage's "plain text in/text out" design.
        return getattr(self._inner, name)


__all__ = ["LoggingChatModel"]
