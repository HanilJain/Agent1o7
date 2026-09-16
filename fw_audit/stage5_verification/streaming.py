"""`stream_graph_live` — drives a compiled LangGraph `StateGraph` via
dual-mode `astream(stream_mode=["updates", "values"])` instead of a single
`ainvoke`, so every node's produced update is visible (live-echoed +
`cmdlog`-recorded) as it happens, and optionally lets a caller stop right
after one named node for per-node diagnosis (`debug dynamic --stop-after`).

Used by `fvvw.graph.run_dynamic_track_only` for the dynamic track's 9-node
graph (`fvvw.dynamic_graph.build_dynamic_graph`). NOT used for the static
v1 loop (`agent.graph.build_verifier_graph`) — that one already has its own
richer, transcript-based live view (`agent.verifier`'s `on_step`/
`_stream_with_callback`, and `fvvw.static_track.run_static_track`'s mirror
of it), which renders actual agent reasoning/tool calls rather than a raw
per-node state diff. This module is for graphs (like the dynamic one) that
have no such transcript concept.

Confirmed against the installed LangGraph version (see this repo's own
verification step before writing this file): `astream(...,
stream_mode=["updates", "values"])` yields `(mode, payload)` tuples —
`("updates", {node_name: update_dict})` right before the corresponding
`("values", full_reduced_state)` for the same super-step. Consuming the
`"values"` side means LangGraph itself applies every field's reducer (e.g.
`iteration_history`'s `Annotated[list, operator.add]`) — this module never
re-implements reducer semantics by hand. With `stop_after=None` (the
default), the LAST `"values"` chunk is bit-for-bit what a plain
`await compiled.ainvoke(initial_state, config=config)` would have
returned — a behavior-preserving swap for every existing caller.
"""

from __future__ import annotations

from typing import Any

from fw_audit.stage5_verification.cmdlog import CommandLog


async def stream_graph_live(
    compiled: Any,
    initial_state: dict,
    *,
    config: dict | None = None,
    command_log: CommandLog | None = None,
    stop_after: str | None = None,
) -> dict:
    """Run `compiled` to completion (or, when `stop_after` is given, until
    that node has fired once), returning the final accumulated state.

    Every node's update is recorded via `command_log.record(kind=
    "node_update")` when a `command_log` is given (its own `live` console,
    if attached, then echoes it to the terminal — see `cmdlog.CommandLog`/
    `live_console.LiveConsole`) — this is purely additive bookkeeping on
    top of whatever fine-grained LLM/tool records that node's own body
    already produces (`dynamic_agents.py`'s agentic loops, `tools.
    qemu_gdb_tool` commands); it gives a coarse "what did this node decide"
    summary even for nodes with no LLM/tool call of their own (e.g.
    `health_gate`).

    `stop_after`, when given, must name one of the graph's own node ids
    (e.g. `"bringup"`, `"health_gate"`) — once that node's update has been
    seen AND its corresponding reduced state has arrived, streaming stops
    and that state is returned immediately, without running any node that
    would normally follow. If the named node never actually fires during
    this run (e.g. a conditional edge skips it), the graph simply runs to
    completion as if `stop_after` had not been passed — this is reported
    back to the caller as an ordinary finished result, not an error, since
    "that node didn't run this round" is itself a diagnosable fact.
    """
    final_state: dict = dict(initial_state)
    pending_stop = False
    async for mode, chunk in compiled.astream(
        initial_state, config=config, stream_mode=["updates", "values"]
    ):
        if mode == "updates":
            for node_name, update in chunk.items():
                if command_log is not None:
                    command_log.record(
                        node=node_name,
                        kind="node_update",
                        command=f"node:{node_name}",
                        payload=repr(update),
                        ok=True,
                    )
                if stop_after is not None and node_name == stop_after:
                    pending_stop = True
        elif mode == "values":
            final_state = chunk
            if pending_stop:
                break
    return final_state


__all__ = ["stream_graph_live"]
