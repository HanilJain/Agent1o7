"""Tests for `fw_audit.stage5_verification.streaming.stream_graph_live` —
the dual-mode `astream` driver used by `fvvw.graph.run_dynamic_track_only`
for the dynamic track's compiled `StateGraph`."""

from __future__ import annotations

import asyncio
import operator
from typing import Annotated, TypedDict

import pytest
from langgraph.graph import END, StateGraph

from fw_audit.stage5_verification.cmdlog import CommandLog
from fw_audit.stage5_verification.streaming import stream_graph_live

pytestmark = pytest.mark.filterwarnings("ignore")


class _State(TypedDict, total=False):
    x: int
    log: Annotated[list, operator.add]


async def _node_a(state: _State) -> dict:
    return {"x": state.get("x", 0) + 1, "log": ["a"]}


async def _node_b(state: _State) -> dict:
    return {"x": state.get("x", 0) + 10, "log": ["b"]}


def _build_graph():
    graph = StateGraph(_State)
    graph.add_node("a", _node_a)
    graph.add_node("b", _node_b)
    graph.set_entry_point("a")
    graph.add_edge("a", "b")
    graph.add_edge("b", END)
    return graph.compile()


def _run(coro):
    return asyncio.run(coro)


def test_stop_after_none_matches_plain_ainvoke():
    compiled = _build_graph()
    streamed = _run(stream_graph_live(compiled, {}, stop_after=None))
    invoked = _run(compiled.ainvoke({}))
    assert streamed == invoked
    assert streamed["x"] == 11
    assert streamed["log"] == ["a", "b"]


def test_stop_after_first_node_halts_before_second():
    compiled = _build_graph()
    result = _run(stream_graph_live(compiled, {}, stop_after="a"))
    assert result["x"] == 1
    assert result["log"] == ["a"]


def test_stop_after_node_that_never_fires_runs_to_completion():
    """A `stop_after` naming a node this run's path never actually reaches
    (e.g. a conditional edge skipped it) should behave exactly like
    `stop_after=None` — never hang or error."""
    compiled = _build_graph()
    result = _run(stream_graph_live(compiled, {}, stop_after="nonexistent_node"))
    assert result["x"] == 11
    assert result["log"] == ["a", "b"]


def test_records_one_node_update_per_node(tmp_path):
    compiled = _build_graph()
    log = CommandLog(tmp_path / "gid.dynamic.jsonl", track="dynamic")
    _run(stream_graph_live(compiled, {}, command_log=log))
    records = log.read_all()
    assert [r["node"] for r in records] == ["a", "b"]
    assert all(r["kind"] == "node_update" for r in records)


def test_no_command_log_means_no_records():
    compiled = _build_graph()
    # Should not raise even with command_log=None (the default).
    result = _run(stream_graph_live(compiled, {}))
    assert result["x"] == 11
