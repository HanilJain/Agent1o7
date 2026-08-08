"""LangGraph wiring for Stage 1.

Owns the four-rule `tplink_decrypt` trigger policy as conditional edges,
so it can't be silently violated by a later edit to any single node:

    1. tplink_decrypt never runs unless the user passed --tplink.
    2. Even when flagged, it only runs if binwalk attempt 1 did not succeed.
    3. When triggered, it runs BEFORE binwalk is re-run (decrypt, then extract).
    4. If binwalk attempt 1 succeeds, tplink_decrypt is skipped entirely,
       regardless of the flag — satisfied structurally: the "success" branch
       below routes straight to generate_tree and never visits the decrypt
       node at all.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from langgraph.graph import END, StateGraph

from fw_audit.stage1_ingestion.extraction.binwalk import binwalk_succeeded
from fw_audit.stage1_ingestion.extraction.script import BINWALK_1_DIR, BINWALK_2_DIR
from fw_audit.stage1_ingestion.nodes import (
    fail_unsupported,
    finalize,
    generate_tree,
    identify_binaries,
    initialize,
    tplink_decrypt_and_binwalk_2,
    unzip_and_binwalk_1,
)
from fw_audit.stage1_ingestion.state import FirmwareIngestionState, IngestionStatus


def _after_binwalk_1(state: FirmwareIngestionState) -> str:
    """Rule 2 + rule 4: decrypt only on failure, only when flagged."""
    if state.get("status") == IngestionStatus.FAILED:
        return "fail_unsupported"

    result = state.get("binwalk_1_result")
    out_dir = Path(state["db_subfolder"]) / BINWALK_1_DIR
    if result is not None and binwalk_succeeded(result, out_dir):
        return "generate_tree"  # rule 4: success -> skip decrypt entirely
    if state.get("is_tplink"):
        return "tplink_decrypt"  # rule 1 + rule 2: flagged and attempt 1 failed
    return "fail_unsupported"  # rule 1: no flag -> no decrypt, hard fail


def _after_binwalk_2(state: FirmwareIngestionState) -> str:
    """After the (decrypt -> re-run binwalk) path: did attempt 2 succeed?"""
    result = state.get("binwalk_2_result")
    out_dir = Path(state["db_subfolder"]) / BINWALK_2_DIR
    if result is not None and binwalk_succeeded(result, out_dir):
        return "generate_tree"
    return "fail_unsupported"


def _after_generate_tree(state: FirmwareIngestionState) -> str:
    if state.get("status") == IngestionStatus.FAILED:
        return "finalize"
    return "identify_binaries"


def _after_identify(state: FirmwareIngestionState) -> str:
    return "finalize"


def build_graph():
    """Construct (uncompiled) the Stage 1 StateGraph."""
    graph = StateGraph(FirmwareIngestionState)

    graph.add_node("initialize", initialize)
    graph.add_node("unzip_and_binwalk_1", unzip_and_binwalk_1)
    graph.add_node("tplink_decrypt", tplink_decrypt_and_binwalk_2)
    graph.add_node("generate_tree", generate_tree)
    graph.add_node("identify_binaries", identify_binaries)
    graph.add_node("fail_unsupported", fail_unsupported)
    graph.add_node("finalize", finalize)

    graph.set_entry_point("initialize")
    graph.add_edge("initialize", "unzip_and_binwalk_1")
    graph.add_conditional_edges(
        "unzip_and_binwalk_1",
        _after_binwalk_1,
        {
            "generate_tree": "generate_tree",
            "tplink_decrypt": "tplink_decrypt",
            "fail_unsupported": "fail_unsupported",
        },
    )
    graph.add_conditional_edges(
        "tplink_decrypt",
        _after_binwalk_2,
        {"generate_tree": "generate_tree", "fail_unsupported": "fail_unsupported"},
    )
    graph.add_conditional_edges(
        "generate_tree",
        _after_generate_tree,
        {"identify_binaries": "identify_binaries", "finalize": "finalize"},
    )
    graph.add_conditional_edges(
        "identify_binaries", _after_identify, {"finalize": "finalize"}
    )
    graph.add_edge("fail_unsupported", "finalize")
    graph.add_edge("finalize", END)

    return graph


@lru_cache(maxsize=1)
def get_graph():
    """Return the compiled, cached Stage 1 graph singleton."""
    return build_graph().compile()
