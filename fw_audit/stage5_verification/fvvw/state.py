"""`FVVWState` — the LangGraph state schema (the "short-term memory"/STM
store, per the FVVW v3 design doc's §2) the top-level fork-join graph
(`fvvw.graph`) runs on.

Namespaced so the fork-join isolation rule is MECHANICAL, not just
conventional (see the doc's §2 table): no static-track node reads
`dynamic_*` keys, and no dynamic-track node reads `static_*` keys — only
`joint_evaluate` reads both. Each track's compiled subgraph is given a
narrowed state view exposing only its own keys (see `fvvw.graph`), so a
violation would be a KeyError/type error, not a silent cross-read.

Reuses the SAME `operator.add` reducer pattern `stage5_verification.agent.
graph.VerifierState.transcript` already established (see that module for
the precedent) — `signals` here is the dynamic track's equivalent
accumulator, since `collect_signals`/`instrument_trigger` both append to it
across a bring-up/retry loop rather than each overwriting the last node's
value.
"""

from __future__ import annotations

import operator
from typing import Annotated, Literal, TypedDict

from fw_audit.common.findings import Finding
from fw_audit.common.verification import (
    Agreement,
    MechanismConfidence,
    ReachabilityConfidence,
    StrategyPlan,
    TargetMeta,
    TrackResult,
)


class ClaimDict(TypedDict, total=False):
    """`mem.claim.*` — written by `ingest_report` (realized by the existing
    `candidate_index.discover_candidates`), read by every node. Mirrors the
    design doc's `Claim` TypedDict, expressed against this repo's actual
    `Finding`/`VerificationCandidate` shape rather than an abstract one."""

    global_id: str
    chunk_id: str
    bin_id: str
    finding: Finding


class FVVWState(TypedDict, total=False):
    """The fork-join graph's full state. Grouped by STM namespace (see this
    module's docstring); every key here is also documented in the FVVW v3
    implementation plan's Phase 1 section.
    """

    # ---- mem.claim.* — ingest_report (candidate_index.discover_candidates) ---
    claim: ClaimDict

    # ---- mem.target.* — characterize_target -------------------------------
    target: TargetMeta

    # ---- mem.plan.* — strategy_agent ---------------------------------------
    plan: StrategyPlan

    # ---- mem.static.* — the static track (build_verifier_graph, reused) ---
    static_result: TrackResult

    # ---- mem.dynamic.* — the dynamic track ---------------------------------
    dynamic_result: TrackResult
    emulation_plan: dict
    gdb_transcript: str
    signals: Annotated[list[dict], operator.add]
    active_hypothesis: Literal["A", "B"]

    # ---- mem.repair.* — bringup_stabilize -----------------------------------
    repair_return_to: str
    """Node name to resume once `bringup_stabilize` fixes an issue — the
    dotted repair back-edges in the FVVW §5 topology diagram."""
    repair_applied_fixes: Annotated[list[str], operator.add]
    repair_quirks_discovered: Annotated[list[str], operator.add]

    # ---- mem.joint.* — joint_evaluate (reads BOTH static_result and
    # dynamic_result; the only node permitted to) ---------------------------
    agreement: Agreement
    mechanism_confidence: MechanismConfidence
    reachability_confidence: ReachabilityConfidence
    residual_unknowns: Annotated[list[str], operator.add]

    # ---- write_report --------------------------------------------------------
    report_markdown: str


# ---------------------------------------------------------------------- #
# Narrowed views for track isolation (FVVW §10 wiring notes: "compile each
# track as a subgraph with a narrowed state view exposing only its own
# namespace"). These key tuples are what `fvvw.graph` uses to build each
# subgraph's own `TypedDict`-equivalent input/output schema — kept here,
# next to `FVVWState` itself, so the two can never silently drift apart.
# ---------------------------------------------------------------------- #

STATIC_TRACK_READABLE_KEYS: tuple[str, ...] = ("claim", "target", "plan")
"""Keys the static-track subgraph may READ. Notably excludes every
`dynamic_*`/`emulation_plan`/`gdb_transcript`/`signals`/`active_hypothesis`/
`repair_*` key — the static-track isolation rule."""

STATIC_TRACK_WRITABLE_KEYS: tuple[str, ...] = ("static_result",)
"""Keys the static-track subgraph may WRITE."""

DYNAMIC_TRACK_READABLE_KEYS: tuple[str, ...] = ("claim", "target", "plan")
"""Keys the dynamic-track subgraph may READ. Notably excludes
`static_result` — the dynamic-track isolation rule."""

DYNAMIC_TRACK_WRITABLE_KEYS: tuple[str, ...] = (
    "dynamic_result",
    "emulation_plan",
    "gdb_transcript",
    "signals",
    "active_hypothesis",
    "repair_return_to",
    "repair_applied_fixes",
    "repair_quirks_discovered",
)
"""Keys the dynamic-track subgraph may WRITE."""

JOINT_EVALUATE_READABLE_KEYS: tuple[str, ...] = (
    "claim",
    "target",
    "plan",
    "static_result",
    "dynamic_result",
)
"""`joint_evaluate` is the ONLY node in the whole graph permitted to read
both `static_result` and `dynamic_result` — see `fvvw.joint`."""


__all__ = [
    "DYNAMIC_TRACK_READABLE_KEYS",
    "DYNAMIC_TRACK_WRITABLE_KEYS",
    "JOINT_EVALUATE_READABLE_KEYS",
    "STATIC_TRACK_READABLE_KEYS",
    "STATIC_TRACK_WRITABLE_KEYS",
    "ClaimDict",
    "FVVWState",
]
