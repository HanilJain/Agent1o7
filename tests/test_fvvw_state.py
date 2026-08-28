"""Tests for `stage5_verification.fvvw.state` — Stage 5 FVVW v3 Phase 1.

The isolation rule ("no static-track node reads mem.dynamic.*, and no
dynamic-track node reads mem.static.*") is meant to be MECHANICAL, per the
module's own docstring — these tests pin the key-tuple invariants that
make it so, independent of `fvvw.graph`'s actual wiring (Phase 5), so a
future edit that accidentally widens one track's readable/writable set
fails here first.
"""

from __future__ import annotations

from fw_audit.stage5_verification.fvvw.state import (
    DYNAMIC_TRACK_READABLE_KEYS,
    DYNAMIC_TRACK_WRITABLE_KEYS,
    JOINT_EVALUATE_READABLE_KEYS,
    STATIC_TRACK_READABLE_KEYS,
    STATIC_TRACK_WRITABLE_KEYS,
    FVVWState,
)


def test_static_track_cannot_write_dynamic_keys():
    assert set(STATIC_TRACK_WRITABLE_KEYS).isdisjoint(DYNAMIC_TRACK_WRITABLE_KEYS)


def test_dynamic_track_cannot_write_static_keys():
    assert set(DYNAMIC_TRACK_WRITABLE_KEYS).isdisjoint(STATIC_TRACK_WRITABLE_KEYS)


def test_static_track_readable_keys_exclude_dynamic_result():
    assert "dynamic_result" not in STATIC_TRACK_READABLE_KEYS
    assert "signals" not in STATIC_TRACK_READABLE_KEYS
    assert "gdb_transcript" not in STATIC_TRACK_READABLE_KEYS


def test_dynamic_track_readable_keys_exclude_static_result():
    assert "static_result" not in DYNAMIC_TRACK_READABLE_KEYS


def test_only_joint_evaluate_reads_both_track_results():
    assert "static_result" in JOINT_EVALUATE_READABLE_KEYS
    assert "dynamic_result" in JOINT_EVALUATE_READABLE_KEYS
    # Neither track's own readable set may claim this joint privilege.
    assert not ({"static_result", "dynamic_result"} <= set(STATIC_TRACK_READABLE_KEYS))
    assert not ({"static_result", "dynamic_result"} <= set(DYNAMIC_TRACK_READABLE_KEYS))


def test_every_writable_key_is_a_real_fvvwstate_field():
    """Guards against a typo'd key tuple that silently never round-trips
    through the actual TypedDict (LangGraph state updates are dict-shaped,
    so a misspelled key would fail at update time, not at import time)."""
    valid_keys = set(FVVWState.__annotations__)
    for key in (
        *STATIC_TRACK_WRITABLE_KEYS,
        *DYNAMIC_TRACK_WRITABLE_KEYS,
        *STATIC_TRACK_READABLE_KEYS,
        *DYNAMIC_TRACK_READABLE_KEYS,
        *JOINT_EVALUATE_READABLE_KEYS,
    ):
        assert key in valid_keys, f"{key!r} is not a real FVVWState field"


def test_fvvw_state_accepts_a_populated_dict_shape():
    """TypedDict has no runtime validation, so this is a shape/typo smoke
    test rather than a schema-enforcement test — same spirit as
    `stage5_verification.agent.graph.VerifierState`'s own lack of a
    dedicated construction test."""
    state: FVVWState = {
        "claim": {"global_id": "vulnbin#0000::candidate_001", "bin_id": "vulnbin"},
        "signals": [{"kind": "sink_argument_capture", "value": "; touch /tmp/proof;"}],
        "active_hypothesis": "A",
    }
    assert state["claim"]["bin_id"] == "vulnbin"
    assert state["active_hypothesis"] == "A"
