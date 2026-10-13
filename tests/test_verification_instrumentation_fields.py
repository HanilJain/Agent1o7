"""Backward-compatibility tests for the P1-1/P1-2 additive schema fields
(`common.verification.ObservationRecord.instrumentation_ok`/
`instrumentation_error`, `VerificationState.instrumentation_failures`) —
the DIR-825 dynamic-track hardening plan. Both fields default to values
that reproduce the PRE-existing behavior exactly, so every caller/test
that predates them is unaffected; these tests pin that contract down
directly against the schema, independent of any one call site."""

from __future__ import annotations

from fw_audit.common.verification import ObservationRecord, VerificationState


def test_observation_record_defaults_construct_and_assume_instrumentation_ok():
    """An `ObservationRecord()` built with no arguments at all (every
    pre-existing call site) must default `instrumentation_ok=True` — the
    old, pre-P1-1 assumption every existing caller relied on implicitly."""
    observation = ObservationRecord()
    assert observation.instrumentation_ok is True
    assert observation.instrumentation_error is None


def test_observation_record_round_trips_instrumentation_fields_through_json():
    observation = ObservationRecord(
        instrumentation_ok=False,
        instrumentation_error="gdb: no symbol table is loaded",
    )
    parsed = ObservationRecord.model_validate_json(observation.model_dump_json())
    assert parsed == observation


def test_verification_state_defaults_construct_with_zero_instrumentation_failures():
    state = VerificationState(global_id="g1")
    assert state.instrumentation_failures == 0


def test_verification_state_round_trips_instrumentation_failures_through_json():
    state = VerificationState(global_id="g1", instrumentation_failures=3)
    parsed = VerificationState.model_validate_json(state.model_dump_json())
    assert parsed.instrumentation_failures == 3


def test_verification_state_model_copy_increments_instrumentation_failures_immutably():
    """`_update_state_for_round` (dynamic_graph.py) relies on `model_copy`
    to produce a NEW state each round, never mutating the prior one in
    place — pin that contract down at the schema level."""
    state = VerificationState(global_id="g1", instrumentation_failures=1)
    new_state = state.model_copy(update={"instrumentation_failures": 2})
    assert state.instrumentation_failures == 1
    assert new_state.instrumentation_failures == 2
    assert new_state is not state
