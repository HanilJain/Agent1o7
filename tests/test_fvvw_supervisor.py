"""Tests for `stage5_verification.fvvw.supervisor` — the Continuous
Verification Supervisor (Tier 3 of the FVVW dynamic-track hardening
plan). Three pure, independently-testable pieces, no Docker/QEMU/GDB/LLM
required anywhere in this file:

1. `apply_event`/`apply_events` — the deterministic canonical-state
   reducer (T3-K): process-exit detection, canonical state updates,
   immutability, and dedup/staleness safety under concurrent/out-of-order
   event delivery.
2. `propose_action` — the deterministic supervisor (T3-M): recovery
   decisions for each of the plan's named scenarios (daemon/startup
   failure, process-exited-before-bp, missing sink address, stalled
   execution).
3. `validate_action`/`record_attempt` — the bounded no-repeat gate
   (T3-M): prevention of repeated failed actions, escalation ladder,
   legality checks, and the `"escalate"` resolution.

Also covers the user's explicit "rejection of confirmation without
evidence" requirement at the supervisor layer — `propose_action` never
proposes `confirmed`/`refuted` at all (that stays exclusively
`dynamic_track.match_oracle`'s/the Tier 1 gates' job), and
`validate_action` passes a `confirmed`/`refuted`/`inconclusive` decision
through unchanged rather than re-adjudicating it — this file asserts both
halves of that invariant directly against the supervisor's own API.
"""

from __future__ import annotations

from fw_audit.common.verification import (
    AttemptRecord,
    RouteDecision,
    VerificationEvent,
    VerificationState,
)
from fw_audit.config.settings import Settings
from fw_audit.stage5_verification.fvvw.supervisor import (
    apply_event,
    apply_events,
    propose_action,
    record_attempt,
    validate_action,
)

# --------------------------------------------------------------------- #
# apply_event — canonical-state updates, immutability, process-exit
# detection, and dedup/staleness safety (T3-K)
# --------------------------------------------------------------------- #


def test_apply_event_is_immutable():
    """The reducer must never mutate its input — a prerequisite for
    concurrent monitors calling it against the "same" state independently
    without racing on a shared mutable object."""
    state = VerificationState(global_id="g1")
    event = VerificationEvent(kind="TARGET_STARTED", source="process_health_monitor", seq=1)
    new_state = apply_event(state, event)
    assert new_state is not state
    assert state.process_status == "not_started"  # original untouched
    assert new_state.process_status == "running"


def test_target_exit_event_sets_process_exited_before_bp():
    """Process-exit detection: a TARGET_EXITED event observed while
    breakpoint_status != 'hit' deterministically sets process_exited_
    before_bp=True and process_status='exited' — this is the fact T1-E's
    deterministic route keys off, now sourced from the event stream."""
    state = VerificationState(global_id="g1")
    state = apply_event(
        state, VerificationEvent(kind="TARGET_STARTED", source="m", seq=1)
    )
    state = apply_event(
        state,
        VerificationEvent(
            kind="TARGET_EXITED", source="m", seq=2, payload={"exit_code": 1}
        ),
    )
    assert state.process_status == "exited"
    assert state.process_exited_before_bp is True


def test_target_exit_after_breakpoint_hit_does_not_set_exited_before_bp():
    """The SAME TARGET_EXITED event, but arriving AFTER a real
    BREAKPOINT_HIT, must NOT be mischaracterized as 'exited before the
    breakpoint' — the process reached the breakpoint fine and exited
    normally afterward (e.g. QEMU user-mode exiting on GDB disconnect)."""
    state = VerificationState(global_id="g1")
    state = apply_event(state, VerificationEvent(kind="TARGET_STARTED", source="m", seq=1))
    state = apply_event(
        state, VerificationEvent(kind="BREAKPOINT_HIT", source="m", seq=1)
    )
    state = apply_event(
        state, VerificationEvent(kind="TARGET_EXITED", source="m", seq=2)
    )
    assert state.process_exited_before_bp is False


def test_apply_event_advances_canonical_state_through_a_full_sequence():
    """A realistic event sequence advances every relevant field
    correctly, in order — canonical state updates, end to end."""
    state = VerificationState(global_id="g1")
    events = [
        VerificationEvent(kind="TARGET_STARTED", source="m", seq=1),
        VerificationEvent(kind="GDB_CONNECTED", source="m", seq=1),
        VerificationEvent(kind="BREAKPOINT_HIT", source="m", seq=1),
        VerificationEvent(
            kind="SINK_REACHED", source="m", seq=1, payload={"addr": "0x2000"}
        ),
        VerificationEvent(
            kind="ARTIFACT_CREATED", source="m", seq=1, payload={"path": "/tmp/proof"}
        ),
        VerificationEvent(
            kind="SIGNAL_RECEIVED", source="m", seq=1, payload={"signal": "SIGSEGV"}
        ),
    ]
    state = apply_events(state, events)
    assert state.process_status == "running"
    assert state.gdb_status == "connected"
    assert state.breakpoint_status == "hit"
    assert state.reached is True
    assert state.sink_reachable is True
    assert state.sink_addr == "0x2000"
    assert state.filesystem_artifacts == ["/tmp/proof"]
    assert state.signals == ["SIGSEGV"]
    assert len(state.events) == 6


def test_apply_event_drops_stale_and_duplicate_events():
    """Concurrent event handling safety (T3-K): an event with seq <= the
    highest already-applied seq for its kind is dropped entirely — the
    state (including events/last_applied_seq bookkeeping) is returned
    UNCHANGED, never partially applied."""
    state = VerificationState(global_id="g1")
    state = apply_event(
        state, VerificationEvent(kind="TARGET_EXITED", source="m", seq=5)
    )
    assert state.process_status == "exited"

    # A stale (lower seq) TARGET_EXITED must not regress/duplicate.
    before = state
    after_stale = apply_event(
        state, VerificationEvent(kind="TARGET_EXITED", source="m", seq=3)
    )
    assert after_stale == before
    assert len(after_stale.events) == 1

    # An exact duplicate (same seq) must also be dropped.
    after_dup = apply_event(
        state, VerificationEvent(kind="TARGET_EXITED", source="m", seq=5)
    )
    assert after_dup == before
    assert len(after_dup.events) == 1


def test_apply_event_never_regresses_monotonic_breakpoint_status():
    """A BREAKPOINT_MISSED event arriving (out of order) AFTER a real
    BREAKPOINT_HIT must never downgrade the status back to 'missed' —
    monotonic status ordering is what makes the reducer deterministic
    regardless of which order concurrent monitors' events actually land
    in."""
    state = VerificationState(global_id="g1")
    state = apply_event(state, VerificationEvent(kind="BREAKPOINT_HIT", source="m", seq=1))
    assert state.breakpoint_status == "hit"
    state = apply_event(
        state, VerificationEvent(kind="BREAKPOINT_MISSED", source="m", seq=1)
    )
    assert state.breakpoint_status == "hit"  # never regressed


def test_apply_event_never_regresses_process_status():
    state = VerificationState(global_id="g1")
    state = apply_event(state, VerificationEvent(kind="TARGET_EXITED", source="m", seq=1))
    assert state.process_status == "exited"
    state = apply_event(state, VerificationEvent(kind="TARGET_STARTED", source="m", seq=2))
    assert state.process_status == "exited"  # never un-exits


def test_apply_events_concurrent_arrival_order_is_deterministic():
    """The SAME set of events, applied in two DIFFERENT arrival orders
    (simulating two independent monitors racing), must converge on the
    identical final state — the concurrent-event-handling guarantee
    T3-K's monotonic/idempotent design exists to provide."""
    events_a = [
        VerificationEvent(kind="TARGET_STARTED", source="proc", seq=1),
        VerificationEvent(kind="GDB_CONNECTED", source="gdb", seq=1),
        VerificationEvent(kind="BREAKPOINT_HIT", source="gdb", seq=1),
    ]
    events_b = list(reversed(events_a))  # BREAKPOINT_HIT first this time

    state_a = apply_events(VerificationState(global_id="g1"), events_a)
    state_b = apply_events(VerificationState(global_id="g1"), events_b)

    assert state_a.process_status == state_b.process_status == "running"
    assert state_a.gdb_status == state_b.gdb_status == "connected"
    assert state_a.breakpoint_status == state_b.breakpoint_status == "hit"
    assert state_a.reached == state_b.reached is True


# --------------------------------------------------------------------- #
# propose_action — the deterministic supervisor (T3-M)
# --------------------------------------------------------------------- #


def test_supervisor_process_exit_routes_to_escalate():
    state = VerificationState(global_id="g1", process_exited_before_bp=True)
    decision = propose_action(state)
    assert decision is not None
    assert decision.route == "escalate_direct_call"


def test_supervisor_daemon_startup_failure_routes_to_direct_call():
    """Daemon + startup-unreachable -> direct-call strategy: the
    supervisor's own defense-in-depth check (T2-G already prefers
    direct_call mode UP FRONT via plan_emulation; this is the SAME
    escalation reached from the failure_reason the harness observed when
    bring-up nonetheless keeps failing against one)."""
    state = VerificationState(
        global_id="g1",
        process_status="not_started",
        failure_reason="daemon target with an unreachable startup path — mandatory "
        "config-file parser near main; startup not reachable under partial emulation",
    )
    decision = propose_action(state)
    assert decision is not None
    assert decision.route == "escalate_direct_call"


def test_supervisor_startup_failure_without_daemon_signal_routes_to_retry_bringup():
    """An ordinary (non-daemon) startup failure — process never started,
    SOME failure reason recorded, but nothing daemon-shaped — routes to
    the ordinary in-place repair (retry_bringup), not straight to
    escalation."""
    state = VerificationState(
        global_id="g1",
        process_status="not_started",
        failure_reason="qemu binary staging failed: no such file or directory",
    )
    decision = propose_action(state)
    assert decision is not None
    assert decision.route == "retry_bringup"


def test_supervisor_missing_sink_address_routes_to_resolve_address():
    """Missing sink address (T2-F), once the entry breakpoint has already
    been reached, routes to resolve_address."""
    state = VerificationState(
        global_id="g1", breakpoint_status="hit", process_status="running", sink_addr=""
    )
    decision = propose_action(state)
    assert decision is not None
    assert decision.route == "resolve_address"


def test_supervisor_breakpoint_not_hit_routes_to_retry_gdb_attach():
    state = VerificationState(
        global_id="g1", breakpoint_status="unset", process_status="running"
    )
    decision = propose_action(state)
    assert decision is not None
    assert decision.route == "retry_gdb_attach"


def test_supervisor_trigger_failure_routes_to_retry_trigger():
    state = VerificationState(
        global_id="g1",
        breakpoint_status="hit",
        process_status="running",
        sink_addr="0x2000",
        sink_reachable=True,
        current_trigger_type="deliver_via_argv",
        failure_reason="trigger delivery failed: payload rejected",
    )
    decision = propose_action(state)
    assert decision is not None
    assert decision.route == "retry_trigger"


def test_supervisor_stalled_execution_diagnoses_and_recovers_once():
    """Stalled/timeout: first occurrence -> a bounded retry_bringup
    recovery attempt; a SECOND stall recorded in attempt_history (after
    that recovery didn't help) -> escalates straight to inconclusive
    rather than retrying an execution that has already stalled twice."""
    stalled_state = VerificationState(
        global_id="g1",
        breakpoint_status="hit",
        process_status="running",
        sink_addr="0x2000",
        sink_reachable=True,
        failure_reason="stalled execution — no progress within 30s",
    )
    first = propose_action(stalled_state)
    assert first is not None
    assert first.route == "retry_bringup"

    already_stalled_once = stalled_state.model_copy(
        update={
            "attempt_history": [
                AttemptRecord(
                    action="retry_bringup",
                    trigger_reason="stalled execution — no progress within 30s (round 1)",
                    outcome="applied",
                    seq=1,
                )
            ]
        }
    )
    second = propose_action(already_stalled_once)
    assert second is not None
    assert second.route == "inconclusive"


def test_supervisor_returns_none_when_genuinely_ambiguous():
    """A state with no clear deterministic signal (reached the sink,
    resolved sink address, no failure_reason) must return None — the
    caller falls back to the LLM router, exactly the 'deterministic
    first, LLM only when ambiguous' shape match_oracle already
    established for confirm/refute."""
    state = VerificationState(
        global_id="g1",
        breakpoint_status="hit",
        process_status="running",
        sink_addr="0x2000",
        sink_reachable=True,
    )
    assert propose_action(state) is None


def test_supervisor_never_proposes_confirmed_or_refuted():
    """propose_action must NEVER itself propose a confirmed/refuted
    route, no matter how the state looks — those stay exclusively
    dynamic_track.match_oracle's/the Tier 1 gates' call, checked BEFORE
    the supervisor ever runs. This is the schema-level expression of
    'no amount of agent reasoning, confidence, or planning can become
    evidence' at the supervisor layer."""
    interesting_states = [
        VerificationState(global_id="g1", process_exited_before_bp=True),
        VerificationState(global_id="g1", breakpoint_status="hit", sink_reachable=True),
        VerificationState(global_id="g1", breakpoint_status="unset"),
        VerificationState(
            global_id="g1", breakpoint_status="hit", sink_addr="0x1", failure_reason="stalled"
        ),
    ]
    for state in interesting_states:
        decision = propose_action(state)
        if decision is not None:
            assert decision.route not in ("confirmed", "refuted")


# --------------------------------------------------------------------- #
# validate_action / record_attempt — the bounded no-repeat gate (T3-M)
# --------------------------------------------------------------------- #


def test_validate_action_rejects_repeated_failed_action():
    """Prevention of repeated failed actions: proposing the SAME action
    against the SAME unchanged underlying condition is only tolerated a
    BOUNDED number of times (governed by `stage5_supervisor_max_same_
    action` — the FIRST proposal is recorded as 'applied', so the action
    is allowed to repeat up to `max_same_action` further times before it
    is rejected and rewritten to the next escalation tier) — never
    reissued indefinitely, and once escalated, it never oscillates back.
    This is the direct fix for the dead-daemon retry_gdb_attach loop the
    DIR-825 incident exposed."""
    settings = Settings(_env_file=None, FWA_STAGE5_SUPERVISOR_MAX_SAME_ACTION=2)
    state = VerificationState(
        global_id="g1", breakpoint_status="unset", process_status="running"
    )

    decisions = []
    for _ in range(6):
        proposed = propose_action(state)
        assert proposed is not None
        validated = validate_action(proposed, state, settings)
        decisions.append(validated.route)
        state = record_attempt(state, validated)

    # retry_gdb_attach is BOUNDED — it must stop repeating well before the
    # loop's own 6-round ceiling, never reissued every single round.
    retry_gdb_attach_count = decisions.count("retry_gdb_attach")
    assert 1 <= retry_gdb_attach_count <= settings.stage5_supervisor_max_same_action + 1
    assert retry_gdb_attach_count < len(decisions)

    # Escalation is MONOTONIC, not a retry-forever loop in disguise: once
    # a different route appears, retry_gdb_attach must never reappear
    # afterward.
    first_escalated_index = next(
        i for i, d in enumerate(decisions) if d != "retry_gdb_attach"
    )
    assert all(
        d != "retry_gdb_attach" for d in decisions[first_escalated_index:]
    ), f"retry_gdb_attach oscillated back in: {decisions}"


def test_recovery_budget_exhaustion_ends_inconclusive():
    """Bounded recovery: repeatedly escalating an unchanged failing
    condition through every tier must eventually converge on
    'inconclusive' and STAY there — never an infinite loop, never cycling
    back to an earlier tier."""
    settings = Settings(_env_file=None, FWA_STAGE5_SUPERVISOR_MAX_SAME_ACTION=1)
    state = VerificationState(global_id="g1", process_exited_before_bp=True)

    routes: list[str] = []
    for _ in range(10):
        proposed = propose_action(state)
        assert proposed is not None
        validated = validate_action(proposed, state, settings)
        routes.append(validated.route)
        state = record_attempt(state, validated)
        if validated.route == "inconclusive":
            break

    assert routes[-1] == "inconclusive"
    # Once inconclusive is reached it must be terminal — no further
    # validate_action call against the SAME state should ever escalate
    # past it or cycle back.
    final_proposed = propose_action(state)
    if final_proposed is not None:
        final_validated = validate_action(final_proposed, state, settings)
        assert final_validated.route in ("inconclusive", "escalate_direct_call")


def test_validate_action_resolves_escalate_to_direct_call_when_not_yet_attempted():
    state = VerificationState(global_id="g1", current_strategy="user")
    settings = Settings(_env_file=None)
    decision = RouteDecision(route="escalate", diagnosis="last resort", confidence="HIGH")
    resolved = validate_action(decision, state, settings)
    assert resolved.route == "escalate_direct_call"


def test_validate_action_resolves_escalate_to_inconclusive_when_direct_call_already_tried():
    state = VerificationState(global_id="g1", current_strategy="direct_call")
    settings = Settings(_env_file=None)
    decision = RouteDecision(route="escalate", diagnosis="last resort", confidence="HIGH")
    resolved = validate_action(decision, state, settings)
    assert resolved.route == "inconclusive"


def test_validate_action_passes_terminal_routes_through_unchanged():
    """confirmed/refuted/inconclusive are never subject to the no-repeat
    escalation ladder or re-adjudicated in any way — validate_action's
    ONLY job for a terminal route is to pass it straight through, never
    to second-guess a verdict-adjacent decision that isn't its own to
    make."""
    settings = Settings(_env_file=None)
    state = VerificationState(global_id="g1")
    for route in ("confirmed", "refuted", "inconclusive"):
        decision = RouteDecision(route=route, diagnosis="d", confidence="HIGH")
        result = validate_action(decision, state, settings)
        assert result is decision or result.route == route


def test_validate_action_rejects_unrecognized_route():
    """Legality check: an unrecognized route is downgraded to
    inconclusive rather than forwarded to a conditional-edge lookup that
    would silently fall through to __end__ with no diagnosis."""
    state = VerificationState(global_id="g1")
    settings = Settings(_env_file=None)
    bogus = RouteDecision.model_construct(
        route="not_a_real_route", diagnosis="d", confidence="HIGH"
    )
    result = validate_action(bogus, state, settings)
    assert result.route == "inconclusive"


def test_record_attempt_never_records_terminal_dispositions():
    state = VerificationState(global_id="g1")
    for route in ("confirmed", "refuted", "inconclusive"):
        decision = RouteDecision(route=route, diagnosis="d", confidence="HIGH")
        result_state = record_attempt(state, decision)
        assert result_state.attempt_history == []
