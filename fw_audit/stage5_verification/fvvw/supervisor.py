"""Continuous Verification Supervisor — Tier 3 of the FVVW dynamic-track
hardening plan (see `stage5_verification/CLAUDE.md` and the implementation
plan this module was built from). The architecture:

    workers/monitors -> structured events -> VerificationState -> Supervisor
        -> validated next action -> existing harness -> new observations (loop)

Three pure, independently-testable pieces, each with ONE job:

- `apply_event` (T3-K): the deterministic REDUCER. Folds one
  `common.verification.VerificationEvent` into a `VerificationState`,
  producing a NEW state (never mutates the input in place). Idempotent
  and monotonic against duplicate or stale (out-of-order) events, so
  several concurrent monitors (T3-L, `fvvw.monitors`) emitting into the
  same run can never desynchronize the canonical picture — this is what
  makes concurrent event handling deterministic regardless of arrival
  order.
- `propose_action` (T3-M): the deterministic SUPERVISOR. Reads a
  `VerificationState` (never raw graph state, never an LLM's own
  reasoning) and proposes ONE `RouteDecision`, or `None` when nothing in
  the state cleanly resolves to a confident deterministic route — the
  caller then falls back to the existing LLM router
  (`dynamic_agents.route_observation`), the SAME "deterministic first,
  LLM only when genuinely ambiguous" shape `dynamic_track.match_oracle`
  already established for the confirm/refute axis. This function NEVER
  proposes `"confirmed"`/`"refuted"` — those stay exclusively `match_
  oracle`'s call, checked by `dynamic_graph._run_evaluate_route` BEFORE
  this function ever runs, so this module can never become a second,
  competing source of verdict-adjacent routing.
- `validate_action` (T3-M): the deterministic GATE every proposed action
  — deterministic OR LLM-router-produced — passes through before it is
  ever acted on. Rejects (and rewrites to the next escalation tier) an
  action that has already demonstrably failed/made-no-progress the SAME
  way `Settings.stage5_supervisor_max_same_action` times in a row — the
  direct fix for the dead-daemon `retry_gdb_attach` loop the DIR-825
  incident exposed — and enforces a bounded recovery ladder that always
  converges on `inconclusive`, never an unbounded retry.

Hard invariant this module exists to enforce (the plan's "Important
constraint" section):

    Supervisor = decides WHAT TO TRY NEXT
    Harness    = determines WHAT ACTUALLY HAPPENED
    Deterministic verifier = determines WHAT THE EVIDENCE PROVES

`propose_action`/`validate_action` never construct or imply a
`VerificationVerdict` — only `dynamic_graph._build_track_result` does
that, from a terminal `RouteDecision.route`, exactly as before Tier 3. No
amount of agent reasoning, confidence, or planning performed anywhere in
this module can become evidence; `CONFIRMED` continues to require the
Tier 1 positive-evidence gates (`dynamic_track.match_oracle` +
`dynamic_graph._build_track_result`'s empty-observation refusal), both
completely UNCHANGED by Tier 3.
"""

from __future__ import annotations

from fw_audit.common.verification import (
    AttemptRecord,
    RouteDecision,
    VerificationEvent,
    VerificationState,
)
from fw_audit.config.settings import Settings

# --------------------------------------------------------------------- #
# apply_event / apply_events — the canonical-state reducer (T3-K)
# --------------------------------------------------------------------- #

# Monotonic status orderings — an event that would move a status field
# BACKWARD relative to its current position is never applied. This is
# what keeps the reducer deterministic under concurrent/out-of-order
# monitor delivery with no lock: a stale TARGET_STARTED arriving after a
# TARGET_EXITED already landed can never un-exit the process, and a
# BREAKPOINT_MISSED arriving after a BREAKPOINT_HIT can never downgrade a
# real hit back to "missed".
_PROCESS_STATUS_ORDER = {"not_started": 0, "running": 1, "exited": 2}
_BREAKPOINT_STATUS_ORDER = {"unset": 0, "set": 1, "missed": 2, "hit": 3}


def apply_event(state: VerificationState, event: VerificationEvent) -> VerificationState:
    """Fold ONE `VerificationEvent` into `state`, returning a NEW
    `VerificationState` — `state` itself is never mutated (see this
    module's docstring on why immutability is what makes concurrent
    monitor delivery deterministic: two monitors can call this against
    the "same" state concurrently and each produces its own independent
    new state from the SAME input, rather than racing on a shared
    mutable object).

    Idempotent/monotonic (T3-K): an event whose `seq` is `<=` the highest
    `seq` already applied for that event's `kind` is a stale or duplicate
    delivery and is dropped — `state` is returned COMPLETELY UNCHANGED
    (not even `events`/`last_applied_seq` grow), so a caller may safely
    feed this the same event twice, or events out of arrival order, from
    several concurrent monitor consumers, with no external synchronization
    needed. A fresh (non-stale) event additionally never regresses a
    monotonic status field — see `_PROCESS_STATUS_ORDER`/
    `_BREAKPOINT_STATUS_ORDER` above.
    """
    last_seq = state.last_applied_seq.get(event.kind, -1)
    if event.seq <= last_seq:
        return state

    updates: dict = {
        "events": [*state.events, event],
        "last_applied_seq": {**state.last_applied_seq, event.kind: event.seq},
    }

    if event.kind == "TARGET_STARTED":
        if _PROCESS_STATUS_ORDER["running"] > _PROCESS_STATUS_ORDER[state.process_status]:
            updates["process_status"] = "running"
    elif event.kind == "TARGET_EXITED":
        updates["process_status"] = "exited"
        # Derive process_exited_before_bp deterministically straight from
        # the event stream — the SAME fact T1-D/T1-E compute from a single
        # GDB-transcript parse, now ALSO derivable purely from events, so
        # a monitor observing the exit independently of the transcript
        # parser (e.g. a bare /proc poll — see fvvw.monitors) still
        # produces the correct fact without needing transcript text at
        # all.
        if state.breakpoint_status != "hit":
            updates["process_exited_before_bp"] = True
        updates["failure_reason"] = (
            f"target exited (source={event.source!r}, payload={event.payload!r})"
        )
    elif event.kind == "GDB_CONNECTED":
        updates["gdb_status"] = "connected"
    elif event.kind == "BREAKPOINT_HIT":
        updates["breakpoint_status"] = "hit"
        updates["reached"] = True
        captured = event.payload.get("captured_argument")
        if captured is not None:
            updates["captured_argument"] = captured
    elif event.kind == "BREAKPOINT_MISSED":
        if _BREAKPOINT_STATUS_ORDER["missed"] > _BREAKPOINT_STATUS_ORDER[state.breakpoint_status]:
            updates["breakpoint_status"] = "missed"
        if state.reached is None:
            updates["reached"] = False
    elif event.kind == "TRIGGER_DELIVERED":
        trigger_type = event.payload.get("trigger_type")
        if trigger_type:
            updates["current_trigger_type"] = trigger_type
    elif event.kind == "TRIGGER_FAILED":
        updates["failure_reason"] = event.payload.get("reason", "trigger delivery failed")
    elif event.kind == "SINK_REACHED":
        updates["sink_reachable"] = True
        addr = event.payload.get("addr")
        if addr:
            updates["sink_addr"] = addr
    elif event.kind == "ARTIFACT_CREATED":
        path = event.payload.get("path")
        if path and path not in state.filesystem_artifacts:
            updates["filesystem_artifacts"] = [*state.filesystem_artifacts, path]
    elif event.kind == "SIGNAL_RECEIVED":
        name = event.payload.get("signal", "")
        if name and name not in state.signals:
            updates["signals"] = [*state.signals, name]
    elif event.kind == "TIMEOUT":
        updates["failure_reason"] = event.payload.get("reason", "timed out")

    return state.model_copy(update=updates)


def apply_events(state: VerificationState, events: list[VerificationEvent]) -> VerificationState:
    """Fold several events, in order, via repeated `apply_event` calls —
    a thin convenience for a caller draining a batch of events accumulated
    since the last round (T3-L's monitors emit into a shared queue; the
    caller drains it once per node step and applies the whole batch)."""
    for event in events:
        state = apply_event(state, event)
    return state


# --------------------------------------------------------------------- #
# propose_action — the deterministic supervisor (T3-M)
# --------------------------------------------------------------------- #


def propose_action(state: VerificationState) -> RouteDecision | None:
    """Reads `state` and proposes ONE `RouteDecision`, or `None` when
    nothing here cleanly resolves to a confident deterministic route —
    the caller then falls back to the existing LLM router. Checked in
    priority order; the FIRST matching case wins.

    1. `instrumentation_failures >= 2` (P1-2): GDB has failed to
       INSTRUMENT the target (set a real breakpoint) for two or more
       consecutive rounds — a harness/recipe-level problem (bad break
       operand, stripped symbol, ...), never an ordinary "not yet hit"
       miss. This is the DIR-825 incident's exact root cause: without
       this case, `instrumentation_ok=False` rounds fell straight through
       to case #7 below and were repeatedly diagnosed as "breakpoint never
       hit — wrong sink location, missing symbol, or input never reached
       that code path" for 9 rounds running. On the FIRST such failure
       (`instrumentation_failures == 1`), fall through instead — a single
       bad round could still be `resolve_address`'s job (case #6, checked
       after) or a genuinely transient GDB hiccup the LLM router should
       see once before this case forces an escalation. Routes to
       `escalate_direct_call`.
    2. `process_exited_before_bp` (T1-E): the process died before the
       entry/sink breakpoint was ever reached — re-attaching to the SAME
       dead process cannot succeed no matter how many times it is
       retried (the dead-daemon `retry_gdb_attach` loop the DIR-825
       incident exposed). Routes to `escalate_direct_call`.
    3. A daemon/startup-unreachable signal in `failure_reason` (T2-G —
       `plan_emulation` already prefers `direct_call` mode UP FRONT for
       such a target; this is the supervisor's own defense-in-depth
       check for when bring-up nonetheless keeps failing against one,
       mirroring `joint.py::collect_residual_unknowns`'s existing
       "shouldn't happen, but flagged rather than silently trusted"
       posture): `escalate_direct_call`.
    4. `process_status == "not_started"` with a `failure_reason` already
       set (a startup failure the harness observed before the target
       ever ran at all): `retry_bringup`.
    5. `current_trigger_type` set and `failure_reason` names a trigger
       problem: `retry_trigger`.
    6. No `sink_addr` resolved yet, and the round hasn't reached it any
       other way: `resolve_address` (T2-F) — never honestly proceed to
       gdb_attach with no real sink location.
    7. `breakpoint_status` not yet `"hit"` and the process hasn't exited:
       `retry_gdb_attach` — the ordinary "not yet hit, try again" case
       (this SUBSUMES `_run_evaluate_route`'s pre-Tier-3 inline `elif not
       reached` branch, moved here per the plan).
    8. A stall/timeout signal in `failure_reason`: `retry_bringup` once;
       a SECOND stall recorded in `attempt_history` for the identical
       reason escalates straight to `inconclusive` rather than retrying
       an execution that has already demonstrably stalled twice.
    9. Nothing above applies: `None` — genuinely ambiguous, defer to the
       LLM router.
    """
    if state.instrumentation_failures >= 2:
        return RouteDecision(
            route="escalate_direct_call",
            diagnosis=(
                f"instrumentation has failed {state.instrumentation_failures} consecutive "
                f"rounds in a row ({state.failure_reason or 'no further detail captured'}) — "
                "this is a harness/recipe-level failure (GDB never successfully set a "
                "breakpoint), not an ordinary 'breakpoint not yet hit' miss; retrying the "
                "identical broken instrumentation cannot succeed, escalating to a direct-call "
                "invocation instead."
            ),
            confidence="HIGH",
        )

    if state.process_exited_before_bp:
        return RouteDecision(
            route="escalate_direct_call",
            diagnosis=(
                "process exited before the entry/sink breakpoint was ever hit "
                f"({state.failure_reason or 'no further detail captured'}) — natural "
                "dispatch cannot complete under the current reach strategy; re-attaching "
                "to the same dead process cannot succeed, escalating to a direct-call "
                "invocation (T2-H) instead of retrying gdb_attach."
            ),
            confidence="HIGH",
        )

    reason_lower = state.failure_reason.lower()
    if "daemon" in reason_lower and (
        "startup" in reason_lower
        or "unreachable" in reason_lower
        or "not reachable" in reason_lower
    ):
        return RouteDecision(
            route="escalate_direct_call",
            diagnosis=f"daemon target with an unreachable startup path: {state.failure_reason} "
            "— partial (single-service) emulation is unlikely to ever get past bring-up "
            "naturally; escalating to a direct-call invocation.",
            confidence="HIGH",
        )

    if state.process_status == "not_started" and state.failure_reason:
        return RouteDecision(
            route="retry_bringup",
            diagnosis=f"startup failure observed before the target ever ran: "
            f"{state.failure_reason}",
            confidence="HIGH",
        )

    if state.current_trigger_type and "trigger" in reason_lower:
        return RouteDecision(
            route="retry_trigger",
            diagnosis=f"trigger delivery failed: {state.failure_reason}",
            confidence="MEDIUM",
        )

    if state.breakpoint_status in ("unset", "missed") and state.process_status != "exited":
        return RouteDecision(
            route="retry_gdb_attach",
            diagnosis="breakpoint never hit this round — wrong sink location, missing "
            "symbol, or input never reached that code path.",
            confidence="MEDIUM",
        )

    # Only relevant ONCE we're past the entry breakpoint (natural
    # execution/dispatch is confirmed working) but still can't locate the
    # sink call itself — an unresolved sink address BEFORE that point is
    # `retry_gdb_attach`'s own concern (Node 5 breaks at the functional
    # ENTRY, per `plan.entry_addr`/`target.func_offset`, not at the sink;
    # the sink address only matters once bring-up/attach has succeeded and
    # the trigger step needs somewhere to break — see T2-F).
    if (
        not state.sink_addr.strip()
        and state.breakpoint_status == "hit"
        and state.sink_reachable is not True
    ):
        return RouteDecision(
            route="resolve_address",
            diagnosis="entry breakpoint was reached, but no sink address is resolved — "
            "cannot honestly proceed without a real sink location (T2-F).",
            confidence="MEDIUM",
        )

    if "timed out" in reason_lower or "stalled" in reason_lower:
        already_stalled = any(
            attempt.action == "retry_bringup" and "stall" in attempt.trigger_reason.lower()
            for attempt in state.attempt_history
        )
        if already_stalled:
            return RouteDecision(
                route="inconclusive",
                diagnosis=f"stalled execution recurred after a prior recovery attempt: "
                f"{state.failure_reason}",
                confidence="HIGH",
            )
        return RouteDecision(
            route="retry_bringup",
            diagnosis=f"stalled execution — attempting one bounded recovery: "
            f"{state.failure_reason}",
            confidence="MEDIUM",
        )

    return None


# --------------------------------------------------------------------- #
# validate_action — the deterministic action gate (T3-M)
# --------------------------------------------------------------------- #

_KNOWN_ROUTES: frozenset[str] = frozenset(
    {
        "confirmed",
        "refuted",
        "retry_bringup",
        "retry_gdb_attach",
        "retry_trigger",
        "escalate_direct_call",
        "inconclusive",
        "resolve_address",
        "restart_execution",
        "escalate",
    }
)
"""Defense-in-depth legality check, mirroring the "revalidate even though
the type system should already guarantee it" posture `common.verification.
GuardSpec`/`render_guard_breakpoint_commands` already establish for
`forced_value` — a `RouteDecision.route` is a pydantic `Literal`, so an
invalid value should never reach here from a properly-constructed object,
but `validate_action` refuses to silently act on one anyway if it ever
does (e.g. a future caller building a `RouteDecision` from an untyped
dict)."""

_ESCALATION_CHAIN: dict[str, str] = {
    "retry_gdb_attach": "retry_bringup",
    "retry_trigger": "escalate_direct_call",
    "retry_bringup": "escalate_direct_call",
    "resolve_address": "escalate_direct_call",
    "restart_execution": "escalate_direct_call",
    "escalate_direct_call": "inconclusive",
}
"""What a repeatedly-failing action escalates to, per the plan's bounded
recovery tiers — each value is strictly "further along" toward a terminal
disposition, so repeatedly following the chain always converges on
`inconclusive` (deliberately absent as a KEY here — reaching it is itself
the terminal case `validate_action` stops recursing at)."""


def _attempt_signature(decision: RouteDecision, state: VerificationState) -> str:
    """A compact discriminator for "the same action, proposed against the
    same underlying condition" — the direct generalization of
    `dynamic_track.BringupContext.no_progress_since_last_fault`'s
    signature-comparison pattern to every recovery route, not just
    bring-up faults (see `common.verification.AttemptRecord`'s own
    docstring). Deliberately built from STATE FACTS, never `decision.
    diagnosis` prose — an LLM router could phrase the identical
    underlying condition differently each round, which would defeat a
    prose-based dedup; comparing the raw facts instead makes the
    "unchanged condition" detection robust to how any one round happens
    to describe it.

    Deliberately EXCLUDES `state.failure_reason` (fixed in the DIR-825
    incident's fix — the docstring above already promised "never decision.
    diagnosis prose", but `failure_reason` is itself free text populated
    from an LLM router's own diagnosis/an `instrumentation_error` string in
    some rounds, so leaving it IN the signature let every round's slightly
    different phrasing count as a "new" condition and defeated this exact
    dedup — a round-tripped LLM-produced `failure_reason` string could vary
    on every call even against an IDENTICAL underlying failure). Includes
    `instrumentation_failures > 0` instead (a coarse boolean bucket, not
    the raw count — the raw count itself increments every round and would
    reintroduce the same "always looks new" problem) so a repeated
    instrumentation failure is still recognized as the unchanged condition
    it is."""
    return (
        f"{state.process_status}:{state.gdb_status}:{state.breakpoint_status}:"
        f"{state.process_exited_before_bp}:{state.reached}:{bool(state.sink_addr.strip())}:"
        f"{state.instrumentation_failures > 0}"
    )


def record_attempt(state: VerificationState, decision: RouteDecision) -> VerificationState:
    """Append an `AttemptRecord` for `decision` onto `state.attempt_
    history` — called once per round, AFTER `validate_action` has settled
    on the FINAL decision, so the recorded action always reflects what
    actually got acted on (never a proposal `validate_action` itself
    rejected/rewrote).

    `outcome` is derived from whether the identical `(action, signature)`
    pair already appears earlier in `state.attempt_history`: `"applied"`
    the first time an action addresses a given underlying condition
    (state facts, via `_attempt_signature`), `"no_progress"` every
    subsequent time the SAME action is proposed against the SAME
    unchanged condition — the condition genuinely has not moved if the
    supervisor is proposing the identical fix against the identical
    diagnosed state facts again. Terminal dispositions
    (`confirmed`/`refuted`/`inconclusive`) are never recorded — nothing
    downstream will ever read a terminal round's own attempt outcome,
    so recording one would only be dead bookkeeping.
    """
    if decision.route in ("confirmed", "refuted", "inconclusive"):
        return state
    signature = _attempt_signature(decision, state)
    seen_before = any(
        attempt.action == decision.route and attempt.trigger_reason == signature
        for attempt in state.attempt_history
    )
    record = AttemptRecord(
        action=decision.route,
        trigger_reason=signature,
        outcome="no_progress" if seen_before else "applied",
        seq=len(state.attempt_history) + 1,
    )
    return state.model_copy(update={"attempt_history": [*state.attempt_history, record]})


def validate_action(
    decision: RouteDecision,
    state: VerificationState,
    settings: Settings,
) -> RouteDecision:
    """The deterministic gate every proposed `RouteDecision` — whether it
    came from `propose_action` or the LLM router — passes through before
    it is ever acted on.

    1. **Legality**: `decision.route` must be a route this codebase
       actually understands (`_KNOWN_ROUTES`) — an unrecognized route is
       downgraded to `inconclusive` rather than being forwarded to a
       conditional-edge lookup that would silently fall through to
       `__end__` with no diagnosis.
    2. **`escalate` resolution**: the plan's own last-tier recovery
       action, `"escalate"`, is resolved HERE into a concrete route the
       graph already understands — `escalate_direct_call` if direct-call
       mode hasn't been attempted yet (`state.current_strategy !=
       "direct_call"`), else `inconclusive`. This keeps `dynamic_graph`'s
       `_ROUTE_TO_NODE`/`_TERMINAL_ROUTES` from needing a THIRD meaning
       for the same underlying disposition — `"escalate"` never reaches
       the graph's own routing tables, only this function's output does.
    3. **No-repeat**: if `decision.route` has already `failed`/
       `no_progress`ed `>= settings.stage5_supervisor_max_same_action`
       times against the SAME underlying condition
       (`_attempt_signature`) in `state.attempt_history`, it is REWRITTEN
       to the next tier in `_ESCALATION_CHAIN` instead of being reissued
       — the direct fix for the dead-daemon `retry_gdb_attach` loop: the
       Nth identical proposal against an unchanged condition is rejected
       and escalated, never repeated verbatim.
    4. **Bounded recovery**: if the escalated tier is ITSELF already
       exhausted against the same condition, the function recurses
       through the SAME check on the escalated decision — bounded by
       `_ESCALATION_CHAIN`'s own strictly-terminal-converging shape (see
       its docstring), so this always terminates at `inconclusive` at the
       latest, never an unbounded loop.

    Terminal dispositions (`confirmed`/`refuted`/`inconclusive`) pass
    through UNCHANGED — they are never subject to the no-repeat
    escalation ladder (there is nothing further to escalate a terminal
    route TO), and `confirmed` in particular is gated exclusively by the
    Tier 1 evidence check upstream of this function, never re-adjudicated
    here.
    """
    if decision.route not in _KNOWN_ROUTES:
        return RouteDecision(
            route="inconclusive",
            diagnosis=f"proposed route {decision.route!r} is not a recognized action — "
            "refusing to act on it.",
            confidence="LOW",
        )

    if decision.route == "escalate":
        target = (
            "inconclusive" if state.current_strategy == "direct_call" else "escalate_direct_call"
        )
        decision = RouteDecision(
            route=target,
            diagnosis=f"'escalate' resolved to {target!r}: {decision.diagnosis}",
            confidence=decision.confidence,
        )

    if decision.route in ("confirmed", "refuted", "inconclusive"):
        return decision

    signature = _attempt_signature(decision, state)
    repeated_failures = sum(
        1
        for attempt in state.attempt_history
        if attempt.action == decision.route
        and attempt.trigger_reason == signature
        and attempt.outcome in ("failed", "no_progress")
    )
    if repeated_failures < settings.stage5_supervisor_max_same_action:
        return decision

    next_tier = _ESCALATION_CHAIN.get(decision.route, "inconclusive")
    escalated = RouteDecision(
        route=next_tier,
        diagnosis=f"{decision.route!r} already failed/made-no-progress "
        f"{repeated_failures} time(s) against the same condition "
        f"(>= stage5_supervisor_max_same_action={settings.stage5_supervisor_max_same_action}) "
        f"— escalating to {next_tier!r} instead of repeating it. Original diagnosis: "
        f"{decision.diagnosis}",
        confidence="HIGH",
    )
    if next_tier in ("confirmed", "refuted", "inconclusive"):
        return escalated
    return validate_action(escalated, state, settings)


__all__ = [
    "apply_event",
    "apply_events",
    "propose_action",
    "record_attempt",
    "validate_action",
]
