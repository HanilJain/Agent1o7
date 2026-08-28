"""`joint_evaluate` (FVVW v3 §6 node 17) — the ONE node in the whole
fork-join permitted to read both `mem.static.result` and
`mem.dynamic.result` (see `fvvw.state`'s isolation-key tuples). Purely
deterministic — a rule engine, no LLM call — the taxonomy is fully
specified by the design doc; only narrative composition needs an LLM, and
that lives in `fvvw.report.write_report`.
"""

from __future__ import annotations

from fw_audit.common.verification import (
    Agreement,
    MechanismConfidence,
    ReachabilityConfidence,
    TrackResult,
    VerificationVerdict,
)


def classify_agreement(static_result: TrackResult, dynamic_result: TrackResult) -> Agreement:
    """FVVW's four-way agreement taxonomy — deterministic given both
    tracks' terminal `VerificationVerdict`s.

    - `concordant_confirm`: both tracks independently CONFIRMED.
    - `concordant_refute`: both tracks independently REFUTED.
    - `discordant`: one CONFIRMED, the other REFUTED — a genuine
      disagreement between two independent witnesses.
    - `one_sided`: one track reached a definite verdict (CONFIRMED or
      REFUTED) while the other is INCONCLUSIVE or ERROR (i.e. never really
      ran to a decisive answer) — NOT the same as `discordant`, since there
      is no actual contradiction, just one missing witness.
    """
    s, d = static_result.verdict, dynamic_result.verdict
    definite = {VerificationVerdict.CONFIRMED, VerificationVerdict.REFUTED}

    if s == VerificationVerdict.CONFIRMED and d == VerificationVerdict.CONFIRMED:
        return Agreement.CONCORDANT_CONFIRM
    if s == VerificationVerdict.REFUTED and d == VerificationVerdict.REFUTED:
        return Agreement.CONCORDANT_REFUTE
    if {s, d} == definite:
        return Agreement.DISCORDANT
    return Agreement.ONE_SIDED


def classify_mechanism_confidence(
    static_result: TrackResult, dynamic_result: TrackResult, agreement: Agreement
) -> MechanismConfidence:
    """The mechanism axis: does unsanitized attacker data reach the sink
    unmodified, IF the path is taken? Deliberately never a bare boolean —
    see `classify_reachability_confidence` for the paired, independent
    axis (FVVW's two-axis-truth principle: these are never collapsed).

    - `concordant_confirm` agreement -> `confirmed_strong` (multi-signal
      corroboration: two INDEPENDENT tracks both confirmed).
    - `one_sided` agreement, with the surviving track CONFIRMED ->
      `confirmed_single_track` (only one witness ran to a confirmed
      verdict; not upgraded to `confirmed_strong` since only one witness
      actually spoke).
    - `discordant` agreement -> `discordant_hold`, ALWAYS — never
      auto-resolved by trusting one track by default, per the design doc's
      hard requirement. This is the one case a human reviewer must look at.
    - Everything else (both inconclusive/error, or one_sided with the
      surviving track REFUTED — treated as leaning refuted rather than
      confirmed) -> `inconclusive`.
    """
    if agreement == Agreement.CONCORDANT_CONFIRM:
        return MechanismConfidence.CONFIRMED_STRONG
    if agreement == Agreement.DISCORDANT:
        return MechanismConfidence.DISCORDANT_HOLD
    if agreement == Agreement.ONE_SIDED:
        surviving = _surviving_definite_verdict(static_result, dynamic_result)
        if surviving == VerificationVerdict.CONFIRMED:
            return MechanismConfidence.CONFIRMED_SINGLE_TRACK
    return MechanismConfidence.INCONCLUSIVE


def _surviving_definite_verdict(
    static_result: TrackResult, dynamic_result: TrackResult
) -> VerificationVerdict | None:
    """For a `one_sided` agreement, which track actually reached a definite
    (CONFIRMED/REFUTED) verdict? `None` if neither did (shouldn't happen
    for a genuine `one_sided` classification, but never assumed)."""
    definite = {VerificationVerdict.CONFIRMED, VerificationVerdict.REFUTED}
    if static_result.verdict in definite:
        return static_result.verdict
    if dynamic_result.verdict in definite:
        return dynamic_result.verdict
    return None


def classify_reachability_confidence(
    *,
    crosscheck_calls_confirmed: bool | None,
    any_guard_forced: bool,
    dynamic_reached_sink: bool | None,
    agreement: Agreement,
) -> ReachabilityConfidence:
    """The reachability axis: can the path be reached in production —
    independent of whether the mechanism itself is sound. Derived from the
    static cross-check's controllability findings and the dynamic guard
    log (were any guards FORCED to reach the sink, rather than naturally
    satisfied by attacker-controlled input?).

    - A forced guard caps confidence at `forced_unknown` and NEVER raises
      it, even if the mechanism was confirmed_strong — a forced guard means
      reachability was ASSUMED for the test, not demonstrated in the wild.
    - `confirmed`: the dynamic track reached the sink WITHOUT forcing any
      guard, or the static cross-check independently confirmed every
      expected intermediate call is present with no guard concerns raised.
    - `conditional`: reached, but only under conditions the evidence
      doesn't fully generalize (e.g. static cross-check confirmed calls
      present but the dynamic track never actually reached the sink to
      corroborate, or vice versa).
    - `refuted`: neither track ever demonstrated the sink being reached at
      all, and the agreement itself leans refuted (concordant_refute).
    """
    if any_guard_forced:
        return ReachabilityConfidence.FORCED_UNKNOWN
    if agreement == Agreement.CONCORDANT_REFUTE and dynamic_reached_sink is False:
        return ReachabilityConfidence.REFUTED
    if dynamic_reached_sink is True and crosscheck_calls_confirmed is not False:
        return ReachabilityConfidence.CONFIRMED
    if crosscheck_calls_confirmed is True or dynamic_reached_sink is True:
        return ReachabilityConfidence.CONDITIONAL
    if dynamic_reached_sink is None:
        return ReachabilityConfidence.CONDITIONAL
    return ReachabilityConfidence.REFUTED


def collect_residual_unknowns(
    *,
    static_result: TrackResult,
    dynamic_result: TrackResult,
    guard_logs: list[dict] | None = None,
    crosscheck_evidence: dict | None = None,
) -> list[str]:
    """Carry forward every honest caveat from both tracks verbatim — FVVW's
    honest-residual-unknown-accounting principle. Never silently drops a
    limitation just because the overall verdict looks strong."""
    unknowns: list[str] = []

    static_evidence = static_result.evidence or {}
    for step in static_evidence.get("recommended_next_steps", []):
        unknowns.append(f"static track: {step}")

    for guard in guard_logs or []:
        if guard.get("real_value") is not None and guard.get("real_value") != guard.get(
            "forced_value"
        ):
            unknowns.append(
                f"guard {guard.get('name')!r} was FORCED to {guard.get('forced_value')!r} "
                f"to reach the sink (real default was {guard.get('real_value')!r}) — "
                "reachability under this guard's natural default is NOT established."
            )

    if crosscheck_evidence and not crosscheck_evidence.get("all_expected_calls_confirmed", True):
        unknowns.append(
            "static cross-check: not every expected intermediate call was independently "
            "confirmed present in the disassembly."
        )

    if dynamic_result.verdict in (VerificationVerdict.INCONCLUSIVE, VerificationVerdict.ERROR):
        unknowns.append(
            "dynamic track did not reach a decisive verdict "
            f"({dynamic_result.verdict.value}) — see its own evidence for the attempt history."
        )
    if static_result.verdict in (VerificationVerdict.INCONCLUSIVE, VerificationVerdict.ERROR):
        unknowns.append(
            "static track did not reach a decisive verdict "
            f"({static_result.verdict.value}) — see its own evidence for the attempt history."
        )

    return unknowns


class JointVerdict:
    """Plain result bundle (not persisted directly — `fvvw.graph` folds
    this into `mem.joint.*` state keys, and `common.verification.
    FVVWReport` is what actually gets persisted)."""

    def __init__(
        self,
        *,
        agreement: Agreement,
        mechanism_confidence: MechanismConfidence,
        reachability_confidence: ReachabilityConfidence,
        residual_unknowns: list[str],
    ) -> None:
        self.agreement = agreement
        self.mechanism_confidence = mechanism_confidence
        self.reachability_confidence = reachability_confidence
        self.residual_unknowns = residual_unknowns


def joint_evaluate(
    *,
    static_result: TrackResult,
    dynamic_result: TrackResult,
    crosscheck_evidence: dict | None = None,
    guard_logs: list[dict] | None = None,
    dynamic_reached_sink: bool | None = None,
) -> JointVerdict:
    """The `joint_evaluate` node's full classification — the ONLY function
    in this whole fork-join permitted to see both `static_result` and
    `dynamic_result` at once.
    """
    agreement = classify_agreement(static_result, dynamic_result)
    mechanism_confidence = classify_mechanism_confidence(
        static_result, dynamic_result, agreement
    )

    any_guard_forced = any(
        g.get("real_value") is not None and g.get("real_value") != g.get("forced_value")
        for g in (guard_logs or [])
    )
    crosscheck_calls_confirmed = (
        crosscheck_evidence.get("all_expected_calls_confirmed")
        if crosscheck_evidence is not None
        else None
    )
    reachability_confidence = classify_reachability_confidence(
        crosscheck_calls_confirmed=crosscheck_calls_confirmed,
        any_guard_forced=any_guard_forced,
        dynamic_reached_sink=dynamic_reached_sink,
        agreement=agreement,
    )

    residual_unknowns = collect_residual_unknowns(
        static_result=static_result,
        dynamic_result=dynamic_result,
        guard_logs=guard_logs,
        crosscheck_evidence=crosscheck_evidence,
    )

    return JointVerdict(
        agreement=agreement,
        mechanism_confidence=mechanism_confidence,
        reachability_confidence=reachability_confidence,
        residual_unknowns=residual_unknowns,
    )


__all__ = [
    "JointVerdict",
    "classify_agreement",
    "classify_mechanism_confidence",
    "classify_reachability_confidence",
    "collect_residual_unknowns",
    "joint_evaluate",
]
