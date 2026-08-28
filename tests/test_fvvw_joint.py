"""Tests for `stage5_verification.fvvw.joint` — Stage 5 FVVW v3 Phase 5.
The full agreement/mechanism/reachability taxonomy, tested as a truth
table per the design doc's classification rules."""

from __future__ import annotations

from fw_audit.common.verification import (
    Agreement,
    MechanismConfidence,
    ReachabilityConfidence,
    TrackResult,
    VerificationVerdict,
)
from fw_audit.stage5_verification.fvvw.joint import (
    classify_agreement,
    classify_mechanism_confidence,
    classify_reachability_confidence,
    collect_residual_unknowns,
    joint_evaluate,
)


def _result(verdict: VerificationVerdict, **kwargs) -> TrackResult:
    return TrackResult(verdict=verdict, **kwargs)


# ---------------------------------------------------------------------- #
# classify_agreement
# ---------------------------------------------------------------------- #


def test_agreement_both_confirmed_is_concordant_confirm():
    a = classify_agreement(
        _result(VerificationVerdict.CONFIRMED), _result(VerificationVerdict.CONFIRMED)
    )
    assert a == Agreement.CONCORDANT_CONFIRM


def test_agreement_both_refuted_is_concordant_refute():
    a = classify_agreement(
        _result(VerificationVerdict.REFUTED), _result(VerificationVerdict.REFUTED)
    )
    assert a == Agreement.CONCORDANT_REFUTE


def test_agreement_confirmed_vs_refuted_is_discordant():
    a = classify_agreement(
        _result(VerificationVerdict.CONFIRMED), _result(VerificationVerdict.REFUTED)
    )
    assert a == Agreement.DISCORDANT
    # order-independent
    b = classify_agreement(
        _result(VerificationVerdict.REFUTED), _result(VerificationVerdict.CONFIRMED)
    )
    assert b == Agreement.DISCORDANT


def test_agreement_confirmed_vs_inconclusive_is_one_sided():
    a = classify_agreement(
        _result(VerificationVerdict.CONFIRMED), _result(VerificationVerdict.INCONCLUSIVE)
    )
    assert a == Agreement.ONE_SIDED


def test_agreement_refuted_vs_error_is_one_sided():
    a = classify_agreement(
        _result(VerificationVerdict.REFUTED), _result(VerificationVerdict.ERROR)
    )
    assert a == Agreement.ONE_SIDED


def test_agreement_both_inconclusive_is_one_sided():
    a = classify_agreement(
        _result(VerificationVerdict.INCONCLUSIVE), _result(VerificationVerdict.INCONCLUSIVE)
    )
    assert a == Agreement.ONE_SIDED


# ---------------------------------------------------------------------- #
# classify_mechanism_confidence
# ---------------------------------------------------------------------- #


def test_mechanism_concordant_confirm_is_confirmed_strong():
    m = classify_mechanism_confidence(
        _result(VerificationVerdict.CONFIRMED),
        _result(VerificationVerdict.CONFIRMED),
        Agreement.CONCORDANT_CONFIRM,
    )
    assert m == MechanismConfidence.CONFIRMED_STRONG


def test_mechanism_discordant_is_always_discordant_hold():
    """Never auto-resolved by trusting one track by default — this is the
    single most important invariant in this whole module."""
    m = classify_mechanism_confidence(
        _result(VerificationVerdict.CONFIRMED),
        _result(VerificationVerdict.REFUTED),
        Agreement.DISCORDANT,
    )
    assert m == MechanismConfidence.DISCORDANT_HOLD
    m2 = classify_mechanism_confidence(
        _result(VerificationVerdict.REFUTED),
        _result(VerificationVerdict.CONFIRMED),
        Agreement.DISCORDANT,
    )
    assert m2 == MechanismConfidence.DISCORDANT_HOLD


def test_mechanism_one_sided_confirmed_survivor_is_confirmed_single_track():
    m = classify_mechanism_confidence(
        _result(VerificationVerdict.CONFIRMED),
        _result(VerificationVerdict.INCONCLUSIVE),
        Agreement.ONE_SIDED,
    )
    assert m == MechanismConfidence.CONFIRMED_SINGLE_TRACK


def test_mechanism_one_sided_refuted_survivor_is_inconclusive_not_confirmed():
    m = classify_mechanism_confidence(
        _result(VerificationVerdict.REFUTED),
        _result(VerificationVerdict.ERROR),
        Agreement.ONE_SIDED,
    )
    assert m == MechanismConfidence.INCONCLUSIVE


def test_mechanism_concordant_refute_is_inconclusive_not_confirmed():
    """concordant_refute is NOT confirmed_strong — mechanism confidence
    specifically measures whether the vulnerability mechanism is
    confirmed, not whether the tracks merely agree."""
    m = classify_mechanism_confidence(
        _result(VerificationVerdict.REFUTED),
        _result(VerificationVerdict.REFUTED),
        Agreement.CONCORDANT_REFUTE,
    )
    assert m == MechanismConfidence.INCONCLUSIVE


def test_mechanism_both_inconclusive_is_inconclusive():
    m = classify_mechanism_confidence(
        _result(VerificationVerdict.INCONCLUSIVE),
        _result(VerificationVerdict.INCONCLUSIVE),
        Agreement.ONE_SIDED,
    )
    assert m == MechanismConfidence.INCONCLUSIVE


# ---------------------------------------------------------------------- #
# classify_reachability_confidence
# ---------------------------------------------------------------------- #


def test_reachability_forced_guard_caps_at_forced_unknown_even_if_confirmed():
    r = classify_reachability_confidence(
        crosscheck_calls_confirmed=True,
        any_guard_forced=True,
        dynamic_reached_sink=True,
        agreement=Agreement.CONCORDANT_CONFIRM,
    )
    assert r == ReachabilityConfidence.FORCED_UNKNOWN


def test_reachability_confirmed_when_dynamic_reached_without_forcing():
    r = classify_reachability_confidence(
        crosscheck_calls_confirmed=True,
        any_guard_forced=False,
        dynamic_reached_sink=True,
        agreement=Agreement.CONCORDANT_CONFIRM,
    )
    assert r == ReachabilityConfidence.CONFIRMED


def test_reachability_refuted_when_concordant_refute_and_never_reached():
    r = classify_reachability_confidence(
        crosscheck_calls_confirmed=False,
        any_guard_forced=False,
        dynamic_reached_sink=False,
        agreement=Agreement.CONCORDANT_REFUTE,
    )
    assert r == ReachabilityConfidence.REFUTED


def test_reachability_conditional_when_only_static_crosscheck_confirmed():
    r = classify_reachability_confidence(
        crosscheck_calls_confirmed=True,
        any_guard_forced=False,
        dynamic_reached_sink=None,  # dynamic track not_run
        agreement=Agreement.ONE_SIDED,
    )
    assert r == ReachabilityConfidence.CONDITIONAL


def test_reachability_conditional_when_dynamic_unknown_and_no_crosscheck():
    r = classify_reachability_confidence(
        crosscheck_calls_confirmed=None,
        any_guard_forced=False,
        dynamic_reached_sink=None,
        agreement=Agreement.ONE_SIDED,
    )
    assert r == ReachabilityConfidence.CONDITIONAL


def test_forced_guard_never_raises_confidence_above_forced_unknown():
    """Even the strongest possible agreement (concordant_confirm) must not
    escape forced_unknown once a guard was forced — 'a forced guard caps
    reachability confidence and adds a residual unknown; it never raises
    confidence' per the design doc's safety invariants."""
    for agreement in Agreement:
        r = classify_reachability_confidence(
            crosscheck_calls_confirmed=True,
            any_guard_forced=True,
            dynamic_reached_sink=True,
            agreement=agreement,
        )
        assert r == ReachabilityConfidence.FORCED_UNKNOWN


# ---------------------------------------------------------------------- #
# collect_residual_unknowns
# ---------------------------------------------------------------------- #


def test_residual_unknowns_includes_forced_guard_caveat():
    unknowns = collect_residual_unknowns(
        static_result=_result(VerificationVerdict.CONFIRMED),
        dynamic_result=_result(VerificationVerdict.CONFIRMED),
        guard_logs=[
            {"name": "acscli2_acs_restart", "real_value": "0", "forced_value": "1"},
        ],
    )
    assert any("acscli2_acs_restart" in u and "FORCED" in u for u in unknowns)


def test_residual_unknowns_omits_guard_that_matched_naturally():
    """A guard whose real value already equals the forced value was never
    actually forced — no residual unknown for it."""
    unknowns = collect_residual_unknowns(
        static_result=_result(VerificationVerdict.CONFIRMED),
        dynamic_result=_result(VerificationVerdict.CONFIRMED),
        guard_logs=[{"name": "g", "real_value": "1", "forced_value": "1"}],
    )
    assert not any("FORCED" in u for u in unknowns)


def test_residual_unknowns_includes_incomplete_crosscheck():
    unknowns = collect_residual_unknowns(
        static_result=_result(VerificationVerdict.CONFIRMED),
        dynamic_result=_result(VerificationVerdict.CONFIRMED),
        crosscheck_evidence={"all_expected_calls_confirmed": False},
    )
    assert any("cross-check" in u for u in unknowns)


def test_residual_unknowns_includes_indecisive_track_verdicts():
    unknowns = collect_residual_unknowns(
        static_result=_result(VerificationVerdict.INCONCLUSIVE),
        dynamic_result=_result(VerificationVerdict.ERROR),
    )
    assert any("static track" in u for u in unknowns)
    assert any("dynamic track" in u for u in unknowns)


def test_residual_unknowns_carries_static_next_steps_verbatim():
    unknowns = collect_residual_unknowns(
        static_result=_result(
            VerificationVerdict.INCONCLUSIVE,
            evidence={"recommended_next_steps": ["try a more targeted CPGQL query by hand"]},
        ),
        dynamic_result=_result(VerificationVerdict.CONFIRMED),
    )
    assert any("try a more targeted CPGQL query by hand" in u for u in unknowns)


# ---------------------------------------------------------------------- #
# joint_evaluate — end-to-end
# ---------------------------------------------------------------------- #


def test_joint_evaluate_concordant_confirm_end_to_end():
    verdict = joint_evaluate(
        static_result=_result(VerificationVerdict.CONFIRMED),
        dynamic_result=_result(VerificationVerdict.CONFIRMED),
        crosscheck_evidence={"all_expected_calls_confirmed": True},
        guard_logs=[],
        dynamic_reached_sink=True,
    )
    assert verdict.agreement == Agreement.CONCORDANT_CONFIRM
    assert verdict.mechanism_confidence == MechanismConfidence.CONFIRMED_STRONG
    assert verdict.reachability_confidence == ReachabilityConfidence.CONFIRMED
    assert verdict.residual_unknowns == []


def test_joint_evaluate_discordant_holds_for_human_review():
    verdict = joint_evaluate(
        static_result=_result(VerificationVerdict.CONFIRMED),
        dynamic_result=_result(VerificationVerdict.REFUTED),
    )
    assert verdict.agreement == Agreement.DISCORDANT
    assert verdict.mechanism_confidence == MechanismConfidence.DISCORDANT_HOLD


def test_joint_evaluate_forced_guard_with_concordant_confirm_still_caps_reachability():
    verdict = joint_evaluate(
        static_result=_result(VerificationVerdict.CONFIRMED),
        dynamic_result=_result(VerificationVerdict.CONFIRMED),
        guard_logs=[{"name": "g", "real_value": "0", "forced_value": "1"}],
        dynamic_reached_sink=True,
    )
    assert verdict.mechanism_confidence == MechanismConfidence.CONFIRMED_STRONG
    assert verdict.reachability_confidence == ReachabilityConfidence.FORCED_UNKNOWN
    assert any("FORCED" in u for u in verdict.residual_unknowns)
