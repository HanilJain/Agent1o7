"""Round-trip + basic-shape tests for the FVVW v3 schema additions in
`fw_audit.common.verification` — Stage 5 Phase 1. Mirrors
`tests/test_stage5_verification_schema.py`'s acceptance-test shape for the
existing Joern-track schema."""

from __future__ import annotations

from datetime import UTC, datetime

from fw_audit.common.verification import (
    Agreement,
    DynamicPlan,
    FVVWReport,
    GuardSpec,
    Hypotheses,
    MechanismConfidence,
    ReachabilityConfidence,
    StaticPlan,
    StrategyPlan,
    TargetMeta,
    TrackResult,
    VerificationVerdict,
)


def _target_meta() -> TargetMeta:
    return TargetMeta(
        arch="arm",
        endianness="little",
        is_64bit=False,
        pie=False,
        stripped=True,
        libc="uClibc",
        func_offset="0x00026938",
        dispatch_resolvable=True,
        binary_path="/rootfs/bin/vulnbin",
        rootfs_dir="/rootfs",
    )


def _static_plan() -> StaticPlan:
    return StaticPlan(
        target_function="FUN_00026938",
        source_fields=["argv[1]"],
        sink_names=["system"],
        expected_intermediate_calls=["strcpy", "snprintf"],
        sanitizer_patterns=["escapeshellarg"],
        crosscheck_required=True,
        decisive_observable="metacharacter present unmodified in the sink arg",
    )


def _dynamic_plan() -> DynamicPlan:
    return DynamicPlan(
        reach_strategy="inferior_call",
        entry_addr="0x00022594",
        target_addr="0x00026938",
        sink_addr="0x00020ba8",
        guards=[GuardSpec(name="acscli2_acs_restart", addr="0x000276dc", forced_value="1")],
        argv_template=["rc", "vuln_path", "; touch /tmp/proof;"],
        payload_marker=";touch /tmp/claim_001_proof;",
        required_signals=["sink_argument_capture", "target_self_report", "filesystem_artifact"],
        decisive_observable="metacharacter present unmodified in the sink arg",
    )


def test_target_meta_round_trips_through_json():
    target = _target_meta()
    parsed = TargetMeta.model_validate_json(target.model_dump_json())
    assert parsed == target


def test_target_meta_pie_defaults_to_none_when_undetermined():
    target = TargetMeta(arch="mips", endianness="big", func_offset="0x1000")
    assert target.pie is None
    assert target.stripped is None


def test_static_plan_round_trips_through_json():
    plan = _static_plan()
    parsed = StaticPlan.model_validate_json(plan.model_dump_json())
    assert parsed == plan


def test_dynamic_plan_round_trips_with_guards():
    plan = _dynamic_plan()
    parsed = DynamicPlan.model_validate_json(plan.model_dump_json())
    assert parsed == plan
    assert parsed.guards[0].name == "acscli2_acs_restart"


def test_strategy_plan_carries_both_track_plans_and_hypotheses():
    strategy = StrategyPlan(
        threat_model={"trust_boundary": "argv[1]", "access_requirement": "local_shell"},
        hypotheses=Hypotheses(
            a="attacker-controlled argv[1] reaches system() unsanitized",
            b="the value is always escaped before reaching system()",
            decisive_observable="metacharacter present unmodified in the sink arg",
        ),
        static_plan=_static_plan(),
        dynamic_plan=_dynamic_plan(),
    )
    parsed = StrategyPlan.model_validate_json(strategy.model_dump_json())
    assert parsed == strategy
    assert parsed.static_runnable is True
    assert parsed.dynamic_runnable is True
    # Post-check validator (fvvw.strategy) confirms these match; the schema
    # itself only carries them, doesn't enforce equality.
    assert (
        parsed.static_plan.decisive_observable
        == parsed.dynamic_plan.decisive_observable
        == parsed.hypotheses.decisive_observable
    )


def test_track_result_reuses_existing_verification_verdict_enum():
    result = TrackResult(
        verdict=VerificationVerdict.CONFIRMED,
        proved_hypothesis="A",
        evidence={"gdb_transcript": "..."},
        iters_used=2,
    )
    parsed = TrackResult.model_validate_json(result.model_dump_json())
    assert parsed.verdict == VerificationVerdict.CONFIRMED


def test_track_result_defaults_to_no_proved_hypothesis():
    result = TrackResult(verdict=VerificationVerdict.INCONCLUSIVE)
    assert result.proved_hypothesis == "none"


def test_agreement_enum_values():
    assert {a.value for a in Agreement} == {
        "concordant_confirm",
        "concordant_refute",
        "discordant",
        "one_sided",
    }


def test_mechanism_confidence_discordant_hold_never_auto_resolves():
    """Not a behavior test (that lives in fvvw.joint) — just pins the enum
    value the design doc's 'never auto-resolved by trusting one track by
    default' invariant is expressed through."""
    assert MechanismConfidence.DISCORDANT_HOLD.value == "discordant_hold"


def test_reachability_confidence_forced_unknown_is_distinct_from_conditional():
    assert ReachabilityConfidence.FORCED_UNKNOWN != ReachabilityConfidence.CONDITIONAL


def test_fvvw_report_round_trips_with_both_track_results():
    report = FVVWReport(
        global_id="vulnbin#0000::candidate_001",
        bin_id="vulnbin",
        static_result=TrackResult(verdict=VerificationVerdict.CONFIRMED, proved_hypothesis="A"),
        dynamic_result=TrackResult(verdict=VerificationVerdict.CONFIRMED, proved_hypothesis="A"),
        agreement=Agreement.CONCORDANT_CONFIRM,
        mechanism_confidence=MechanismConfidence.CONFIRMED_STRONG,
        reachability_confidence=ReachabilityConfidence.CONFIRMED,
        residual_unknowns=["caller of vuln_path could not be statically resolved"],
        report_markdown="# Disclosure Report\n...",
        started_at=datetime.now(UTC),
    )
    parsed = FVVWReport.model_validate_json(report.model_dump_json())
    assert parsed == report
    assert parsed.schema_version == 1
