"""Tests for `stage5_verification.fvvw.hitl` — the FVVW HITL plan's Part 3.

`prompt_for_track` is exercised with a SCRIPTED `Prompter` (a plain sync
callable returning a pre-chosen `HitlDecision`) so nothing here touches
real stdin — matching this repo's existing "duck-typed fake" convention for
LLMs/executors (`_ScriptedLLM` in `test_fvvw_graph.py`, `FakeExecutor` in
`conftest.py`).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fw_audit.common.verification import (
    DynamicPlan,
    StaticPlan,
    TargetMeta,
    TrackResult,
    VerificationVerdict,
)
from fw_audit.stage5_verification.fvvw.hitl import (
    HitlAction,
    HitlDecision,
    HitlRequest,
    build_human_review_record,
    force_verdict_result,
    is_budget_exhausted,
    prompt_for_track,
)


def _target() -> TargetMeta:
    return TargetMeta(arch="arm", endianness="little", func_offset="0x1000")


def _dynamic_plan(**overrides) -> DynamicPlan:
    defaults = dict(
        reach_strategy="inferior_call",
        payload_marker=";touch /tmp/claim_001_proof;",
        decisive_observable="obs",
    )
    defaults.update(overrides)
    return DynamicPlan(**defaults)


def _static_plan(**overrides) -> StaticPlan:
    defaults = dict(target_function="FUN_1", decisive_observable="obs")
    defaults.update(overrides)
    return StaticPlan(**defaults)


def _exhausted_result(**evidence_overrides) -> TrackResult:
    evidence = {"budget_exhausted": True}
    evidence.update(evidence_overrides)
    return TrackResult(
        verdict=VerificationVerdict.INCONCLUSIVE,
        proved_hypothesis="none",
        evidence=evidence,
        iters_used=4,
    )


def _request(*, track: str = "dynamic", result: TrackResult | None = None) -> HitlRequest:
    return HitlRequest(
        global_id="bin#0000::finding_001",
        track=track,
        result=result or _exhausted_result(),
        plan=_dynamic_plan() if track == "dynamic" else _static_plan(),
        target=_target(),
        recent_commands=[],
        round_number=1,
    )


# ---------------------------------------------------------------------- #
# is_budget_exhausted — the trigger condition
# ---------------------------------------------------------------------- #


def test_is_budget_exhausted_true_when_tagged():
    result = TrackResult(
        verdict=VerificationVerdict.INCONCLUSIVE,
        proved_hypothesis="none",
        evidence={"budget_exhausted": True},
    )
    assert is_budget_exhausted(result) is True


def test_is_budget_exhausted_false_when_not_tagged():
    """A plain INCONCLUSIVE with no explicit tag is NOT treated as
    budget-exhausted — the trigger is a FACT set by the producing track,
    never re-derived from the bare verdict value alone."""
    result = TrackResult(
        verdict=VerificationVerdict.INCONCLUSIVE, proved_hypothesis="none", evidence={}
    )
    assert is_budget_exhausted(result) is False


def test_is_budget_exhausted_false_for_confirmed():
    result = TrackResult(verdict=VerificationVerdict.CONFIRMED, proved_hypothesis="A")
    assert is_budget_exhausted(result) is False


# ---------------------------------------------------------------------- #
# prompt_for_track — the four actions, scripted (no real stdin)
# ---------------------------------------------------------------------- #


async def test_prompt_for_track_retry_action():
    def scripted(req: HitlRequest) -> HitlDecision:
        assert req.track == "dynamic"
        return HitlDecision(action=HitlAction.RETRY, extra_iterations=6)

    decision = await prompt_for_track(_request(), prompter=scripted)
    assert decision.action == HitlAction.RETRY
    assert decision.extra_iterations == 6


async def test_prompt_for_track_override_plan_action_carries_overrides():
    overrides = {"entry_addr": "0x9999", "sink_addr": "0xAAAA"}

    def scripted(req: HitlRequest) -> HitlDecision:
        return HitlDecision(action=HitlAction.OVERRIDE_PLAN, plan_overrides=overrides)

    decision = await prompt_for_track(_request(), prompter=scripted)
    assert decision.action == HitlAction.OVERRIDE_PLAN
    assert decision.plan_overrides == overrides


async def test_prompt_for_track_inject_action_carries_payload():
    payload = "break *0x2000\ncontinue\nprintf \"TRIGGER:sink_arg:%s\\n\", (char*)$r0\n"

    def scripted(req: HitlRequest) -> HitlDecision:
        return HitlDecision(action=HitlAction.INJECT, injected_payload=payload)

    decision = await prompt_for_track(_request(), prompter=scripted)
    assert decision.action == HitlAction.INJECT
    assert decision.injected_payload == payload


async def test_prompt_for_track_force_verdict_action_carries_verdict_and_rationale():
    def scripted(req: HitlRequest) -> HitlDecision:
        return HitlDecision(
            action=HitlAction.FORCE_VERDICT,
            forced_verdict=VerificationVerdict.CONFIRMED,
            rationale="manually confirmed via ida",
        )

    decision = await prompt_for_track(_request(), prompter=scripted)
    assert decision.action == HitlAction.FORCE_VERDICT
    assert decision.forced_verdict == VerificationVerdict.CONFIRMED
    assert decision.rationale == "manually confirmed via ida"


async def test_prompt_for_track_skip_action():
    def scripted(req: HitlRequest) -> HitlDecision:
        return HitlDecision(action=HitlAction.SKIP)

    decision = await prompt_for_track(_request(), prompter=scripted)
    assert decision.action == HitlAction.SKIP


async def test_prompt_for_track_static_request_carries_static_plan():
    def scripted(req: HitlRequest) -> HitlDecision:
        assert req.track == "static"
        assert isinstance(req.plan, StaticPlan)
        return HitlDecision(action=HitlAction.SKIP)

    await prompt_for_track(_request(track="static"), prompter=scripted)


# ---------------------------------------------------------------------- #
# force_verdict_result — evidence["human_attributed"] is what lets
# joint_evaluate/report state the attribution explicitly
# ---------------------------------------------------------------------- #


def test_force_verdict_result_sets_human_attributed():
    previous = _exhausted_result()
    result = force_verdict_result(
        previous=previous, verdict=VerificationVerdict.CONFIRMED, rationale="confirmed by hand"
    )
    assert result.verdict == VerificationVerdict.CONFIRMED
    assert result.proved_hypothesis == "A"
    assert result.evidence["human_attributed"] is True
    assert result.evidence["rationale"] == "confirmed by hand"
    # iters_used carries forward from the previous (machine) result — the
    # human didn't re-run anything, just re-labeled the outcome.
    assert result.iters_used == previous.iters_used


def test_force_verdict_result_refuted_maps_to_hypothesis_b():
    result = force_verdict_result(
        previous=_exhausted_result(), verdict=VerificationVerdict.REFUTED, rationale="r"
    )
    assert result.proved_hypothesis == "B"


def test_force_verdict_result_inconclusive_maps_to_none():
    result = force_verdict_result(
        previous=_exhausted_result(), verdict=VerificationVerdict.INCONCLUSIVE, rationale="r"
    )
    assert result.proved_hypothesis == "none"


def test_force_verdict_result_preserves_prior_evidence_keys():
    previous = _exhausted_result(some_prior_key="kept")
    result = force_verdict_result(
        previous=previous, verdict=VerificationVerdict.CONFIRMED, rationale="r"
    )
    assert result.evidence["some_prior_key"] == "kept"


# ---------------------------------------------------------------------- #
# build_human_review_record
# ---------------------------------------------------------------------- #


def test_build_human_review_record_force_verdict():
    decision = HitlDecision(
        action=HitlAction.FORCE_VERDICT,
        forced_verdict=VerificationVerdict.CONFIRMED,
        rationale="manual review",
    )
    record = build_human_review_record(track="dynamic", decision=decision, rounds=2)
    assert record.track == "dynamic"
    assert record.action == "force_verdict"
    assert record.rationale == "manual review"
    assert record.rounds == 2
    assert record.overrides == {}


def test_build_human_review_record_override_plan_carries_overrides():
    overrides = {"entry_addr": "0x9999"}
    decision = HitlDecision(action=HitlAction.OVERRIDE_PLAN, plan_overrides=overrides)
    record = build_human_review_record(track="static", decision=decision, rounds=1)
    assert record.overrides == overrides


def test_build_human_review_record_inject_carries_payload():
    decision = HitlDecision(action=HitlAction.INJECT, injected_payload="break *0x2000\n")
    record = build_human_review_record(track="dynamic", decision=decision, rounds=1)
    assert record.overrides == {"injected_payload": "break *0x2000\n"}


def test_build_human_review_record_timestamp_is_recent():
    decision = HitlDecision(action=HitlAction.RETRY, extra_iterations=4)
    before = datetime.now(UTC)
    record = build_human_review_record(track="dynamic", decision=decision, rounds=1)
    after = datetime.now(UTC)
    assert before <= record.timestamp <= after
