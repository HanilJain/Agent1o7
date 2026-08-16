"""Round-trip tests for `fw_audit.common.verification` — the standard JSON
report schema, mirroring `tests/test_findings_schema.py`'s acceptance-test
shape for `common.findings`."""

from __future__ import annotations

from datetime import UTC, datetime

from fw_audit.common.verification import (
    CandidateRunRecord,
    CpgBuildRecord,
    JoernScriptAttempt,
    VerificationReport,
    VerificationRunSummary,
    VerificationVerdict,
    VerifierVerdict,
)


def test_verifier_verdict_round_trips_through_json():
    verdict = VerifierVerdict(
        verdict=VerificationVerdict.CONFIRMED,
        confidence="HIGH",
        summary="s",
        evidence="e",
        recommended_next_steps=["do x"],
    )
    parsed = VerifierVerdict.model_validate_json(verdict.model_dump_json())
    assert parsed == verdict


def test_verification_report_round_trips_through_json():
    report = VerificationReport(
        global_id="bin#0000::c1",
        bin_id="bin",
        model="anthropic:claude-sonnet-4-5",
        cpg_build=CpgBuildRecord(command="joern-parse", ok=True, duration_seconds=1.5),
        attempts=[
            JoernScriptAttempt(
                attempt_index=0, script="cpg.method.l", stdout="[]", ok=True, returncode=0
            )
        ],
        verdict=VerificationVerdict.CONFIRMED,
        confidence="HIGH",
        summary="s",
        evidence="e",
        recommended_next_steps=[],
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )
    parsed = VerificationReport.model_validate_json(report.model_dump_json())
    assert parsed.global_id == report.global_id
    assert parsed.verdict == VerificationVerdict.CONFIRMED
    assert parsed.attempts[0].script == "cpg.method.l"
    assert parsed.schema_version == 1


def test_verification_report_defaults():
    report = VerificationReport(
        global_id="g",
        bin_id="b",
        verdict=VerificationVerdict.ERROR,
        started_at=datetime.now(UTC),
    )
    assert report.tool == "joern"
    assert report.attempts == []
    assert report.cpg_build.ok is False


def test_verification_run_summary_round_trips_through_json():
    summary = VerificationRunSummary(
        run_id="r1",
        status="completed",
        db_subfolder="/db/fw",
        model="anthropic:claude-sonnet-4-5",
        candidates=[
            CandidateRunRecord(
                global_id="bin#0000::c1",
                chunk_id="bin#0000",
                bin_id="bin",
                status="verified",
                attempts=1,
                verdict="CONFIRMED",
            )
        ],
        total_candidates=1,
        total_verified=1,
        verdicts_by_type={"CONFIRMED": 1},
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )
    parsed = VerificationRunSummary.model_validate_json(summary.model_dump_json())
    assert parsed.total_verified == 1
    assert parsed.candidates[0].verdict == "CONFIRMED"


def test_verification_verdict_enum_values():
    assert {v.value for v in VerificationVerdict} == {
        "CONFIRMED",
        "REFUTED",
        "INCONCLUSIVE",
        "ERROR",
    }
