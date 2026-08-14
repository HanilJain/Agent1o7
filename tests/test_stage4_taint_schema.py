"""Tests for `fw_audit.common.taint`."""

from __future__ import annotations

from datetime import UTC, datetime

from fw_audit.common.taint import (
    FindingRunRecord,
    SourceClass,
    Stage4RunSummary,
    TaintPath,
    TaintPathReport,
    TaintStep,
)


def test_taint_step_source_class_optional():
    origin = TaintStep(
        step_index=0,
        code_location="sbin/httpd:main#L10",
        description="read",
        source_class=SourceClass.NVRAM,
    )
    intermediate = TaintStep(step_index=1, code_location="sbin/httpd:main#L20", description="call")
    assert origin.source_class is SourceClass.NVRAM
    assert intermediate.source_class is None


def test_taint_path_report_round_trips_json():
    origin_step = TaintStep(
        step_index=0, code_location="a#L1", description="d", source_class=SourceClass.HTTP_PARAM
    )
    report = TaintPathReport(
        finding_id="bin#0000::c1",
        resolved=True,
        taint_paths=[
            TaintPath(
                steps=[origin_step],
                source_class=SourceClass.HTTP_PARAM,
                confidence="HIGH",
                narrative="n",
            )
        ],
    )
    restored = TaintPathReport.model_validate_json(report.model_dump_json())
    assert restored == report


def test_taint_path_report_defaults_unresolved_empty():
    report = TaintPathReport(finding_id="x", resolved=False, taint_paths=[])
    assert report.missing_context == []
    assert report.analysis_notes == ""


def test_stage4_run_summary_defaults():
    summary = Stage4RunSummary(
        status="completed", db_subfolder="/db/fw", started_at=datetime.now(UTC)
    )
    assert summary.total_findings == 0
    assert summary.findings == []


def test_finding_run_record_optional_error():
    record = FindingRunRecord(
        global_id="bin#0000::c1", chunk_id="bin#0000", bin_id="bin", status="completed"
    )
    assert record.error is None
    assert record.attempts == 0
