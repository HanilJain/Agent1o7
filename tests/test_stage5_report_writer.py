"""Tests for `fw_audit.stage5_verification.report_writer` — Markdown shape."""

from __future__ import annotations

from datetime import UTC, datetime

from fw_audit.common.findings import (
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.common.verification import (
    CpgBuildRecord,
    JoernScriptAttempt,
    VerificationReport,
    VerificationVerdict,
)
from fw_audit.stage5_verification.report_writer import render_report


def _finding() -> Finding:
    return Finding(
        finding_id="c1",
        title="Unbounded memcpy",
        category="memory_safety",
        cwe=["CWE-787"],
        severity=Severity(impact=4, exploitability=3, reachability=3),
        confidence=Confidence.HIGH,
        decision=Decision.ESCALATE,
        evidence_span=EvidenceSpan(function_id="f", line_start=1, line_end=2, code="x"),
        source=FindingSource(
            expression="param_1", type="FUNCTION_PARAMETER", attacker_control="UNKNOWN"
        ),
        sink=FindingSink(expression="memcpy(dst, param_1, len)", type="MEMORY_WRITE"),
        security_condition="unchecked length",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )


def _report(verdict: VerificationVerdict, *, attempts=None, cpg_ok=True) -> VerificationReport:
    return VerificationReport(
        global_id="bin#0000::c1",
        bin_id="bin",
        model="anthropic:claude-sonnet-4-5",
        cpg_build=CpgBuildRecord(
            command="joern-parse whole.c --output cpg.bin",
            ok=cpg_ok,
            duration_seconds=3.2,
            stderr="" if cpg_ok else "boom",
        ),
        attempts=attempts or [],
        verdict=verdict,
        confidence="HIGH",
        summary="The CPG shows an unguarded flow from param_1 to memcpy.",
        evidence="cpg.call.name(\"memcpy\").argument.l -> [param_1]",
        recommended_next_steps=["Confirm with QEMU+GDB dynamic trace."],
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )


def test_render_report_includes_verdict_and_summary():
    report = _report(VerificationVerdict.CONFIRMED)
    md = render_report(report)
    assert "**Verdict: CONFIRMED**" in md
    assert report.summary in md


def test_render_report_includes_original_finding_when_given():
    report = _report(VerificationVerdict.CONFIRMED)
    md = render_report(report, finding=_finding())
    assert "Unbounded memcpy" in md
    assert "memory_safety" in md
    assert "CWE-787" in md


def test_render_report_omits_original_finding_section_when_not_given():
    report = _report(VerificationVerdict.CONFIRMED)
    md = render_report(report)
    assert "## Original claim" not in md


def test_render_report_shows_cpg_build_failure_with_stderr():
    report = _report(VerificationVerdict.ERROR, cpg_ok=False)
    md = render_report(report)
    assert "FAILED" in md
    assert "boom" in md


def test_render_report_lists_each_attempt():
    attempts = [
        JoernScriptAttempt(
            attempt_index=0, script="cpg.method.l", stdout="[]", ok=True, returncode=0
        ),
        JoernScriptAttempt(
            attempt_index=1,
            script="cpg.bad.syntax",
            stderr="parse error",
            ok=False,
            returncode=1,
        ),
    ]
    report = _report(VerificationVerdict.INCONCLUSIVE, attempts=attempts)
    md = render_report(report)
    assert "Attempt 0 — ok" in md
    assert "Attempt 1 — FAILED (returncode=1)" in md
    assert "cpg.method.l" in md
    assert "parse error" in md


def test_render_report_includes_reproduction_command():
    report = _report(VerificationVerdict.CONFIRMED)
    md = render_report(report)
    assert "## How to reproduce this yourself" in md
    assert "joern-parse" in md
    assert "fw-verify debug script" in md


def test_render_report_includes_recommended_next_steps():
    report = _report(VerificationVerdict.INCONCLUSIVE)
    md = render_report(report)
    assert "Confirm with QEMU+GDB dynamic trace." in md
