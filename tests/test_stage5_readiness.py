"""Unit tests for `stage5_verification.readiness`.

Tests cover:
- `assess_readiness` level determination across all DependencyReport shapes
- BLOCKED cases: missing interpreter, ABI-incompatible library, >50% hard-missing
- UNCERTAIN cases: some missing (interpreter present), MISSING_EXPECTED
- STATIC_READY: all present, or static binary
- `format_bringup_brief` output shape
- `should_skip_candidate` logic
"""

from __future__ import annotations

from fw_audit.common.deps import (
    ConfidenceLevel,
    DependencyKind,
    DependencyReport,
    DependencyStatus,
    LibraryResolution,
    ReadinessLevel,
    ResolvedDependency,
)
from fw_audit.stage5_verification.readiness import (
    assess_readiness,
    format_bringup_brief,
    should_skip_candidate,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report(
    *,
    is_static: bool = False,
    interpreter: str | None = None,
    interpreter_status: DependencyStatus | None = None,
    libraries: list[LibraryResolution] | None = None,
    runtime_deps: list[ResolvedDependency] | None = None,
    blocking_reasons: list[str] | None = None,
) -> DependencyReport:
    libs = libraries or []
    total = len(libs)
    resolved = sum(1 for lib in libs if lib.status == DependencyStatus.PRESENT)
    missing = sum(1 for lib in libs if lib.status == DependencyStatus.MISSING)
    incompat = sum(1 for lib in libs if lib.status == DependencyStatus.PRESENT_INCOMPATIBLE)
    return DependencyReport(
        binary_path="/bin/app",
        binary_sha256="a" * 64,
        rootfs_dir="/rootfs",
        is_static=is_static,
        interpreter=interpreter,
        interpreter_status=interpreter_status,
        libraries=libs,
        runtime_deps=runtime_deps or [],
        total_needed=total,
        total_resolved=resolved,
        total_missing=missing,
        total_incompatible=incompat,
        blocking_reasons=blocking_reasons or [],
    )


def _lib(soname: str, status: DependencyStatus, abi_ok: bool | None = True) -> LibraryResolution:
    return LibraryResolution(
        soname=soname,
        status=status,
        resolved_path="/rootfs/lib/" + soname if status == DependencyStatus.PRESENT else "",
        needed_by=["app"],
        arch_compatible=abi_ok,
    )


# ---------------------------------------------------------------------------
# assess_readiness: static binary
# ---------------------------------------------------------------------------


def test_static_binary_is_static_ready() -> None:
    report = _make_report(is_static=True)
    assessment = assess_readiness(report)
    assert assessment.level == ReadinessLevel.STATIC_READY
    assert assessment.blocking_reasons == []


# ---------------------------------------------------------------------------
# assess_readiness: BLOCKED cases
# ---------------------------------------------------------------------------


def test_blocked_missing_interpreter() -> None:
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.MISSING,
    )
    assessment = assess_readiness(report)
    assert assessment.level == ReadinessLevel.BLOCKED
    assert any("interpreter" in r.lower() for r in assessment.blocking_reasons)


def test_blocked_broken_interpreter_symlink() -> None:
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.SYMLINK_BROKEN,
    )
    assessment = assess_readiness(report)
    assert assessment.level == ReadinessLevel.BLOCKED


def test_blocked_abi_incompatible_interpreter() -> None:
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.PRESENT_INCOMPATIBLE,
    )
    assessment = assess_readiness(report)
    assert assessment.level == ReadinessLevel.BLOCKED


def test_blocked_abi_incompatible_library() -> None:
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.PRESENT,
        libraries=[_lib("libssl.so.1", DependencyStatus.PRESENT_INCOMPATIBLE, abi_ok=False)],
    )
    assessment = assess_readiness(report)
    assert assessment.level == ReadinessLevel.BLOCKED
    assert any("ABI-incompatible" in r for r in assessment.blocking_reasons)


def test_blocked_majority_hard_missing() -> None:
    # 3 out of 4 hard-missing (not MISSING_EXPECTED) → >50% → BLOCKED
    libs = [
        _lib("libcrypto.so", DependencyStatus.MISSING),
        _lib("libssl.so", DependencyStatus.MISSING),
        _lib("libhttpd.so", DependencyStatus.MISSING),
        _lib("libc.so.6", DependencyStatus.PRESENT),
    ]
    report = _make_report(
        interpreter="/lib/ld-uClibc.so.0",
        interpreter_status=DependencyStatus.PRESENT,
        libraries=libs,
    )
    assessment = assess_readiness(report)
    assert assessment.level == ReadinessLevel.BLOCKED


# ---------------------------------------------------------------------------
# assess_readiness: UNCERTAIN cases
# ---------------------------------------------------------------------------


def test_uncertain_some_hard_missing() -> None:
    # 1 out of 4 hard-missing — under the 50% threshold → UNCERTAIN
    libs = [
        _lib("libssl.so", DependencyStatus.MISSING),
        _lib("libc.so.6", DependencyStatus.PRESENT),
        _lib("libm.so.6", DependencyStatus.PRESENT),
        _lib("libdl.so.2", DependencyStatus.PRESENT),
    ]
    report = _make_report(
        interpreter="/lib/ld-uClibc.so.0",
        interpreter_status=DependencyStatus.PRESENT,
        libraries=libs,
    )
    assessment = assess_readiness(report)
    assert assessment.level == ReadinessLevel.UNCERTAIN
    assert any("libssl.so" in u for u in assessment.uncertainties)


def test_uncertain_missing_expected() -> None:
    # MISSING_EXPECTED does not block, but produces UNCERTAIN
    libs = [_lib("libpthread.so.0", DependencyStatus.MISSING_EXPECTED)]
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.PRESENT,
        libraries=libs,
    )
    assessment = assess_readiness(report)
    assert assessment.level == ReadinessLevel.UNCERTAIN


def test_uncertain_inferred_runtime_dep() -> None:
    rdep = ResolvedDependency(
        name="/etc/config/wireless",
        kind=DependencyKind.CONFIG_FILE,
        status=DependencyStatus.MISSING,
        confidence=ConfidenceLevel.INFERRED,
    )
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.PRESENT,
        runtime_deps=[rdep],
    )
    assessment = assess_readiness(report)
    assert assessment.level == ReadinessLevel.UNCERTAIN


# ---------------------------------------------------------------------------
# assess_readiness: STATIC_READY
# ---------------------------------------------------------------------------


def test_static_ready_all_present() -> None:
    libs = [
        _lib("libc.so.6", DependencyStatus.PRESENT),
        _lib("libm.so.6", DependencyStatus.PRESENT),
    ]
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.PRESENT,
        libraries=libs,
    )
    assessment = assess_readiness(report)
    assert assessment.level == ReadinessLevel.STATIC_READY
    assert assessment.blocking_reasons == []
    assert assessment.uncertainties == []


def test_static_ready_no_libraries() -> None:
    # Dynamic binary with no DT_NEEDED (unusual but valid)
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.PRESENT,
        libraries=[],
    )
    assessment = assess_readiness(report)
    assert assessment.level == ReadinessLevel.STATIC_READY


# ---------------------------------------------------------------------------
# assess_readiness: remediation_hints
# ---------------------------------------------------------------------------


def test_hints_for_missing_library() -> None:
    libs = [_lib("libfoo.so.1", DependencyStatus.MISSING)]
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.PRESENT,
        libraries=libs,
    )
    assessment = assess_readiness(report)
    assert any("libfoo.so.1" in h for h in assessment.remediation_hints)


def test_hints_for_missing_interpreter() -> None:
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.MISSING,
    )
    assessment = assess_readiness(report)
    assert any("/lib/ld-linux.so.3" in h for h in assessment.remediation_hints)


# ---------------------------------------------------------------------------
# should_skip_candidate
# ---------------------------------------------------------------------------


def test_should_skip_blocked() -> None:
    from fw_audit.common.deps import ReadinessAssessment
    assessment = ReadinessAssessment(
        binary_path="/bin/app",
        binary_sha256="a" * 64,
        level=ReadinessLevel.BLOCKED,
    )
    assert should_skip_candidate(assessment) is True


def test_should_not_skip_uncertain() -> None:
    from fw_audit.common.deps import ReadinessAssessment
    assessment = ReadinessAssessment(
        binary_path="/bin/app",
        binary_sha256="a" * 64,
        level=ReadinessLevel.UNCERTAIN,
    )
    assert should_skip_candidate(assessment) is False


def test_should_not_skip_static_ready() -> None:
    from fw_audit.common.deps import ReadinessAssessment
    assessment = ReadinessAssessment(
        binary_path="/bin/app",
        binary_sha256="a" * 64,
        level=ReadinessLevel.STATIC_READY,
    )
    assert should_skip_candidate(assessment) is False


# ---------------------------------------------------------------------------
# format_bringup_brief
# ---------------------------------------------------------------------------


def test_bringup_brief_static_binary_empty() -> None:
    from fw_audit.common.deps import ReadinessAssessment
    report = _make_report(is_static=True)
    assessment = ReadinessAssessment(
        binary_path="/bin/app",
        binary_sha256="a" * 64,
        level=ReadinessLevel.STATIC_READY,
    )
    brief = format_bringup_brief(assessment, report)
    assert brief == ""


def test_bringup_brief_includes_missing_libraries() -> None:
    from fw_audit.common.deps import ReadinessAssessment
    libs = [
        _lib("libssl.so.1", DependencyStatus.MISSING),
        _lib("libc.so.6", DependencyStatus.PRESENT),
    ]
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.PRESENT,
        libraries=libs,
    )
    assessment = ReadinessAssessment(
        binary_path="/bin/app",
        binary_sha256="a" * 64,
        level=ReadinessLevel.UNCERTAIN,
    )
    brief = format_bringup_brief(assessment, report)
    assert "libssl.so.1" in brief
    assert "missing" in brief.lower()


def test_bringup_brief_includes_interpreter_status() -> None:
    from fw_audit.common.deps import ReadinessAssessment
    report = _make_report(
        interpreter="/lib/ld-uClibc.so.0",
        interpreter_status=DependencyStatus.PRESENT,
    )
    assessment = ReadinessAssessment(
        binary_path="/bin/app",
        binary_sha256="a" * 64,
        level=ReadinessLevel.STATIC_READY,
    )
    brief = format_bringup_brief(assessment, report)
    assert "/lib/ld-uClibc.so.0" in brief
    assert "PRESENT" in brief or "present" in brief


def test_bringup_brief_includes_config_files() -> None:
    from fw_audit.common.deps import ReadinessAssessment
    rdep = ResolvedDependency(
        name="/etc/config/wireless",
        kind=DependencyKind.CONFIG_FILE,
        status=DependencyStatus.MISSING,
        confidence=ConfidenceLevel.INFERRED,
    )
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.PRESENT,
        runtime_deps=[rdep],
    )
    assessment = ReadinessAssessment(
        binary_path="/bin/app",
        binary_sha256="a" * 64,
        level=ReadinessLevel.UNCERTAIN,
    )
    brief = format_bringup_brief(assessment, report)
    assert "/etc/config/wireless" in brief


def test_bringup_brief_no_problems_empty() -> None:
    from fw_audit.common.deps import ReadinessAssessment
    report = _make_report(
        interpreter="/lib/ld-linux.so.3",
        interpreter_status=DependencyStatus.PRESENT,
        libraries=[_lib("libc.so.6", DependencyStatus.PRESENT)],
    )
    assessment = ReadinessAssessment(
        binary_path="/bin/app",
        binary_sha256="a" * 64,
        level=ReadinessLevel.STATIC_READY,
    )
    brief = format_bringup_brief(assessment, report)
    # Interpreter line present, no missing-libs section
    assert "ld-linux.so.3" in brief
    assert "Missing" not in brief
