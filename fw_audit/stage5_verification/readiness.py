"""Execution-readiness assessment for Stage 5 FVVW v3 dynamic track.

Derives a ``ReadinessAssessment`` (a structured JUDGEMENT: can this binary
run under QEMU?) from a ``DependencyReport`` (FACTUAL: what deps does it
have?) and a ``TargetMeta`` (factual: what arch/PIE/daemon flags?).

All functions are purely deterministic — no LLM, no sandbox call.  The module
also provides ``format_bringup_brief``, which renders the assessment into a
structured Markdown section the bringup agent receives in its system prompt so
it knows upfront what to fix rather than rediscovering missing files via strace.
"""

from __future__ import annotations

from fw_audit.common.deps import (
    DependencyReport,
    DependencyStatus,
    ReadinessAssessment,
    ReadinessLevel,
)
from fw_audit.common.verification import TargetMeta

# ---------------------------------------------------------------------------
# Level determination thresholds
# ---------------------------------------------------------------------------

# Fraction of DT_NEEDED libs that must be truly missing (not MISSING_EXPECTED)
# before we call it BLOCKED.  0.5 means >50% missing → BLOCKED.
_BLOCKING_MISSING_FRACTION = 0.5


def _count_hard_missing(report: DependencyReport) -> int:
    """Count libraries that are MISSING (not MISSING_EXPECTED) — these are
    the ones that concretely block dynamic loading."""
    return sum(
        1
        for lib in report.libraries
        if lib.status == DependencyStatus.MISSING
    )


def _count_soft_missing(report: DependencyReport) -> int:
    """Count libraries with MISSING_EXPECTED status — missing but typical for
    partial firmware; likely OK with stubs."""
    return sum(
        1
        for lib in report.libraries
        if lib.status == DependencyStatus.MISSING_EXPECTED
    )


def assess_readiness(
    dep_report: DependencyReport,
    target: TargetMeta | None = None,
) -> ReadinessAssessment:
    """Derive a ``ReadinessAssessment`` from ``dep_report`` (and optionally
    ``target``'s arch facts).

    Level determination (in priority order):
    - **BLOCKED** if:
        * interpreter missing/broken/ABI-incompatible, OR
        * any ABI-incompatible library exists, OR
        * >50% of DT_NEEDED are hard-MISSING (not MISSING_EXPECTED)
    - **UNCERTAIN** if:
        * any MISSING library (interpreter present), OR
        * any MISSING_EXPECTED library
    - **STATIC_READY** otherwise (all libs PRESENT or MISSING_EXPECTED,
      interpreter OK or absent)

    RUNTIME_READY and VERIFICATION_READY are never set here — they are
    upgraded externally by the FVVW health gate after a successful QEMU
    liveness probe / trigger probe.
    """
    binary_path = dep_report.binary_path
    binary_sha256 = dep_report.binary_sha256

    blocking: list[str] = list(dep_report.blocking_reasons)  # copy, don't mutate
    uncertainties: list[str] = []
    hints: list[str] = []

    # Statically linked binaries have no dynamic deps → STATIC_READY by default
    if dep_report.is_static:
        return ReadinessAssessment(
            binary_path=binary_path,
            binary_sha256=binary_sha256,
            level=ReadinessLevel.STATIC_READY,
            blocking_reasons=[],
            uncertainties=[],
            remediation_hints=["Binary is statically linked — no shared library stubs needed."],
        )

    # --- Interpreter check ---
    interp_status = dep_report.interpreter_status
    if interp_status in (
        DependencyStatus.MISSING,
        DependencyStatus.SYMLINK_BROKEN,
        DependencyStatus.PRESENT_INCOMPATIBLE,
    ):
        interp_str = dep_report.interpreter or "unknown interpreter"
        if "dynamic interpreter" not in " ".join(blocking):
            blocking.append(
                f"dynamic interpreter not found in rootfs: {interp_str}"
                if interp_status == DependencyStatus.MISSING
                else f"dynamic interpreter ABI mismatch or broken symlink: {interp_str}"
            )
        hints.append(
            f"Ensure {interp_str} exists inside the rootfs (bind-mount or stub)"
        )

    # --- Library checks ---
    hard_missing = _count_hard_missing(dep_report)
    soft_missing = _count_soft_missing(dep_report)
    incompat = dep_report.total_incompatible

    total = dep_report.total_needed or 1  # avoid ZeroDivisionError

    if incompat > 0:
        incompat_libs = [
            lib.soname
            for lib in dep_report.libraries
            if lib.status == DependencyStatus.PRESENT_INCOMPATIBLE
        ]
        for soname in incompat_libs:
            if soname not in " ".join(blocking):
                blocking.append(f"ABI-incompatible library found: {soname}")
        hints.append(
            "Replace or stub ABI-incompatible libraries with arch-compatible versions"
        )

    if hard_missing / total > _BLOCKING_MISSING_FRACTION:
        blocking.append(
            f"{hard_missing}/{total} required libraries missing from rootfs"
            " (exceeds 50% threshold)"
        )
        missing_names = [
            lib.soname
            for lib in dep_report.libraries
            if lib.status == DependencyStatus.MISSING
        ]
        for name in missing_names[:10]:
            hints.append(f"Create stub library: {name}")

    elif hard_missing > 0:
        missing_names = [
            lib.soname
            for lib in dep_report.libraries
            if lib.status == DependencyStatus.MISSING
        ]
        for name in missing_names:
            uncertainties.append(f"library missing from rootfs: {name}")
            hints.append(f"Create stub library: {name}")

    if soft_missing > 0:
        names = [
            lib.soname
            for lib in dep_report.libraries
            if lib.status == DependencyStatus.MISSING_EXPECTED
        ]
        for name in names:
            uncertainties.append(
                f"library missing but expected for partial firmware: {name}"
            )

    # Runtime dependency uncertainties
    for rdep in dep_report.runtime_deps:
        if rdep.status == DependencyStatus.MISSING:
            uncertainties.append(
                f"inferred {rdep.kind.value} may be required: {rdep.name}"
            )
            if rdep.kind.value == "config_file":
                hints.append(f"Touch dummy config: {rdep.name}")
            elif rdep.kind.value == "device_node":
                hints.append(f"Create device node: {rdep.name}")

    # Determine level
    if blocking:
        level = ReadinessLevel.BLOCKED
    elif uncertainties:
        level = ReadinessLevel.UNCERTAIN
    else:
        level = ReadinessLevel.STATIC_READY

    return ReadinessAssessment(
        binary_path=binary_path,
        binary_sha256=binary_sha256,
        level=level,
        blocking_reasons=blocking,
        uncertainties=uncertainties,
        remediation_hints=hints,
    )


def should_skip_candidate(assessment: ReadinessAssessment) -> bool:
    """Returns True only for BLOCKED candidates.  Never a hard gate by itself
    — callers must also check ``settings.stage5_skip_blocked``."""
    return assessment.level == ReadinessLevel.BLOCKED


# ---------------------------------------------------------------------------
# Bringup brief renderer
# ---------------------------------------------------------------------------


def format_bringup_brief(
    assessment: ReadinessAssessment,
    dep_report: DependencyReport,
) -> str:
    """Render a Markdown section for the bringup agent's system prompt
    listing known missing libraries, config files, and device nodes so it
    can fix the environment proactively instead of relying solely on strace.

    Returns an empty string when there is nothing to report (all deps present,
    static binary, or empty report).
    """
    if dep_report.is_static:
        return ""

    lines: list[str] = []

    # Interpreter summary
    if dep_report.interpreter:
        interp_ok = dep_report.interpreter_status == DependencyStatus.PRESENT
        interp_label = "PRESENT, ABI-compatible" if interp_ok else (
            str(dep_report.interpreter_status.value)
            if dep_report.interpreter_status
            else "unknown"
        )
        lines.append(f"- Interpreter: `{dep_report.interpreter}` ({interp_label})")

    # Missing / incompatible libraries
    problem_libs = [
        lib
        for lib in dep_report.libraries
        if lib.status != DependencyStatus.PRESENT
    ]
    if problem_libs:
        lines.append("")
        lines.append("**Missing / incompatible shared libraries (create stubs or fix):**")
        for lib in problem_libs:
            needed_by = ", ".join(lib.needed_by[:3])
            lines.append(
                f"- `{lib.soname}` — {lib.status.value}"
                + (f" (needed by: {needed_by})" if needed_by else "")
            )

    # Inferred runtime dependencies
    if dep_report.runtime_deps:
        config_deps = [
            d for d in dep_report.runtime_deps if d.kind.value == "config_file"
        ]
        dev_deps = [
            d for d in dep_report.runtime_deps if d.kind.value == "device_node"
        ]

        if config_deps:
            lines.append("")
            lines.append("**Missing config files (create dummies):**")
            for d in config_deps[:10]:
                lines.append(f"- `{d.name}`")

        if dev_deps:
            lines.append("")
            lines.append("**Missing device nodes (create with mknod):**")
            for d in dev_deps[:10]:
                lines.append(f"- `{d.name}`")

    if not lines:
        return ""

    header = [
        "## Known Dependencies (pre-resolved)",
        "",
        f"Readiness level: **{assessment.level.value}**",
        "",
    ]
    return "\n".join(header + lines) + "\n"


__all__ = [
    "assess_readiness",
    "format_bringup_brief",
    "should_skip_candidate",
]
