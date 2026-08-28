"""Tests for `stage5_verification.candidate_index.resolve_binary_target` —
Stage 5 FVVW v3 Phase 1's dynamic-track counterpart to
`resolve_source_path`. Same fixture-building style as
`tests/test_stage5_candidate_index.py`, plus a real-rootfs-on-disk case
since this function (unlike `resolve_source_path`) resolves an absolute
host path OUTSIDE `db_subfolder`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from fw_audit.common.findings import (
    AnalysisReport,
    Confidence,
    Decision,
    EvidenceSpan,
    Finding,
    FindingSink,
    FindingSource,
    Severity,
)
from fw_audit.common.schemas import (
    DecompilationArtifacts,
    DecompilationStatus,
    DecompiledBinary,
    ELFArch,
    ELFInfo,
    ExtractionStatus,
    GhidraFunction,
    Stage2Summary,
)
from fw_audit.stage5_verification.candidate_index import (
    ResolvedBinaryTarget,
    VerificationCandidate,
    discover_candidates,
    resolve_binary_target,
)


def _finding(finding_id: str = "candidate_001") -> Finding:
    return Finding(
        finding_id=finding_id,
        title="t",
        category="command_execution",
        severity=Severity(impact=3, exploitability=3, reachability=3),
        confidence=Confidence.MEDIUM,
        decision=Decision.ESCALATE,
        evidence_span=EvidenceSpan(
            function_id="FUN_00026938", line_start=1, line_end=2, code="x"
        ),
        source=FindingSource(
            expression="argv[1]", type="FUNCTION_PARAMETER", attacker_control="YES"
        ),
        sink=FindingSink(expression="system(cmd)", type="COMMAND_EXECUTION"),
        security_condition="c",
        exploitability="e",
        impact="i",
        why_vulnerable="w",
        why_not_false_positive="n",
    )


def _elf_info(rootfs_path: str) -> ELFInfo:
    return ELFInfo(
        path=rootfs_path,
        absolute_path=f"/x/{rootfs_path}",
        size_bytes=4096,
        arch=ELFArch.ARM,
        is_64bit=False,
        is_little_endian=True,
        is_stripped=True,
        interpreter="/lib/ld-uClibc.so.0",
    )


def _decompiled_binary(
    bin_id: str, rootfs_path: str, *, elf: ELFInfo | None = None, functions=()
) -> DecompiledBinary:
    return DecompiledBinary(
        bin_id=bin_id,
        rootfs_path=rootfs_path,
        requested_path=rootfs_path,
        sha256="0" * 64,
        size_bytes=4096,
        elf=elf,
        status=DecompilationStatus.SUCCEEDED,
        functions=list(functions),
        artifacts=DecompilationArtifacts(
            normalized_joern_c=f"stage2/binaries/{bin_id}/normalized/joern/whole.c"
        ),
    )


def _stage2_summary(*, rootfs_dir: str, binaries: list[DecompiledBinary]) -> Stage2Summary:
    return Stage2Summary(
        run_id="r1",
        status=ExtractionStatus.COMPLETED,
        db_subfolder="db",
        rootfs_dir=rootfs_dir,
        stage2_dir="db/stage2",
        ghidra_image="fw-audit-ghidra:latest",
        binaries=binaries,
        started_at=datetime.now(UTC),
    )


def test_resolves_real_binary_path_from_rootfs_and_rootfs_path(tmp_path: Path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    elf_path = rootfs / "bin" / "vulnbin"
    elf_path.write_bytes(b"\x7fELF")

    elf_info = _elf_info("bin/vulnbin")
    fn = GhidraFunction(
        name="vuln_path", entry_point="0x00026938", size=100, signature="void vuln_path()"
    )
    summary = _stage2_summary(
        rootfs_dir=str(rootfs),
        binaries=[_decompiled_binary("vulnbin", "bin/vulnbin", elf=elf_info, functions=[fn])],
    )

    result = resolve_binary_target("vulnbin", stage2_summary=summary)

    assert isinstance(result, ResolvedBinaryTarget)
    assert result.binary_path == elf_path.resolve()
    assert result.rootfs_dir == rootfs
    assert result.elf == elf_info
    assert result.functions == (fn,)


def test_returns_empty_when_rootfs_dir_unset():
    summary = _stage2_summary(
        rootfs_dir="", binaries=[_decompiled_binary("vulnbin", "bin/vulnbin")]
    )
    result = resolve_binary_target("vulnbin", stage2_summary=summary)
    assert result.binary_path is None
    assert result.rootfs_dir is None
    assert result.elf is None
    assert result.functions == ()


def test_returns_empty_when_rootfs_dir_not_a_real_directory(tmp_path: Path):
    missing_rootfs = tmp_path / "does_not_exist"
    summary = _stage2_summary(
        rootfs_dir=str(missing_rootfs),
        binaries=[_decompiled_binary("vulnbin", "bin/vulnbin")],
    )
    result = resolve_binary_target("vulnbin", stage2_summary=summary)
    assert result.binary_path is None


def test_returns_empty_when_bin_id_not_found(tmp_path: Path):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    summary = _stage2_summary(
        rootfs_dir=str(rootfs), binaries=[_decompiled_binary("other_bin", "bin/other")]
    )
    result = resolve_binary_target("vulnbin", stage2_summary=summary)
    assert result.binary_path is None
    assert result.rootfs_dir is None


def test_returns_elf_and_functions_even_when_elf_file_missing_from_disk(tmp_path: Path):
    """The binary was resolved in Stage 2's summary but the file since
    disappeared from disk (removed/renamed) — binary_path is None (can't
    emulate a file that doesn't exist) but the already-computed ELF/function
    facts are still returned, matching resolve_source_path's "candidate
    still discovered, just can't build a CPG" precedent."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()  # rootfs exists, but bin/vulnbin under it does not
    elf_info = _elf_info("bin/vulnbin")
    fn = GhidraFunction(name="f", entry_point="0x1000", size=10, signature="void f()")
    summary = _stage2_summary(
        rootfs_dir=str(rootfs),
        binaries=[_decompiled_binary("vulnbin", "bin/vulnbin", elf=elf_info, functions=[fn])],
    )

    result = resolve_binary_target("vulnbin", stage2_summary=summary)

    assert result.binary_path is None
    assert result.rootfs_dir == rootfs
    assert result.elf == elf_info
    assert result.functions == (fn,)


def test_discover_candidates_populates_dynamic_track_fields(tmp_path: Path):
    """End-to-end: discover_candidates wires resolve_binary_target's result
    into VerificationCandidate, alongside the existing source_path
    resolution — neither resolution affects the other."""
    db_subfolder = tmp_path / "db"
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "vulnbin").write_bytes(b"\x7fELF")

    joern_c = db_subfolder / "stage2" / "binaries" / "vulnbin" / "normalized" / "joern" / "whole.c"
    joern_c.parent.mkdir(parents=True)
    joern_c.write_text("int main() { return 0; }\n", encoding="utf-8")

    elf_info = _elf_info("bin/vulnbin")
    summary = _stage2_summary(
        rootfs_dir=str(rootfs),
        binaries=[_decompiled_binary("vulnbin", "bin/vulnbin", elf=elf_info)],
    )
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(exist_ok=True)
    (stage2_dir / "stage2_summary.json").write_text(
        summary.model_dump_json(), encoding="utf-8"
    )

    findings_dir = db_subfolder / "stage3" / "findings"
    findings_dir.mkdir(parents=True)
    report = AnalysisReport(chunk_id="vulnbin#0000", findings=[_finding()])
    (findings_dir / "vulnbin__0000.json").write_text(
        json.dumps(report.model_dump(mode="json")), encoding="utf-8"
    )

    candidates = discover_candidates(db_subfolder)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert isinstance(candidate, VerificationCandidate)
    assert candidate.source_path == joern_c.resolve()  # existing static-track field, unaffected
    assert candidate.binary_path == (rootfs / "bin" / "vulnbin").resolve()
    assert candidate.rootfs_dir == rootfs
    assert candidate.elf == elf_info


def test_discover_candidates_tolerates_unresolvable_binary_target(tmp_path: Path):
    """No rootfs_dir at all — dynamic-track fields stay None/empty but the
    static-track source_path resolution and finding discovery are
    unaffected (regression guard for the pre-FVVW-v3 behavior)."""
    db_subfolder = tmp_path / "db"
    joern_c = db_subfolder / "stage2" / "binaries" / "vulnbin" / "normalized" / "joern" / "whole.c"
    joern_c.parent.mkdir(parents=True)
    joern_c.write_text("int main() { return 0; }\n", encoding="utf-8")

    summary = _stage2_summary(
        rootfs_dir="", binaries=[_decompiled_binary("vulnbin", "bin/vulnbin")]
    )
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(exist_ok=True)
    (stage2_dir / "stage2_summary.json").write_text(
        summary.model_dump_json(), encoding="utf-8"
    )

    findings_dir = db_subfolder / "stage3" / "findings"
    findings_dir.mkdir(parents=True)
    report = AnalysisReport(chunk_id="vulnbin#0000", findings=[_finding()])
    (findings_dir / "vulnbin__0000.json").write_text(
        json.dumps(report.model_dump(mode="json")), encoding="utf-8"
    )

    candidates = discover_candidates(db_subfolder)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.source_path == joern_c.resolve()
    assert candidate.binary_path is None
    assert candidate.rootfs_dir is None
    assert candidate.elf is None
    assert candidate.functions == ()
