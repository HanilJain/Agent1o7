"""The contract test that matters: proves Stage 3b-emitted findings are
readable, unchanged, by the REAL Stage 4 (`sink_index.discover_sink_candidates`)
and Stage 5 (`candidate_index.discover_candidates`) discovery logic — not
just that `emit.py`'s output round-trips through `AnalysisReport` in
isolation (see `test_stage3b_emit.py` for that).

No mocking of Stage 4/5 code at all: this writes real emitted claim files
into a real `stage3b/findings/` directory (via `emit.to_analysis_report`,
the actual production code path) and calls the actual, unmodified
downstream discovery functions with `findings_dir=` pointed at it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fw_audit.common.claims import ClaimExtraction
from fw_audit.common.findings import Decision
from fw_audit.common.schemas import (
    DecompilationArtifacts,
    DecompilationStatus,
    DecompiledBinary,
    ExtractionStatus,
    GhidraFunction,
    Stage2Summary,
)
from fw_audit.stage3b_claims import layout
from fw_audit.stage3b_claims.emit import to_analysis_report, to_emitted_claim
from fw_audit.stage3b_claims.models import BinaryResolution, FunctionResolution
from fw_audit.stage4_rag.sink_index import discover_sink_candidates
from fw_audit.stage5_verification.candidate_index import discover_candidates


def _write_claim_finding(
    db_subfolder: Path,
    *,
    claim_id: str,
    bin_id_resolution: BinaryResolution,
    function_resolution: FunctionResolution,
    ordinal: int,
    binary_hint: str = "httpd",
) -> str:
    """Runs the REAL emit.py production path and writes the result to
    stage3b/findings/ exactly as driver.py does. Returns the resulting
    global_id."""
    claim = ClaimExtraction(
        claim_id=claim_id,
        title="Stack overflow claim",
        category="memory_safety",
        binary_hint=binary_hint,
        function_hint="formSetWanNonLogin",
        security_condition="unchecked strcpy",
        evidence_quote="strcpy(buf, x);",
        page_numbers=[3],
    )
    report = to_analysis_report(
        claim,
        doc_stem="acme_report",
        ordinal=ordinal,
        binary_resolution=bin_id_resolution,
        function_resolution=function_resolution,
    )
    emitted = to_emitted_claim(
        report,
        global_id=f"{report.chunk_id}::{claim.claim_id}",
        bin_id=report.chunk_id.rpartition("#")[0],
        binary_resolved=bin_id_resolution.bin_id is not None,
    )
    stage3b_dir_ = layout.stage3b_dir(db_subfolder)
    findings_dir_ = layout.findings_dir(stage3b_dir_)
    findings_dir_.mkdir(parents=True, exist_ok=True)
    target = findings_dir_ / layout.finding_filename(emitted.chunk_id)
    target.write_text(emitted.report_json, encoding="utf-8")
    return emitted.global_id


def _write_stage2_summary(db_subfolder: Path, *, bin_id: str, rootfs_path: str) -> None:
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True, exist_ok=True)
    binary = DecompiledBinary(
        bin_id=bin_id,
        rootfs_path=rootfs_path,
        requested_path=f"/{rootfs_path}",
        sha256="a" * 64,
        size_bytes=100,
        status=DecompilationStatus.SUCCEEDED,
        artifacts=DecompilationArtifacts(normalized_joern_c=f"stage2/binaries/{bin_id}/normalized/joern/whole.c"),
        functions=[
            GhidraFunction(
                name="formSetWanNonLogin", entry_point="0x1000", size=10, signature="void f()"
            )
        ],
    )
    summary = Stage2Summary(
        run_id="r1",
        status=ExtractionStatus.COMPLETED,
        db_subfolder=str(db_subfolder),
        rootfs_dir="rootfs",
        stage2_dir=str(stage2_dir),
        ghidra_image="fw-audit-ghidra:latest",
        binaries=[binary],
        started_at=datetime.now(UTC),
    )
    (stage2_dir / "stage2_summary.json").write_text(
        summary.model_dump_json(indent=2), encoding="utf-8"
    )
    joern_c_path = db_subfolder / f"stage2/binaries/{bin_id}/normalized/joern/whole.c"
    joern_c_path.parent.mkdir(parents=True, exist_ok=True)
    joern_c_path.write_text("int main() { return 0; }\n", encoding="utf-8")


def test_stage4_discovers_resolved_claim_via_findings_dir_override(tmp_path):
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    bin_id = "usr_sbin_httpd__a1b2c3"
    global_id = _write_claim_finding(
        db_subfolder,
        claim_id="claim_001",
        bin_id_resolution=BinaryResolution(bin_id=bin_id, matched_on="basename"),
        function_resolution=FunctionResolution(
            function_name="formSetWanNonLogin", matched_on="exact"
        ),
        ordinal=0,
    )

    # Stage 3's own findings dir is empty/absent — must not affect this.
    stage3b_findings_dir = layout.findings_dir(layout.stage3b_dir(db_subfolder))
    candidates = discover_sink_candidates(
        db_subfolder / "stage3",
        decisions=frozenset({Decision.ESCALATE, Decision.CONTEXT_REQUIRED}),
        findings_dir=stage3b_findings_dir,
    )

    assert len(candidates) == 1
    assert candidates[0].global_id == global_id
    assert candidates[0].bin_id == bin_id
    assert candidates[0].finding.finding_id == "claim_001"


def test_stage4_default_behavior_unaffected_when_findings_dir_omitted(tmp_path):
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    _write_claim_finding(
        db_subfolder,
        claim_id="claim_001",
        bin_id_resolution=BinaryResolution(bin_id="b1", matched_on="basename"),
        function_resolution=FunctionResolution(function_name="fn", matched_on="exact"),
        ordinal=0,
    )
    # Default call (no findings_dir) must find NOTHING — stage3b claims
    # must never leak into Stage 3's own discovery by default.
    candidates = discover_sink_candidates(db_subfolder / "stage3")
    assert candidates == []


def test_stage5_discovers_resolved_claim_and_resolves_source_path(tmp_path):
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    bin_id = "usr_sbin_httpd__a1b2c3"
    _write_stage2_summary(db_subfolder, bin_id=bin_id, rootfs_path="usr/sbin/httpd")

    global_id = _write_claim_finding(
        db_subfolder,
        claim_id="claim_001",
        bin_id_resolution=BinaryResolution(bin_id=bin_id, matched_on="basename"),
        function_resolution=FunctionResolution(
            function_name="formSetWanNonLogin", matched_on="exact"
        ),
        ordinal=0,
    )

    stage3b_findings_dir = layout.findings_dir(layout.stage3b_dir(db_subfolder))
    candidates = discover_candidates(db_subfolder, findings_dir=stage3b_findings_dir)

    assert len(candidates) == 1
    assert candidates[0].global_id == global_id
    assert candidates[0].source_path is not None
    assert candidates[0].source_path.is_file()


def test_stage5_unresolved_claim_gets_context_required_and_is_excluded_by_default(tmp_path):
    """ESCALATE-only default (Stage 5's DEFAULT_DECISIONS) must exclude an
    unresolved claim — this is the whole point of the CONTEXT_REQUIRED
    disposition (see emit.py's docstring): it protects
    characterize_target's hard failure from ever being reached."""
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    _write_stage2_summary(db_subfolder, bin_id="b1", rootfs_path="sbin/httpd")

    _write_claim_finding(
        db_subfolder,
        claim_id="claim_001",
        bin_id_resolution=BinaryResolution(bin_id=None),
        function_resolution=FunctionResolution(function_name=None),
        ordinal=0,
        binary_hint="totally_unknown_binary",
    )

    stage3b_findings_dir = layout.findings_dir(layout.stage3b_dir(db_subfolder))
    # Default decisions (ESCALATE only) — the unresolved claim must NOT appear.
    candidates = discover_candidates(db_subfolder, findings_dir=stage3b_findings_dir)
    assert candidates == []

    # Widening to CONTEXT_REQUIRED surfaces it.
    from fw_audit.common.findings import Decision

    candidates_widened = discover_candidates(
        db_subfolder,
        decisions=frozenset({Decision.CONTEXT_REQUIRED}),
        findings_dir=stage3b_findings_dir,
    )
    assert len(candidates_widened) == 1
    assert candidates_widened[0].finding.decision == Decision.CONTEXT_REQUIRED


def test_stage5_default_behavior_unaffected_when_findings_dir_omitted(tmp_path):
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    _write_stage2_summary(db_subfolder, bin_id="b1", rootfs_path="sbin/httpd")
    _write_claim_finding(
        db_subfolder,
        claim_id="claim_001",
        bin_id_resolution=BinaryResolution(bin_id="b1", matched_on="basename"),
        function_resolution=FunctionResolution(
            function_name="formSetWanNonLogin", matched_on="exact"
        ),
        ordinal=0,
    )
    # Default call — must find NOTHING, since Stage 3's own findings dir
    # doesn't exist.
    candidates = discover_candidates(db_subfolder)
    assert candidates == []


def test_multiple_claims_from_same_binary_all_discovered(tmp_path):
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    bin_id = "b1"
    _write_stage2_summary(db_subfolder, bin_id=bin_id, rootfs_path="sbin/httpd")

    global_ids = set()
    for i in range(3):
        gid = _write_claim_finding(
            db_subfolder,
            claim_id=f"claim_{i:03d}",
            bin_id_resolution=BinaryResolution(bin_id=bin_id, matched_on="basename"),
            function_resolution=FunctionResolution(
            function_name="formSetWanNonLogin", matched_on="exact"
        ),
            ordinal=i,
        )
        global_ids.add(gid)

    stage3b_findings_dir = layout.findings_dir(layout.stage3b_dir(db_subfolder))
    candidates = discover_candidates(db_subfolder, findings_dir=stage3b_findings_dir)
    assert {c.global_id for c in candidates} == global_ids
    assert len(candidates) == 3
