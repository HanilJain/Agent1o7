"""Tests for the Stage 1 / Stage 2 hand-off contracts in common/schemas.py."""

from __future__ import annotations

from datetime import UTC, datetime

from fw_audit.common.schemas import (
    DecompilationArtifacts,
    DecompilationStatus,
    DecompiledBinary,
    ExtractedFunction,
    ExtractedSource,
    ExtractionStatus,
    Stage1Summary,
    Stage2Summary,
)


def test_stage1_summary_accepts_current_status_value():
    summary = Stage1Summary(status="completed", db_subfolder="/data/db/fw")
    assert summary.status == "completed"


def test_stage1_summary_normalizes_enum_repr_status():
    """Older summaries serialize status as str(IngestionStatus.COMPLETED),
    i.e. "IngestionStatus.COMPLETED" — must normalize to "completed"."""
    summary = Stage1Summary(status="IngestionStatus.COMPLETED", db_subfolder="/data/db/fw")
    assert summary.status == "completed"


def test_stage1_summary_normalizes_failed_enum_repr():
    summary = Stage1Summary(status="IngestionStatus.FAILED", db_subfolder="/data/db/fw")
    assert summary.status == "failed"


def test_stage1_summary_rootfs_dir_defaults_to_none():
    summary = Stage1Summary(status="completed", db_subfolder="/data/db/fw")
    assert summary.rootfs_dir is None


def test_stage1_summary_round_trips_identified_binaries():
    raw = {
        "status": "completed",
        "db_subfolder": "/data/db/fw",
        "tree_txt_path": "/data/db/fw/tree.txt",
        "rootfs_dir": "/data/db/fw/binwalk_1/squashfs-root",
        "identified_binaries": [{"path": "bin/httpd"}],
    }
    summary = Stage1Summary.model_validate(raw)
    assert summary.identified_binaries[0].path == "bin/httpd"
    assert summary.rootfs_dir == "/data/db/fw/binwalk_1/squashfs-root"


def test_stage2_summary_round_trips():
    binary = DecompiledBinary(
        bin_id="bin_httpd__abc123def456",
        rootfs_path="bin/httpd",
        requested_path="bin/httpd",
        sha256="a" * 64,
        size_bytes=1024,
        status=DecompilationStatus.SUCCEEDED,
    )
    summary = Stage2Summary(
        run_id="run1",
        status=ExtractionStatus.COMPLETED,
        db_subfolder="/data/db/fw",
        rootfs_dir="/data/db/fw/binwalk_1/squashfs-root",
        stage2_dir="/data/db/fw/stage2",
        ghidra_image="fw-audit-ghidra:latest",
        binaries=[binary],
        started_at=datetime.now(UTC),
    )
    dumped = summary.model_dump(mode="json")
    restored = Stage2Summary.model_validate(dumped)
    assert restored.binaries[0].bin_id == "bin_httpd__abc123def456"
    assert restored.status == ExtractionStatus.COMPLETED


def test_decompiled_binary_round_trips_cleaned_artifact_fields():
    binary = DecompiledBinary(
        bin_id="bin_httpd__abc123def456",
        rootfs_path="bin/httpd",
        requested_path="bin/httpd",
        sha256="a" * 64,
        size_bytes=1024,
        status=DecompilationStatus.SUCCEEDED,
        cleaned_function_count=12,
        dropped_line_count=340,
        artifacts=DecompilationArtifacts(
            cleaned_c="stage2/binaries/bin_httpd__abc123def456/cleaned/whole.c",
            cleaned_index_json="stage2/binaries/bin_httpd__abc123def456/cleaned/functions.json",
        ),
    )
    restored = DecompiledBinary.model_validate(binary.model_dump(mode="json"))

    assert restored.cleaned_function_count == 12
    assert restored.dropped_line_count == 340
    assert restored.artifacts.cleaned_c == binary.artifacts.cleaned_c
    assert restored.artifacts.cleaned_index_json == binary.artifacts.cleaned_index_json


def test_decompiled_binary_cleaned_fields_default_to_zero_and_none():
    """An old summary written before cleaning existed — additive fields
    only, `schema_version` stays 1 (same precedent as `decompiled_tree_dir`)."""
    binary = DecompiledBinary(
        bin_id="bin_httpd__abc123def456",
        rootfs_path="bin/httpd",
        requested_path="bin/httpd",
        sha256="a" * 64,
        size_bytes=1024,
        status=DecompilationStatus.SUCCEEDED,
    )
    assert binary.cleaned_function_count == 0
    assert binary.dropped_line_count == 0
    assert binary.artifacts.cleaned_c is None
    assert binary.artifacts.cleaned_index_json is None


def test_extracted_source_round_trips_and_to_text():
    source = ExtractedSource(
        bin_id="bin_httpd",
        functions=(
            ExtractedFunction(name="a", start_line=1, end_line=3, text="int a(void)\n{\n}"),
            ExtractedFunction(name="b", start_line=5, end_line=7, text="int b(void)\n{\n}"),
        ),
        total_lines=10,
        dropped_line_count=4,
    )
    restored = ExtractedSource.model_validate(source.model_dump(mode="json"))

    assert restored.to_text() == source.to_text()
    assert [f.name for f in restored.functions] == ["a", "b"]
    assert restored.dropped_line_count == 4
