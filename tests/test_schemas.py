"""Tests for the Stage 1 / Stage 2 hand-off contracts in common/schemas.py."""

from __future__ import annotations

from datetime import UTC, datetime

from fw_audit.common.schemas import (
    DecompilationStatus,
    DecompiledBinary,
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
