"""Tests for `fw_audit.stage3b_claims.debug` — all zero-token, dry-run
inspection functions."""

from __future__ import annotations

import sys
import types
from datetime import UTC, datetime

import pytest

from fw_audit.common.schemas import (
    DecompilationArtifacts,
    DecompilationStatus,
    DecompiledBinary,
    ExtractionStatus,
    GhidraFunction,
    Stage2Summary,
)
from fw_audit.stage3b_claims.debug import debug_extract, debug_resolve, debug_segment
from fw_audit.stage3b_claims.errors import Stage3bInputError


class _FakePage:
    def __init__(self, text: str):
        self._text = text

    def extract_text(self):
        return self._text

    def extract_tables(self):
        return []


class _FakePdf:
    def __init__(self, pages):
        self.pages = pages

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _install_fake_pdfplumber(monkeypatch, texts: list[str]) -> None:
    fake_module = types.ModuleType("pdfplumber")
    fake_module.open = lambda path: _FakePdf([_FakePage(t) for t in texts])
    monkeypatch.setitem(sys.modules, "pdfplumber", fake_module)


def test_debug_extract_zero_tokens_returns_document(tmp_path, monkeypatch):
    _install_fake_pdfplumber(monkeypatch, ["Some page text"])
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")

    document = debug_extract(pdf_path)
    assert document.pages[0].text == "Some page text"


def test_debug_extract_missing_file_raises(tmp_path):
    with pytest.raises(Stage3bInputError):
        debug_extract(tmp_path / "nope.pdf")


def test_debug_segment_reports_block_sizes(tmp_path, monkeypatch):
    text = "CVE-2024-1: A finding with enough detail padded out to survive merging here.\n"
    _install_fake_pdfplumber(monkeypatch, [text])
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")

    blocks = debug_segment(pdf_path, max_block_chars=5000)
    assert len(blocks) >= 1
    assert all(b.chars > 0 for b in blocks)
    assert all(isinstance(b.preview, str) for b in blocks)


def test_debug_resolve_no_stage2_summary(tmp_path):
    result = debug_resolve(db_subfolder=tmp_path, binary_hint="httpd", function_hint="foo")
    assert result.bin_id is None
    assert "no usable stage2_summary.json" in result.binary_matched_on


def test_debug_resolve_with_stage2_summary(tmp_path):
    stage2_dir = tmp_path / "stage2"
    stage2_dir.mkdir(parents=True)
    binary = DecompiledBinary(
        bin_id="b1",
        rootfs_path="sbin/httpd",
        requested_path="/sbin/httpd",
        sha256="a" * 64,
        size_bytes=100,
        status=DecompilationStatus.SUCCEEDED,
        artifacts=DecompilationArtifacts(),
        functions=[
            GhidraFunction(
                name="formSetWanNonLogin", entry_point="0x1000", size=10, signature="void f()"
            )
        ],
    )
    summary = Stage2Summary(
        run_id="r1",
        status=ExtractionStatus.COMPLETED,
        db_subfolder=str(tmp_path),
        rootfs_dir="rootfs",
        stage2_dir=str(stage2_dir),
        ghidra_image="fw-audit-ghidra:latest",
        binaries=[binary],
        started_at=datetime.now(UTC),
    )
    (stage2_dir / "stage2_summary.json").write_text(
        summary.model_dump_json(indent=2), encoding="utf-8"
    )

    result = debug_resolve(
        db_subfolder=tmp_path, binary_hint="httpd", function_hint="formSetWanNonLogin"
    )
    assert result.bin_id == "b1"
    assert result.function_name == "formSetWanNonLogin"
