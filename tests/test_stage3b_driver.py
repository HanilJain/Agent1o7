"""Tests for `fw_audit.stage3b_claims.driver.ingest_report` — the
extractor LLM (`extract_claims`) and model resolution (`resolve_usable_spec`)
are faked; PDF extraction is bypassed by pre-seeding the page-text cache
so `pdfplumber` is never needed."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fw_audit.common.claims import ClaimExtractionBatch
from fw_audit.common.findings import AnalysisReport
from fw_audit.common.schemas import (
    DecompilationArtifacts,
    DecompilationStatus,
    DecompiledBinary,
    ExtractionStatus,
    Stage2Summary,
)
from fw_audit.config.llm_config import ModelProvider, ModelSpec
from fw_audit.config.settings import Settings
from fw_audit.stage3b_claims import layout
from fw_audit.stage3b_claims.driver import ExtractorModelUnavailableError, ingest_report
from fw_audit.stage3b_claims.errors import ClaimExtractionUnavailableError


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def _seed_pdf_and_cache(tmp_path: Path, *, text: str, doc_stem: str = "report") -> Path:
    """Create a placeholder PDF file (never actually parsed — the page
    cache is pre-seeded so extract_document is never called) plus its
    cache file directly, mirroring what a real extraction would have
    written."""
    pdf_path = tmp_path / f"{doc_stem}.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 placeholder")
    return pdf_path


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
        artifacts=DecompilationArtifacts(),
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


def _patch_resolve_usable_spec(monkeypatch) -> None:
    monkeypatch.setattr(
        "fw_audit.stage3b_claims.driver.resolve_usable_spec",
        lambda role, settings=None: ModelSpec(provider=ModelProvider.OLLAMA, model="kimi-k3"),
    )


def _patch_extract_document(monkeypatch, *, page_texts: list[str]) -> None:
    from fw_audit.stage3b_claims.models import DocumentText, PageText

    def _fake_extract(pdf_path, *, pages=None):
        pages_tuple = tuple(PageText(page_number=i + 1, text=t) for i, t in enumerate(page_texts))
        return DocumentText(doc_stem="report", pages=pages_tuple, source_path=pdf_path)

    monkeypatch.setattr("fw_audit.stage3b_claims.driver.extract_document", _fake_extract)


async def test_ingest_report_raises_when_extractor_model_unavailable(tmp_path, monkeypatch):
    def _raise(role, settings=None):
        raise ValueError("no usable credential")

    monkeypatch.setattr("fw_audit.stage3b_claims.driver.resolve_usable_spec", _raise)
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    pdf_path = _seed_pdf_and_cache(tmp_path, text="CVE-2024-1")

    with pytest.raises(ExtractorModelUnavailableError):
        await ingest_report(pdf_path, db_subfolder=db_subfolder, settings=_settings())


async def test_ingest_report_no_claims_status_when_document_empty(tmp_path, monkeypatch):
    _patch_resolve_usable_spec(monkeypatch)
    _patch_extract_document(monkeypatch, page_texts=[""])
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    pdf_path = _seed_pdf_and_cache(tmp_path, text="")

    summary = await ingest_report(pdf_path, db_subfolder=db_subfolder, settings=_settings())
    assert summary.status == "no_claims"
    assert summary.block_count == 0


async def test_ingest_report_writes_summary_best_effort(tmp_path, monkeypatch):
    _patch_resolve_usable_spec(monkeypatch)
    _patch_extract_document(monkeypatch, page_texts=[""])
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    pdf_path = _seed_pdf_and_cache(tmp_path, text="")

    await ingest_report(pdf_path, db_subfolder=db_subfolder, settings=_settings())
    summary_path = layout.claims_summary_path(layout.stage3b_dir(db_subfolder))
    assert summary_path.is_file()


async def test_ingest_report_emits_findings_for_resolved_claim(tmp_path, monkeypatch):
    _patch_resolve_usable_spec(monkeypatch)
    _patch_extract_document(
        monkeypatch,
        page_texts=["CVE-2024-12345: Stack overflow in httpd's formSetWanNonLogin handler."],
    )

    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    bin_id = "usr_sbin_httpd__a1b2c3"
    _write_stage2_summary(db_subfolder, bin_id=bin_id, rootfs_path="usr/sbin/httpd")

    async def _fake_extract_claims(block, *, doc_stem, settings):
        from fw_audit.common.claims import ClaimExtraction

        claim = ClaimExtraction(
            claim_id="claim_001",
            title="Stack overflow",
            category="memory_safety",
            binary_hint="httpd",
            function_hint="",
            security_condition="unchecked copy",
            page_numbers=[1],
        )
        return ClaimExtractionBatch(claims=[claim])

    monkeypatch.setattr("fw_audit.stage3b_claims.driver.extract_claims", _fake_extract_claims)

    summary = await ingest_report(
        pdf_path=_seed_pdf_and_cache(tmp_path, text=""),
        db_subfolder=db_subfolder,
        settings=_settings(),
    )

    assert summary.status == "completed"
    assert summary.total_claims == 1
    assert summary.total_emitted == 1
    assert summary.total_failed == 0

    findings_dir = layout.findings_dir(layout.stage3b_dir(db_subfolder))
    files = list(findings_dir.glob("*.json"))
    assert len(files) == 1
    report = AnalysisReport.model_validate_json(files[0].read_text(encoding="utf-8"))
    assert report.findings[0].finding_id == "claim_001"
    assert report.chunk_id.rpartition("#")[0] == bin_id


async def test_ingest_report_records_failed_claim_on_extraction_error(tmp_path, monkeypatch):
    _patch_resolve_usable_spec(monkeypatch)
    _patch_extract_document(monkeypatch, page_texts=["CVE-2024-1: something happened here"])
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()

    async def _fake_extract_claims(block, *, doc_stem, settings):
        raise ClaimExtractionUnavailableError("boom")

    monkeypatch.setattr("fw_audit.stage3b_claims.driver.extract_claims", _fake_extract_claims)

    summary = await ingest_report(
        pdf_path=_seed_pdf_and_cache(tmp_path, text=""),
        db_subfolder=db_subfolder,
        settings=_settings(),
    )
    assert summary.total_failed >= 1
    assert summary.status == "completed"


async def test_ingest_report_works_without_stage2_summary(tmp_path, monkeypatch):
    """No stage2_summary.json at all — binary resolution should come back
    empty for every claim (CONTEXT_REQUIRED), never raise."""
    _patch_resolve_usable_spec(monkeypatch)
    _patch_extract_document(monkeypatch, page_texts=["CVE-2024-1: unresolved binary case"])
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()

    async def _fake_extract_claims(block, *, doc_stem, settings):
        from fw_audit.common.claims import ClaimExtraction

        claim = ClaimExtraction(
            claim_id="claim_001",
            title="t",
            category="c",
            binary_hint="unknown_binary",
            security_condition="sc",
        )
        return ClaimExtractionBatch(claims=[claim])

    monkeypatch.setattr("fw_audit.stage3b_claims.driver.extract_claims", _fake_extract_claims)

    summary = await ingest_report(
        pdf_path=_seed_pdf_and_cache(tmp_path, text=""),
        db_subfolder=db_subfolder,
        settings=_settings(),
    )
    assert summary.total_emitted == 1
    assert summary.total_unresolved_binary == 1


async def test_ingest_report_page_cache_written_and_reused(tmp_path, monkeypatch):
    _patch_resolve_usable_spec(monkeypatch)
    call_count = {"n": 0}

    from fw_audit.stage3b_claims.models import DocumentText, PageText

    def _fake_extract(pdf_path, *, pages=None):
        call_count["n"] += 1
        return DocumentText(
            doc_stem="report",
            pages=(PageText(page_number=1, text=""),),
            source_path=pdf_path,
        )

    monkeypatch.setattr("fw_audit.stage3b_claims.driver.extract_document", _fake_extract)

    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    pdf_path = _seed_pdf_and_cache(tmp_path, text="")

    await ingest_report(pdf_path, db_subfolder=db_subfolder, settings=_settings())
    assert call_count["n"] == 1
    cache_path = layout.pages_cache_path(
        layout.source_dir(layout.stage3b_dir(db_subfolder)), "report"
    )
    assert cache_path.is_file()

    # Second run should use the cache, not call extract_document again.
    await ingest_report(pdf_path, db_subfolder=db_subfolder, settings=_settings())
    assert call_count["n"] == 1


async def test_ingest_report_debug_blocks_written_when_requested(tmp_path, monkeypatch):
    _patch_resolve_usable_spec(monkeypatch)
    _patch_extract_document(
        monkeypatch, page_texts=["CVE-2024-1: something reasonably long to segment properly"]
    )
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()

    async def _fake_extract_claims(block, *, doc_stem, settings):
        return ClaimExtractionBatch(claims=[], not_a_finding=True)

    monkeypatch.setattr("fw_audit.stage3b_claims.driver.extract_claims", _fake_extract_claims)

    await ingest_report(
        pdf_path=_seed_pdf_and_cache(tmp_path, text=""),
        db_subfolder=db_subfolder,
        settings=_settings(),
        write_debug_blocks=True,
    )
    debug_path = layout.blocks_debug_path(
        layout.debug_dir(layout.stage3b_dir(db_subfolder)), "report"
    )
    assert debug_path.is_file()
    payload = json.loads(debug_path.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert len(payload) >= 1
