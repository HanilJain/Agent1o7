"""Tests for the `fw-claims` CLI (fw_audit.stage3b_claims.runner)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from fw_audit.common.claims import ClaimsRunSummary
from fw_audit.stage3b_claims.driver import ExtractorModelUnavailableError
from fw_audit.stage3b_claims.runner import _parse_args, main


def test_parse_args_ingest_requires_db_subfolder():
    with pytest.raises(SystemExit):
        _parse_args(["ingest", "report.pdf"])


def test_parse_args_ingest_minimal():
    args = _parse_args(["ingest", "report.pdf", "--db-subfolder", "data/db/fw"])
    assert args.command == "ingest"
    assert args.pdf_path == "report.pdf"
    assert args.db_subfolder == "data/db/fw"
    assert args.model is None
    assert args.pages is None
    assert args.debug is False


def test_parse_args_ingest_full():
    args = _parse_args(
        [
            "ingest",
            "report.pdf",
            "--db-subfolder",
            "data/db/fw",
            "--model",
            "ollama:kimi-k3",
            "--pages",
            "4-19",
            "--run-id",
            "abc123",
            "--debug",
        ]
    )
    assert args.model == "ollama:kimi-k3"
    assert args.pages == "4-19"
    assert args.run_id == "abc123"
    assert args.debug is True


def test_parse_args_debug_extract():
    args = _parse_args(["debug", "extract", "report.pdf", "--pages", "1-3"])
    assert args.command == "debug"
    assert args.debug_command == "extract"
    assert args.pdf_path == "report.pdf"
    assert args.pages == "1-3"


def test_parse_args_debug_segment():
    args = _parse_args(["debug", "segment", "report.pdf", "--max-block-chars", "5000"])
    assert args.debug_command == "segment"
    assert args.max_block_chars == 5000


def test_parse_args_debug_resolve():
    args = _parse_args(
        [
            "debug",
            "resolve",
            "--db-subfolder",
            "data/db/fw",
            "--binary",
            "httpd",
            "--function",
            "formSetWanNonLogin",
        ]
    )
    assert args.debug_command == "resolve"
    assert args.binary_hint == "httpd"
    assert args.function_hint == "formSetWanNonLogin"


def test_main_ingest_missing_pdf_returns_2(tmp_path, capsys):
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()
    rc = main(["ingest", str(tmp_path / "nope.pdf"), "--db-subfolder", str(db_subfolder)])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_main_ingest_missing_db_subfolder_returns_2(tmp_path, capsys):
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")
    rc = main(["ingest", str(pdf_path), "--db-subfolder", str(tmp_path / "nope")])
    assert rc == 2
    assert "--db-subfolder" in capsys.readouterr().err


def test_main_ingest_extractor_unavailable_returns_2(tmp_path, monkeypatch, capsys):
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()

    async def _raise(*args, **kwargs):
        raise ExtractorModelUnavailableError("no credential")

    monkeypatch.setattr("fw_audit.stage3b_claims.runner.ingest_report", _raise)
    rc = main(["ingest", str(pdf_path), "--db-subfolder", str(db_subfolder)])
    assert rc == 2
    assert "extractor model unavailable" in capsys.readouterr().err


def test_main_ingest_success_prints_summary(tmp_path, monkeypatch, capsys):
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")
    db_subfolder = tmp_path / "db"
    db_subfolder.mkdir()

    async def _fake_ingest(pdf_path, *, db_subfolder, settings, run_id, pages, write_debug_blocks):
        return ClaimsRunSummary(
            status="completed",
            db_subfolder=str(db_subfolder),
            source_pdf=str(pdf_path),
            doc_stem="report",
            model="ollama:kimi-k3",
            page_count=5,
            block_count=3,
            total_claims=2,
            total_emitted=2,
            total_failed=0,
            total_unresolved_binary=1,
            started_at=datetime.now(UTC),
        )

    monkeypatch.setattr("fw_audit.stage3b_claims.runner.ingest_report", _fake_ingest)
    rc = main(["ingest", str(pdf_path), "--db-subfolder", str(db_subfolder)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "report" in out
    assert "2 total, 2 emitted" in out


def test_main_debug_extract_zero_tokens(tmp_path, monkeypatch, capsys):
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")

    from fw_audit.stage3b_claims.models import DocumentText, PageText

    def _fake_debug_extract(pdf_path, *, pages=None):
        return DocumentText(
            doc_stem="report", pages=(PageText(page_number=1, text="hello"),), source_path=pdf_path
        )

    monkeypatch.setattr("fw_audit.stage3b_claims.runner.debug_extract", _fake_debug_extract)
    rc = main(["debug", "extract", str(pdf_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "hello" in out


def test_main_debug_segment_reports_cost_estimate(tmp_path, monkeypatch, capsys):
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")

    from fw_audit.stage3b_claims.debug import BlockSummary

    def _fake_debug_segment(pdf_path, *, pages=None, max_block_chars=12000):
        return (
            BlockSummary(block_id="block_0000", page_numbers=(1,), chars=120, preview="preview"),
        )

    monkeypatch.setattr("fw_audit.stage3b_claims.runner.debug_segment", _fake_debug_segment)
    rc = main(["debug", "segment", str(pdf_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "blocks: 1" in out
    assert "total_chars: 120" in out


def test_main_debug_resolve(tmp_path, monkeypatch, capsys):
    from fw_audit.stage3b_claims.debug import ResolveResult

    def _fake_debug_resolve(*, db_subfolder, binary_hint, function_hint):
        return ResolveResult(
            binary_hint=binary_hint,
            function_hint=function_hint,
            bin_id="b1",
            binary_matched_on="basename",
            function_name="fn",
            function_matched_on="exact",
        )

    monkeypatch.setattr("fw_audit.stage3b_claims.runner.debug_resolve", _fake_debug_resolve)
    rc = main(
        [
            "debug",
            "resolve",
            "--db-subfolder",
            str(tmp_path),
            "--binary",
            "httpd",
            "--function",
            "fn",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "bin_id='b1'" in out
