"""Tests for `fw_audit.stage3b_claims.extractor`.

`pdfplumber` is injected as a fake module via `sys.modules` for the unit
tests below — the unit suite never needs the real dependency installed
(confirmed: `import pdfplumber` fails in this environment), exercising the
lazy-import contract `extractor.extract_document` promises. A real-PDF
test is marked `integration` and skipped when no sample PDF is available.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from fw_audit.stage3b_claims.errors import Stage3bInputError
from fw_audit.stage3b_claims.extractor import doc_stem, extract_document


def test_doc_stem_sanitizes_filename():
    assert doc_stem(Path("ACME Pentest 2026.pdf")) == "ACME_Pentest_2026"


def test_doc_stem_handles_already_safe_name():
    assert doc_stem(Path("acme_report_v2.pdf")) == "acme_report_v2"


def test_extract_document_missing_file_raises(tmp_path):
    with pytest.raises(Stage3bInputError, match="not found"):
        extract_document(tmp_path / "nope.pdf")


def test_extract_document_missing_pdfplumber_raises(tmp_path, monkeypatch):
    # Ensure pdfplumber is NOT importable for this test regardless of the
    # real environment.
    monkeypatch.setitem(sys.modules, "pdfplumber", None)
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")
    with pytest.raises(Stage3bInputError, match="pip install"):
        extract_document(pdf_path)


class _FakePage:
    def __init__(self, text: str, tables: list | None = None):
        self._text = text
        self._tables = tables or []

    def extract_text(self):
        return self._text

    def extract_tables(self):
        return self._tables


class _FakePdf:
    def __init__(self, pages: list[_FakePage]):
        self.pages = pages

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _install_fake_pdfplumber(monkeypatch, pages: list[_FakePage]) -> None:
    fake_module = types.ModuleType("pdfplumber")
    fake_module.open = lambda path: _FakePdf(pages)
    monkeypatch.setitem(sys.modules, "pdfplumber", fake_module)


def test_extract_document_returns_page_text(tmp_path, monkeypatch):
    _install_fake_pdfplumber(monkeypatch, [_FakePage("Page one text"), _FakePage("Page two text")])
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")

    document = extract_document(pdf_path)
    assert document.doc_stem == "report"
    assert len(document.pages) == 2
    assert document.pages[0].page_number == 1
    assert document.pages[0].text == "Page one text"
    assert document.pages[1].text == "Page two text"


def test_extract_document_appends_table_text(tmp_path, monkeypatch):
    table = [["Severity", "CVE"], ["Critical", "CVE-2024-1"]]
    _install_fake_pdfplumber(monkeypatch, [_FakePage("Intro", tables=[table])])
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")

    document = extract_document(pdf_path)
    assert "Intro" in document.pages[0].text
    assert "Severity" in document.pages[0].text
    assert "CVE-2024-1" in document.pages[0].text


def test_extract_document_pages_filter(tmp_path, monkeypatch):
    _install_fake_pdfplumber(
        monkeypatch, [_FakePage("p1"), _FakePage("p2"), _FakePage("p3"), _FakePage("p4")]
    )
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")

    document = extract_document(pdf_path, pages="2-3")
    assert [p.page_number for p in document.pages] == [2, 3]


def test_extract_document_pages_filter_comma_list(tmp_path, monkeypatch):
    _install_fake_pdfplumber(
        monkeypatch, [_FakePage("p1"), _FakePage("p2"), _FakePage("p3"), _FakePage("p4")]
    )
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")

    document = extract_document(pdf_path, pages="1,3")
    assert [p.page_number for p in document.pages] == [1, 3]


def test_extract_document_invalid_pages_range_raises(tmp_path, monkeypatch):
    _install_fake_pdfplumber(monkeypatch, [_FakePage("p1")])
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")

    with pytest.raises(Stage3bInputError):
        extract_document(pdf_path, pages="not-a-range")


def test_extract_document_parse_error_wrapped(tmp_path, monkeypatch):
    fake_module = types.ModuleType("pdfplumber")

    def _raise(path):
        raise RuntimeError("corrupt PDF")

    fake_module.open = _raise
    monkeypatch.setitem(sys.modules, "pdfplumber", fake_module)
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4 fake")

    with pytest.raises(Stage3bInputError, match="Could not parse"):
        extract_document(pdf_path)


@pytest.mark.integration
def test_extract_document_real_pdf():
    pytest.importorskip("pdfplumber")
    sample = Path(__file__).parent / "fixtures" / "sample_report.pdf"
    if not sample.is_file():
        pytest.skip("no sample_report.pdf fixture available")
    document = extract_document(sample)
    assert document.pages
