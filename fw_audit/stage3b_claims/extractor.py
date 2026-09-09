"""Deterministic, zero-LLM PDF text extraction.

`pdfplumber` is chosen over the lighter `pypdf` specifically for layout
fidelity: a vulnerability report's evidence is often a code listing or a
CVSS/severity table, and `pdfplumber`'s `extract_tables()` keeps that
row/column structure intact rather than flattening it into ambiguous
whitespace-separated text the way a pure `pypdf` text extraction would.
This is a one-time cost per document, not per claim, so the heavier
dependency (`pdfminer.six` + `Pillow`, pulled in transitively) is a
reasonable trade for a real accuracy gain on the input this package cares
about most.

`pdfplumber` is imported LAZILY, inside `extract_document()` — never at
module import time — so the unit suite never needs it installed. This
mirrors `stage4_rag`'s lazy `chromadb`/`sentence-transformers` imports and
`stage5_verification.fvvw.graph.resolve_checkpointer`'s lazy
`langgraph-checkpoint-sqlite` import: install `fw-audit[pdf]` only if you
actually run `fw-claims ingest`.
"""

from __future__ import annotations

import re
from pathlib import Path

from fw_audit.stage3b_claims.errors import Stage3bInputError
from fw_audit.stage3b_claims.models import DocumentText, PageText

_SAFE_STEM_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def doc_stem(pdf_path: Path) -> str:
    """Filesystem-safe stem for namespacing this document's artifacts —
    same sanitization spirit as `stage2_extraction.layout.bin_id`, just
    simpler since a PDF filename is already mostly filesystem-safe."""
    stem = pdf_path.stem.strip() or "report"
    return _SAFE_STEM_RE.sub("_", stem)


def _parse_pages_arg(pages: str | None, *, page_count: int) -> tuple[int, ...]:
    """Parse a `--pages` selector like `"4-19"` or `"1,3,5-8"` into a sorted
    tuple of 1-indexed page numbers, clamped to `[1, page_count]`. `None`
    means every page. Never raises on an out-of-range page — silently
    clamps, since a user-supplied page range is a convenience, not a
    contract other code depends on."""
    if pages is None:
        return tuple(range(1, page_count + 1))
    selected: set[int] = set()
    for part in pages.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, _, end_str = part.partition("-")
            try:
                start, end = int(start_str), int(end_str)
            except ValueError as exc:
                raise Stage3bInputError(f"Invalid --pages range {part!r}: {exc}") from exc
            for n in range(min(start, end), max(start, end) + 1):
                if 1 <= n <= page_count:
                    selected.add(n)
        else:
            try:
                n = int(part)
            except ValueError as exc:
                raise Stage3bInputError(f"Invalid --pages entry {part!r}: {exc}") from exc
            if 1 <= n <= page_count:
                selected.add(n)
    return tuple(sorted(selected))


def _render_table(rows: list[list[str | None]]) -> str:
    """Render one `pdfplumber` extracted table as pipe-delimited text —
    plain enough for the LLM to read as a table without needing markdown
    table syntax the model might over-interpret."""
    lines = []
    for row in rows:
        cells = [(cell or "").strip().replace("\n", " ") for cell in row]
        lines.append(" | ".join(cells))
    return "\n".join(lines)


def extract_document(pdf_path: Path, *, pages: str | None = None) -> DocumentText:
    """Extract per-page text (plus any tables, appended after the page's
    plain text) from `pdf_path`. Zero LLM calls, zero tokens spent.

    `pages` optionally restricts extraction to a subset (`"4-19"`,
    `"1,3,5-8"`) — useful to skip a report's boilerplate front matter/
    appendices before spending anything downstream.

    Raises `Stage3bInputError` if `pdfplumber` isn't installed (naming the
    `pip install "fw-audit[pdf]"` fix), the file doesn't exist, or it can't
    be parsed as a PDF.
    """
    if not pdf_path.is_file():
        raise Stage3bInputError(f"PDF not found: {pdf_path}")

    try:
        import pdfplumber
    except ImportError as exc:
        raise Stage3bInputError(
            "pdfplumber is not installed — PDF extraction needs it. "
            'Install with: pip install "fw-audit[pdf]"'
        ) from exc

    try:
        with pdfplumber.open(pdf_path) as pdf:
            page_count = len(pdf.pages)
            wanted = set(_parse_pages_arg(pages, page_count=page_count))
            page_texts: list[PageText] = []
            for i, page in enumerate(pdf.pages, start=1):
                if i not in wanted:
                    continue
                text = page.extract_text() or ""
                tables = page.extract_tables() or []
                if tables:
                    rendered = "\n\n".join(_render_table(t) for t in tables if t)
                    if rendered:
                        text = f"{text}\n\n[TABLE]\n{rendered}" if text else f"[TABLE]\n{rendered}"
                page_texts.append(PageText(page_number=i, text=text))
    except Stage3bInputError:
        raise
    except Exception as exc:  # pdfplumber raises assorted PDF-parsing errors
        raise Stage3bInputError(f"Could not parse PDF {pdf_path}: {exc}") from exc

    return DocumentText(
        doc_stem=doc_stem(pdf_path),
        pages=tuple(page_texts),
        source_path=pdf_path.resolve(),
    )
