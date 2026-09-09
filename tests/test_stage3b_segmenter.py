"""Tests for `fw_audit.stage3b_claims.segmenter` — pure, zero-LLM claim-block
segmentation. Every test constructs a `DocumentText` directly rather than
going through `extractor.py` (which needs pdfplumber) — segmentation is
independently testable by design."""

from __future__ import annotations

from fw_audit.stage3b_claims.models import DocumentText, PageText, SegmenterConfig
from fw_audit.stage3b_claims.segmenter import segment


def _doc(*page_texts: str) -> DocumentText:
    pages = tuple(PageText(page_number=i + 1, text=t) for i, t in enumerate(page_texts))
    return DocumentText(doc_stem="doc", pages=pages, source_path=__file__)  # type: ignore[arg-type]


def test_empty_document_yields_no_blocks():
    assert segment(_doc()) == ()
    assert segment(_doc("")) == ()


def test_splits_on_cve_identifier():
    text = (
        "Intro paragraph with no vulnerability content whatsoever, padded to be long "
        "enough to survive the runt-block merge threshold used by this test suite here.\n"
        "CVE-2024-12345: Stack overflow in httpd\n"
        "Details about the overflow follow here and continue for a while to be realistic.\n"
    )
    blocks = segment(_doc(text), config=SegmenterConfig(min_block_chars=10))
    assert len(blocks) == 2
    assert "CVE-2024-12345" in blocks[1].text


def test_splits_on_cwe_identifier():
    text = (
        "Padding text that is long enough on its own to not be merged as a runt block.\n"
        "CWE-121: Stack-based Buffer Overflow\n"
        "More detail padding text goes here to keep this block above the runt threshold.\n"
    )
    blocks = segment(_doc(text), config=SegmenterConfig(min_block_chars=10))
    assert any("CWE-121" in b.text for b in blocks)


def test_splits_on_numbered_finding_heading():
    text = (
        "Padding text that is long enough on its own to not be merged as a runt block.\n"
        "Finding 3: Command Injection in formSetWanNonLogin\n"
        "The handler passes unsanitized input to system() without any validation at all.\n"
        "Finding 4: Hardcoded Credentials\n"
        "A hardcoded root password is present in the firmware image at a known offset.\n"
    )
    blocks = segment(_doc(text), config=SegmenterConfig(min_block_chars=10))
    assert len(blocks) == 3
    assert "Finding 3" in blocks[1].text
    assert "Finding 4" in blocks[2].text


def test_runt_blocks_are_merged_into_following_block():
    # A bare heading line immediately followed by another boundary line
    # should not become its own near-empty block.
    text = (
        "Padding text long enough to survive as its own block on this first pass here.\n"
        "Finding 1\n"
        "Finding 2: Buffer Overflow\n"
        "Real content that makes this block long enough to not be a runt any longer now.\n"
    )
    blocks = segment(_doc(text), config=SegmenterConfig(min_block_chars=20))
    # "Finding 1" alone is short — it should have merged forward into the
    # "Finding 2" block rather than surviving as its own block.
    assert not any(b.text.strip() == "Finding 1" for b in blocks)


def test_oversized_block_is_hard_split():
    paragraph = "Some evidence line that repeats.\n" * 50  # ~1700 chars
    text = f"CVE-2024-00001: A finding.\n\n{paragraph}\n\n{paragraph}"
    blocks = segment(_doc(text), config=SegmenterConfig(max_block_chars=1000, min_block_chars=10))
    assert all(len(b.text) <= 1000 or "\n\n" not in b.text for b in blocks)
    assert len(blocks) >= 2


def test_no_boundary_match_falls_back_to_fixed_size_runs():
    # Plain prose with none of the boundary patterns.
    text = "This is just prose. " * 200
    blocks = segment(_doc(text), config=SegmenterConfig(max_block_chars=500))
    assert len(blocks) >= 2
    assert all(len(b.text) <= 500 for b in blocks)


def test_page_numbers_are_tracked_per_block():
    text_p1 = "CVE-2024-00001: Finding on page one, padded long enough to survive merging.\n"
    text_p2 = "More detail continues on page two of the same finding write-up here now.\n"
    blocks = segment(_doc(text_p1, text_p2), config=SegmenterConfig(min_block_chars=5))
    all_pages = {p for b in blocks for p in b.page_numbers}
    assert 1 in all_pages
    assert 2 in all_pages


def test_extra_headings_config_is_honored():
    text = (
        "Padding text long enough to survive as its own block for this particular test.\n"
        "SECTION: Custom Boundary\n"
        "Body text that follows the custom heading and is reasonably long by itself here.\n"
    )
    cfg = SegmenterConfig(min_block_chars=10, extra_headings=("SECTION:",))
    blocks = segment(_doc(text), config=cfg)
    assert any(b.text.strip().startswith("SECTION:") for b in blocks)


def test_deterministic_same_input_same_output():
    text = "CVE-2024-00001: A\nBody text one.\nCVE-2024-00002: B\nBody text two padded out.\n"
    doc = _doc(text)
    assert segment(doc) == segment(doc)
