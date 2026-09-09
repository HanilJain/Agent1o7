"""Deterministic, zero-LLM claim-block segmentation.

This is the main token-control lever in the whole package: the LLM never
sees a full report, only one block at a time (`agent/converter.py`), so the
number and size of blocks `segment()` produces is directly proportional to
the run's token bill. `fw-claims debug segment` prints block count and
per-block character counts precisely so that cost can be estimated before
spending anything.

Splits on signals that reliably mark the start of a new claim in a
vulnerability report: CVE identifiers, `CWE-\\d+` mentions, numbered-finding
headings ("Finding 3", "3.2 Stack Overflow in ..."), and severity-table
rows. Runt blocks (shorter than `min_block_chars`) are merged into their
neighbor rather than sent to the LLM on their own — a lone heading line
with no body wastes a full LLM call for nothing. Blocks longer than
`max_block_chars` are hard-split at the nearest paragraph boundary, so a
single long finding write-up doesn't balloon one call's token cost.

If nothing matches (a report that doesn't follow any of these conventions),
falls back to one block per `max_block_chars`-sized run of pages — every
report still gets *some* coverage, just without claim-aware boundaries.
"""

from __future__ import annotations

import re

from fw_audit.stage3b_claims.models import ClaimBlock, DocumentText, SegmenterConfig

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_CWE_RE = re.compile(r"\bCWE-\d+\b")
_NUMBERED_HEADING_RE = re.compile(
    r"^\s*(?:Finding\s+\d+\b|Vulnerability\s+\d+\b|\d+(?:\.\d+)+\s+\S)", re.IGNORECASE
)
_SEVERITY_ROW_RE = re.compile(
    r"^\s*(?:Critical|High|Medium|Low)\b.{0,80}\|", re.IGNORECASE
)

_DEFAULT_BOUNDARY_PATTERNS = (_CVE_RE, _CWE_RE, _NUMBERED_HEADING_RE, _SEVERITY_ROW_RE)


def _is_boundary_line(line: str, *, extra_headings: tuple[str, ...]) -> bool:
    if any(p.search(line) for p in _DEFAULT_BOUNDARY_PATTERNS):
        return True
    return any(line.strip().lower().startswith(h.lower()) for h in extra_headings)


def _split_oversized(text: str, *, max_chars: int) -> list[str]:
    """Hard-split `text` at the nearest paragraph boundary (`\\n\\n`) at or
    before `max_chars`, repeating until every piece fits. Falls back to a
    hard character cut only if a single paragraph itself exceeds
    `max_chars` (e.g. one giant unbroken evidence dump)."""
    if len(text) <= max_chars:
        return [text]
    pieces: list[str] = []
    remaining = text
    while len(remaining) > max_chars:
        window = remaining[:max_chars]
        split_at = window.rfind("\n\n")
        if split_at < max_chars // 4:
            # No good paragraph boundary in range — fall back to a hard cut
            # rather than producing a near-empty first piece.
            split_at = max_chars
        pieces.append(remaining[:split_at].strip())
        remaining = remaining[split_at:].strip()
    if remaining:
        pieces.append(remaining)
    return [p for p in pieces if p]


def segment(
    document: DocumentText, *, config: SegmenterConfig | None = None
) -> tuple[ClaimBlock, ...]:
    """Split `document`'s page text into claim-sized blocks.

    Pure and deterministic: the same `DocumentText` always yields the same
    blocks, with no I/O and no LLM call — see this module's docstring for
    the boundary rules and the size caps.
    """
    cfg = config or SegmenterConfig()

    # Flatten to (page_number, line) pairs so a boundary/paragraph split
    # never loses which page a line came from.
    tagged_lines: list[tuple[int, str]] = []
    for page in document.pages:
        for line in page.text.splitlines():
            tagged_lines.append((page.page_number, line))

    if not tagged_lines:
        return ()

    raw_blocks: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []
    saw_any_boundary = False
    for page_number, line in tagged_lines:
        if _is_boundary_line(line, extra_headings=cfg.extra_headings) and current:
            saw_any_boundary = True
            raw_blocks.append(current)
            current = [(page_number, line)]
        else:
            current.append((page_number, line))
    if current:
        raw_blocks.append(current)

    if not saw_any_boundary:
        # No claim-shaped boundary matched anywhere in the document — fall
        # back to fixed-size runs so the report still gets full coverage.
        full_text = "\n".join(line for _, line in tagged_lines)
        pieces = _split_oversized(full_text, max_chars=cfg.max_block_chars)
        # Re-derive page numbers for each fallback piece by locating its
        # first line among the tagged lines (best-effort; a fallback block
        # spans a contiguous run so its own first-matching page is a
        # faithful lower bound).
        blocks: list[ClaimBlock] = []
        cursor = 0
        for i, piece in enumerate(pieces):
            piece_lines = piece.count("\n") + 1
            covered = tagged_lines[cursor : cursor + piece_lines]
            pages_covered = tuple(sorted({p for p, _ in covered})) or (
                tagged_lines[min(cursor, len(tagged_lines) - 1)][0],
            )
            blocks.append(
                ClaimBlock(block_id=f"block_{i:04d}", page_numbers=pages_covered, text=piece)
            )
            cursor += piece_lines
        return tuple(blocks)

    # Merge runt blocks into the following block (or the previous one if
    # this is the last block) so a lone heading with little body never
    # becomes its own LLM call.
    merged: list[list[tuple[int, str]]] = []
    for block in raw_blocks:
        text_len = sum(len(line) for _, line in block)
        if merged and text_len < cfg.min_block_chars:
            merged[-1].extend(block)
        else:
            merged.append(block)
    if len(merged) >= 2 and sum(len(line) for _, line in merged[-1]) < cfg.min_block_chars:
        tail = merged.pop()
        merged[-1].extend(tail)

    result: list[ClaimBlock] = []
    for i, block in enumerate(merged):
        pages_covered = tuple(sorted({p for p, _ in block}))
        text = "\n".join(line for _, line in block).strip()
        if not text:
            continue
        for j, piece in enumerate(_split_oversized(text, max_chars=cfg.max_block_chars)):
            block_id = f"block_{i:04d}" if j == 0 else f"block_{i:04d}_{j:02d}"
            result.append(ClaimBlock(block_id=block_id, page_numbers=pages_covered, text=piece))
    return tuple(result)
