"""Greedy line-count accumulation of Step 2's extracted functions into
Step 3's `Chunk`s. See `chunk/__init__.py`'s module docstring for why this
needs no second AST walk.
"""

from __future__ import annotations

from fw_audit.stage3_analysis.models import Chunk, ExtractedFunction, ExtractedSource


def chunk_source(
    source: ExtractedSource,
    *,
    bin_id: str,
    rootfs_path: str,
    source_relpath: str,
    chunk_lines: int,
    max_chunk_lines: int,
) -> tuple[Chunk, ...]:
    """Greedily accumulate `source.functions` (already in original source
    order — see `ExtractedSource.to_text()`'s own docstring on why that
    order is trustworthy) into `Chunk`s targeting `chunk_lines` lines
    each, NEVER splitting a function across two chunks.

    `bin_id`/`rootfs_path`/`source_relpath` are accepted as explicit
    parameters rather than read off `source` (which only carries `bin_id`,
    not the other two — `ExtractedSource` has no notion of where a binary
    lives on disk, only `Target` does) so this function's inputs are
    fully self-contained; it does not cross-check that `bin_id` matches
    `source.bin_id` if a caller happens to pass a different value. Callers
    (`ingest.py`) always pass `target.bin_id`/`target.rootfs_path`/
    `target.source_relpath` together with a `source` built by calling
    `extract_functions(text, bin_id=target.bin_id, ...)`, so the two
    naturally agree in production use.

    Algorithm, one pass over `source.functions`, no lookahead:

    * Maintain a `pending` list (the chunk being accumulated) and its
      running `pending_total` line count.
    * For each function, its own span is `end_line - start_line + 1` —
      the exact idiom `extract.extract_functions` already uses for the
      same computation, reused here rather than re-derived from `.text`.
    * **A function whose own span exceeds `max_chunk_lines` (the hard
      cap)**: flush any non-empty `pending` first (as its own, non-
      oversized chunk), then emit this function ALONE as its own chunk
      with `oversized=True`, then continue with a fresh empty `pending`.
      This is the one case a chunk's line count may exceed
      `max_chunk_lines` — by construction, since the function itself
      already does and functions are never split.
    * **A function whose own span is between `chunk_lines` and
      `max_chunk_lines` (inclusive)**: NOT marked oversized. If merging
      it into a non-empty `pending` would push `pending_total` over
      `max_chunk_lines`, flush `pending` first (as its own chunk), so the
      hard cap is never violated by a merge. Otherwise, append it to
      `pending`. Either way, since this function's span alone already
      meets or exceeds `chunk_lines`, the chunk it ends up in is closed
      (flushed) immediately after — it never sits in `pending` waiting
      for a subsequent function.
    * **Otherwise (a normal, small function)**: append it to `pending`,
      add its span to `pending_total`. If `pending_total` has now reached
      `chunk_lines` (the soft target), flush `pending` as a chunk — the
      function that crossed the limit stays IN that chunk; the soft
      limit is checked only AFTER appending, never before, so it is never
      the reason a function is excluded from the chunk it would
      naturally fall into.
    * After the loop, flush any remaining non-empty `pending` — the last
      chunk in a binary is very unlikely to land exactly on
      `chunk_lines`, and must still be emitted rather than silently
      dropped.

    `source.functions == ()` (e.g. a target with zero real functions,
    surviving nothing past `extract_functions`'s filter) returns `()`
    directly — the loop simply never executes, and the final flush is a
    no-op on an already-empty `pending`.

    Chunk ordinals are `len(chunks)` at the moment each is appended —
    i.e. simply the running count of chunks emitted so far, kept dense
    and zero-based across every case above (normal, oversized, and
    hard-cap-forced-flush chunks all share the same counter).

    Raises `ValueError` if `chunk_lines > max_chunk_lines` — a
    misconfiguration (the soft target must not exceed the hard cap) that
    should fail loudly and immediately rather than silently producing
    every chunk as "oversized" or behaving unpredictably.

    Pure and in-memory: no filesystem I/O, no `tree-sitter` import (this
    module never re-parses — `source` already carries every function's
    exact boundaries). Bounded per single binary: never accumulates more
    than one `ExtractedSource`'s worth of chunk text at a time — callers
    invoke this once per `Target`, matching `extract_functions`'s own
    per-target granularity.
    """
    if chunk_lines > max_chunk_lines:
        raise ValueError(
            f"chunk_lines ({chunk_lines}) must not exceed max_chunk_lines ({max_chunk_lines})"
        )

    chunks: list[Chunk] = []
    pending: list[ExtractedFunction] = []
    pending_total = 0

    for func in source.functions:
        span = func.end_line - func.start_line + 1

        if span > max_chunk_lines:
            pending = _flush(
                chunks,
                pending,
                bin_id=bin_id,
                rootfs_path=rootfs_path,
                source_relpath=source_relpath,
            )
            pending_total = 0
            chunks.append(
                _build_chunk(
                    [func],
                    bin_id=bin_id,
                    rootfs_path=rootfs_path,
                    source_relpath=source_relpath,
                    ordinal=len(chunks),
                    oversized=True,
                )
            )
            continue

        if pending and pending_total + span > max_chunk_lines:
            pending = _flush(
                chunks,
                pending,
                bin_id=bin_id,
                rootfs_path=rootfs_path,
                source_relpath=source_relpath,
            )
            pending_total = 0

        pending.append(func)
        pending_total += span

        if pending_total >= chunk_lines:
            pending = _flush(
                chunks,
                pending,
                bin_id=bin_id,
                rootfs_path=rootfs_path,
                source_relpath=source_relpath,
            )
            pending_total = 0

    _flush(
        chunks, pending, bin_id=bin_id, rootfs_path=rootfs_path, source_relpath=source_relpath
    )

    return tuple(chunks)


def _flush(
    chunks: list[Chunk],
    pending: list[ExtractedFunction],
    *,
    bin_id: str,
    rootfs_path: str,
    source_relpath: str,
) -> list[ExtractedFunction]:
    """Append `pending` (if non-empty) to `chunks` as one non-oversized
    `Chunk`, and return a fresh empty list for the caller's next pending
    accumulation. Mutates `chunks` in place — `chunk_source`'s loop needs
    running state (whether the soft/hard limit has been crossed depends
    on everything accumulated so far), so this is the one place an
    otherwise-pure module does in-place mutation, scoped tightly to a
    single call's local `chunks` list."""
    if pending:
        chunks.append(
            _build_chunk(
                pending,
                bin_id=bin_id,
                rootfs_path=rootfs_path,
                source_relpath=source_relpath,
                ordinal=len(chunks),
                oversized=False,
            )
        )
    return []


def _build_chunk(
    functions: list[ExtractedFunction],
    *,
    bin_id: str,
    rootfs_path: str,
    source_relpath: str,
    ordinal: int,
    oversized: bool,
) -> Chunk:
    """One non-empty `functions` list -> one `Chunk`. `functions` is
    always non-empty here — both call sites in `chunk_source`/`_flush`
    only invoke this after checking that."""
    text = "\n\n".join(f.text for f in functions)
    return Chunk(
        chunk_id=f"{bin_id}#{ordinal:04d}",
        bin_id=bin_id,
        rootfs_path=rootfs_path,
        source_relpath=source_relpath,
        functions=tuple(functions),
        start_line=functions[0].start_line,
        end_line=functions[-1].end_line,
        approx_tokens=len(text) // 4,
        oversized=oversized,
    )


__all__ = ["chunk_source"]
