"""Step 4: hand chunks to an `asyncio.Queue` for a worker pool to pull —
the last piece of Stage 3 Component 1 (see `stage3_analysis/__init__.py`'s
module docstring for the Component 1/Component 2 boundary this respects).

Top-level module, not nested under `chunk/` — named `chunk_queue` to stay
unambiguous against both the `chunk/` subpackage (Step 3) and Python's
stdlib `queue` module.

In-process, not Redis or any external broker
--------------------------------------------------------------------------
No message-queue/task-queue dependency exists anywhere in this project, and
none is introduced here: `ChunkQueue` wraps a plain `asyncio.Queue`, and its
producer + consumers all run inline within one `fw-analyze --queue`
invocation. This is a deliberate choice, not an oversight — this pipeline is
a single-machine CLI tool with no existing long-running-service infra (no
`docker-compose`, only single-shot `docker run --rm`), and nothing in its
design calls for chunks to be shared across multiple firmware-analysis runs
or multiple machines. If that requirement ever appears, it belongs in a
fresh design, not a retrofit of this module.

Reliability without a broker: disk as the source of truth
--------------------------------------------------------------------------
`ChunkQueue` never holds a `Chunk`'s text in memory once queued — `put()`
persists `chunk.to_text()` to `layout.chunks_dir()`/`layout.chunk_filename()`
(the same location `ingest._write_chunk_debug_sources`'s `--debug-chunks`
dump already uses) and queues a `ChunkHandle` (metadata + `chunk_path`
pointer) instead of the `Chunk` itself. This bounds the queue's own memory
footprint to `O(maxsize x metadata size)` regardless of firmware size or
binary count, gives durable, inspectable, idempotent chunk artifacts (same
`chunk_id` -> same file -> identical content, since chunking is
deterministic), and is what makes `ack`/`nack` retry semantics possible
without a broker's own persistence layer.

Component 2's extension point
--------------------------------------------------------------------------
`run_queue()`'s `consumer` parameter IS the hand-off to Component 2 (not
yet built — see `stage3_analysis/__init__.py`): pass a real one (the future
LLM agent call) once it exists. Omitting it uses `_noop_consumer`, which
proves the queue/backpressure/ack/nack/close plumbing works end-to-end
without doing any real analysis.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path

from fw_audit.common.schemas import ChunkRecord, Stage3Summary
from fw_audit.config.settings import Settings
from fw_audit.stage3_analysis import layout
from fw_audit.stage3_analysis.chunk.strategy import chunk_source
from fw_audit.stage3_analysis.cleaned_io import load_cleaned_source
from fw_audit.stage3_analysis.models import Chunk, ChunkHandle, IngestionReport

logger = logging.getLogger("fw_audit.stage3_analysis")

Consumer = Callable[[ChunkHandle], Awaitable[None]]

#: Sentinel pushed once per worker by `ChunkQueue.close()`. `None` rather
#: than a dedicated object: `ChunkHandle` is never `None`, so the type
#: distinction is unambiguous, and it needs no import of its own.
_SENTINEL = None


class ChunkQueue:
    """Bounded `asyncio.Queue[ChunkHandle | None]` wrapper: `put()` persists
    a `Chunk` to disk and enqueues a `ChunkHandle`; consumers drain it via
    `async for handle in queue: ...`; `ack()`/`nack()` record outcomes;
    `close()` shuts every consumer down cleanly via one sentinel each.

    Bookkeeping (`produced`/`acked`/`failed`, all `list[ChunkHandle]`) lives
    on the instance itself rather than a second parallel structure — the
    orchestrator (`run_queue()`) reads these directly to build the
    `Stage3Summary` once every consumer has finished.
    """

    def __init__(
        self,
        *,
        maxsize: int,
        workers: int,
        max_attempts: int,
        chunks_dir: Path,
    ) -> None:
        self._queue: asyncio.Queue[ChunkHandle | None] = asyncio.Queue(maxsize=maxsize)
        self._workers = workers
        self._max_attempts = max_attempts
        self._chunks_dir = chunks_dir
        self.produced: list[ChunkHandle] = []
        self.acked: list[ChunkHandle] = []
        self.failed: list[ChunkHandle] = []

    async def put(self, chunk: Chunk) -> ChunkHandle:
        """Persist `chunk.to_text()` to `chunks_dir/chunk_filename(chunk_id)`
        (creating the directory on first use), build a `ChunkHandle`
        pointing at that file, and enqueue it — `await`ing here is what
        makes backpressure real: once `maxsize` un-acked handles are
        pending, this blocks until a consumer's `ack()`/`nack()` frees a
        slot. Idempotent: re-`put()`-ing the same `chunk_id` overwrites the
        file with identical content (chunking is deterministic for the
        same input/settings), never duplicates or corrupts it.
        """
        self._chunks_dir.mkdir(parents=True, exist_ok=True)
        chunk_path = self._chunks_dir / layout.chunk_filename(chunk.chunk_id)
        chunk_path.write_text(chunk.to_text(), encoding="utf-8")
        handle = ChunkHandle.from_chunk(chunk, chunk_path)
        self.produced.append(handle)
        await self._queue.put(handle)
        return handle

    def __aiter__(self) -> ChunkQueue:
        return self

    async def __anext__(self) -> ChunkHandle:
        """Consumer-side iteration: `async for handle in queue: ...`.
        Raises `StopAsyncIteration` on receiving this consumer's sentinel
        (calling `task_done()` for it immediately — a sentinel needs no
        `ack()`/`nack()` from the caller, since it was never `produced`)."""
        handle = await self._queue.get()
        if handle is _SENTINEL:
            self._queue.task_done()
            raise StopAsyncIteration
        return handle

    def ack(self, handle: ChunkHandle) -> None:
        """Record `handle` as successfully processed and signal
        `asyncio.Queue.task_done()` for its `get()`."""
        self.acked.append(handle)
        self._queue.task_done()

    async def nack(self, handle: ChunkHandle) -> None:
        """Signal `task_done()` for `handle`'s `get()` (its attempt is
        over, successful or not), then either re-queue a NEW handle with
        `attempt + 1` (via `dataclasses.replace` — `ChunkHandle` is frozen,
        per this project's immutability convention) if under
        `max_attempts`, or record `handle` AS-IS (unchanged `attempt`) as
        permanently failed without re-queueing. `handle.attempt` is always
        the 0-indexed number of the attempt that just ran — so
        `attempt + 1` is consistently "attempts made so far" for both a
        handle that eventually gets acked and one that ends up in
        `failed`; appending `handle` unmodified here (not a
        `dataclasses.replace`-bumped copy) is what keeps that arithmetic
        consistent between the two outcomes. The retried handle re-enters
        the SAME bounded queue (a fresh `asyncio.Queue.put()` call), so it
        can still block on backpressure like any other item — retries
        don't bypass the memory bound `maxsize` provides."""
        self._queue.task_done()
        attempts_made = handle.attempt + 1
        if attempts_made >= self._max_attempts:
            self.failed.append(handle)
            return
        await self._queue.put(dataclasses.replace(handle, attempt=attempts_made))

    async def close(self) -> None:
        """Waits for every outstanding item to be fully processed — via
        `asyncio.Queue.join()`, which blocks until every `put()` so far
        has a matching `task_done()` — THEN pushes exactly `workers`
        sentinels so each concurrent consumer's `async for` loop receives
        exactly one and stops.

        The `join()` first is load-bearing, not defensive: without it, a
        chunk that gets `nack()`'d and re-queued AFTER the producer has
        already finished calling `put()` for every real chunk would have
        its retry land BEHIND the sentinel this method pushes (FIFO) —
        the worker would dequeue the sentinel first, raise
        `StopAsyncIteration`, and exit before ever seeing the retry.
        `join()` naturally accounts for retries too (each is its own
        `put()`/`task_done()` pair), so it only returns once every chunk —
        including every one that got nacked and re-queued along the way —
        has reached a final ack or permanent-failure outcome."""
        await self._queue.join()
        for _ in range(self._workers):
            await self._queue.put(_SENTINEL)


async def _noop_consumer(handle: ChunkHandle) -> None:
    """Placeholder used when `run_queue()` is called without a real
    `consumer`. Does nothing besides letting the handle flow through to
    `ack()` — proves the queue/backpressure/ack/close plumbing works
    end-to-end, but performs NO vulnerability analysis. Component 2 (not
    yet built — see this module's docstring) supplies the real consumer."""
    return None


async def _worker(queue: ChunkQueue, consumer: Consumer) -> None:
    """One of `settings.stage3_queue_workers` concurrent consumer tasks.
    Broad `except Exception` around `consumer(handle)` is deliberate: the
    real future consumer (an LLM call) can fail in ways this module can't
    enumerate (network errors, timeouts, rate limits, malformed responses)
    — an unknown failure should retry/eventually-fail gracefully via
    `nack()`, not crash the whole worker pool and lose every other
    in-flight chunk's progress."""
    async for handle in queue:
        try:
            await consumer(handle)
        except Exception as exc:
            logger.warning(
                "chunk %s failed (attempt %d): %s",
                handle.chunk_id,
                handle.attempt + 1,
                exc,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )
            await queue.nack(handle)
        else:
            queue.ack(handle)


async def produce_chunks(
    report: IngestionReport, settings: Settings, queue: ChunkQueue
) -> list[str]:
    """For each `Target` in `report.targets`: load Stage 2's persisted
    cleaned artifact (`cleaned_io.load_cleaned_source` — no re-parsing,
    unlike the former in-memory `extract_functions()` call this replaced),
    `chunk_source()` (using `settings.stage3_chunk_lines`/
    `stage3_max_chunk_lines`), and `queue.put()` every resulting `Chunk`.
    `queue.close()` ALWAYS runs (via `finally`) so spawned consumers never
    hang waiting for a sentinel that never comes, even if this stops early.

    A `Target` with no `cleaned_source_path`/`cleaned_index_path` (Stage 2
    skipped cleaning for it) is skipped individually with a warning —
    unlike the old process-wide `Stage3InputError` short-circuit (missing
    tree-sitter used to abort every remaining target at once), a missing
    artifact for one binary says nothing about any other's, since Stage 2
    now decides cleaning availability per binary, not process-wide.
    Returns the warnings accumulated (empty list if none), for the caller
    to fold into `Stage3Summary`.
    """
    warnings: list[str] = []
    try:
        if not report.targets:
            return warnings
        for target in report.targets:
            if target.cleaned_source_path is None or target.cleaned_index_path is None:
                msg = (
                    f"chunking skipped for {target.bin_id}: no cleaned artifact recorded "
                    "(Stage 2 may have skipped cleaning for this binary)"
                )
                logger.warning(msg)
                warnings.append(msg)
                continue
            try:
                source = load_cleaned_source(
                    target.cleaned_source_path, target.cleaned_index_path
                )
            except (OSError, ValueError) as exc:
                msg = f"chunking skipped for {target.bin_id}: {exc}"
                logger.warning(msg)
                warnings.append(msg)
                continue
            chunks = chunk_source(
                source,
                bin_id=target.bin_id,
                rootfs_path=target.rootfs_path,
                source_relpath=target.source_relpath,
                chunk_lines=settings.stage3_chunk_lines,
                max_chunk_lines=settings.stage3_max_chunk_lines,
            )
            for chunk in chunks:
                await queue.put(chunk)
    finally:
        await queue.close()
    return warnings


async def run_queue(
    report: IngestionReport,
    *,
    settings: Settings,
    consumer: Consumer | None = None,
    run_id: str | None = None,
) -> Stage3Summary:
    """Component 1's Step 4 entry point — and Component 2's intended
    extension point (see this module's docstring): pass a real `consumer`
    once Component 2's LLM agent exists; omitting it exercises the
    plumbing with `_noop_consumer` only.

    Spawns `produce_chunks()` and `settings.stage3_queue_workers` `_worker`
    tasks concurrently via `asyncio.gather` (the producer must run
    concurrently with consumers, not before them, or `put()`'s backpressure
    would deadlock waiting for a consumer that's never been scheduled).
    Writes `stage3_summary.json` itself (via `layout.stage3_summary_path`),
    mirroring `Stage2Summary`'s precedent of being written by the
    orchestrator function itself, not only a CLI wrapper — a programmatic
    caller invoking `run_queue()` directly still gets a summary.
    """
    run_id = run_id or uuid.uuid4().hex[:12]
    started_at = datetime.now(UTC)

    chunks_dir = layout.chunks_dir(layout.stage3_dir(report.db_subfolder))
    queue = ChunkQueue(
        maxsize=settings.stage3_queue_maxsize,
        workers=settings.stage3_queue_workers,
        max_attempts=settings.stage3_queue_max_attempts,
        chunks_dir=chunks_dir,
    )

    active_consumer = consumer or _noop_consumer
    producer_task = asyncio.create_task(produce_chunks(report, settings, queue))
    worker_tasks = [
        asyncio.create_task(_worker(queue, active_consumer))
        for _ in range(settings.stage3_queue_workers)
    ]
    warnings = await producer_task
    await asyncio.gather(*worker_tasks)

    finished_at = datetime.now(UTC)
    summary = _build_summary(
        report=report,
        queue=queue,
        run_id=run_id,
        warnings=warnings,
        started_at=started_at,
        finished_at=finished_at,
    )
    _write_summary(report.db_subfolder, summary)
    return summary


def _build_summary(
    *,
    report: IngestionReport,
    queue: ChunkQueue,
    run_id: str,
    warnings: list[str],
    started_at: datetime,
    finished_at: datetime,
) -> Stage3Summary:
    if not report.targets:
        status = "no_targets"
    elif warnings and not queue.produced:
        # Every target hit a missing/unreadable cleaned artifact — the
        # process-wide analog of the old "tree-sitter not installed"
        # short-circuit, just detected per-target now that Stage 2 decides
        # cleaning availability per binary rather than once for the whole
        # process. A run where SOME targets chunked fine despite a few
        # skips is "completed" (with warnings), not this.
        status = "stage3_input_unavailable"
    else:
        status = "completed"

    acked_ids = {h.chunk_id for h in queue.acked}
    records = [
        ChunkRecord(
            chunk_id=h.chunk_id,
            bin_id=h.bin_id,
            rootfs_path=h.rootfs_path,
            source_relpath=h.source_relpath,
            chunk_path=str(h.chunk_path.relative_to(report.db_subfolder)),
            start_line=h.start_line,
            end_line=h.end_line,
            approx_tokens=h.approx_tokens,
            oversized=h.oversized,
            status="acked" if h.chunk_id in acked_ids else "failed",
            attempts=h.attempt + 1,
        )
        for h in (*queue.acked, *queue.failed)
    ]

    return Stage3Summary(
        run_id=run_id,
        status=status,
        db_subfolder=str(report.db_subfolder),
        chunks=records,
        total_chunks=len(queue.produced),
        total_acked=len(queue.acked),
        total_failed=len(queue.failed),
        total_tokens=sum(h.approx_tokens for h in queue.acked),
        warnings=warnings,
        started_at=started_at,
        finished_at=finished_at,
    )


def _write_summary(db_subfolder: Path, summary: Stage3Summary) -> None:
    """Best-effort write, matching `ingest._write_report`'s discipline: a
    write failure is recoverable (the caller already has the in-memory
    `Stage3Summary`), not a reason to fail the whole run."""
    stage3_dir = layout.stage3_dir(db_subfolder)
    try:
        stage3_dir.mkdir(parents=True, exist_ok=True)
        layout.stage3_summary_path(stage3_dir).write_text(
            summary.model_dump_json(indent=2), encoding="utf-8"
        )
    except OSError:
        pass


__all__ = ["ChunkQueue", "produce_chunks", "run_queue"]
