"""Tests for `fw_audit.stage3_analysis.chunk_queue` — Step 4's `ChunkQueue`,
`produce_chunks`, and `run_queue`. `asyncio_mode = "auto"` is set in
pyproject.toml, so async test functions need no `@pytest.mark.asyncio`.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fw_audit.common.schemas import ExtractionStatus
from fw_audit.config.settings import Settings
from fw_audit.stage3_analysis.chunk_queue import ChunkQueue, produce_chunks, run_queue
from fw_audit.stage3_analysis.ingest import ingest
from fw_audit.stage3_analysis.models import Chunk, ChunkHandle, ExtractedFunction
from tests.conftest import write_cleaned_artifact


def _chunk(
    chunk_id: str = "test_bin#0000", *, bin_id: str = "test_bin", text: str = "void f(void) {}"
) -> Chunk:
    func = ExtractedFunction(name="f", start_line=1, end_line=1, text=text)
    return Chunk(
        chunk_id=chunk_id,
        bin_id=bin_id,
        rootfs_path="bin/test",
        source_relpath="bin/test.c",
        functions=(func,),
        start_line=1,
        end_line=1,
        approx_tokens=len(text) // 4,
        oversized=False,
    )


def _queue(
    tmp_path: Path, *, maxsize: int = 6, workers: int = 3, max_attempts: int = 3
) -> ChunkQueue:
    return ChunkQueue(
        maxsize=maxsize,
        workers=workers,
        max_attempts=max_attempts,
        chunks_dir=tmp_path / "chunks",
    )


# --- ChunkQueue: put/get, disk persistence ---


async def test_put_writes_chunk_text_to_disk(tmp_path):
    queue = _queue(tmp_path)
    chunk = _chunk(text="int add(int a, int b) { return a + b; }")

    handle = await queue.put(chunk)

    assert handle.chunk_path.is_file()
    assert handle.chunk_path.read_text(encoding="utf-8") == chunk.to_text()


async def test_put_returns_handle_with_matching_metadata(tmp_path):
    queue = _queue(tmp_path)
    chunk = _chunk(chunk_id="sbin_wpasupp#0003", bin_id="sbin_wpasupp")

    handle = await queue.put(chunk)

    assert handle.chunk_id == "sbin_wpasupp#0003"
    assert handle.bin_id == "sbin_wpasupp"
    assert handle.rootfs_path == chunk.rootfs_path
    assert handle.source_relpath == chunk.source_relpath
    assert handle.start_line == chunk.start_line
    assert handle.end_line == chunk.end_line
    assert handle.approx_tokens == chunk.approx_tokens
    assert handle.oversized == chunk.oversized
    assert handle.attempt == 0


async def test_put_idempotent_same_chunk_id_overwrites_identical_content(tmp_path):
    queue = _queue(tmp_path)
    chunk = _chunk()

    handle1 = await queue.put(chunk)
    handle2 = await queue.put(chunk)

    assert handle1.chunk_path == handle2.chunk_path
    assert handle1.chunk_path.read_text(encoding="utf-8") == chunk.to_text()


async def test_async_for_yields_put_handles_in_order(tmp_path):
    # Consumed via direct __anext__() calls, not close()+"async for": with a
    # known exact count and nothing consuming concurrently, close() would
    # deadlock on its own join() (see its docstring) waiting for these 3
    # items to be task_done()'d by a consumer that doesn't exist yet.
    queue = _queue(tmp_path, workers=1)
    chunks = [_chunk(chunk_id=f"test_bin#{i:04d}") for i in range(3)]
    for c in chunks:
        await queue.put(c)

    seen = []
    for _ in range(3):
        handle = await queue.__anext__()
        seen.append(handle.chunk_id)
        queue.ack(handle)

    assert seen == ["test_bin#0000", "test_bin#0001", "test_bin#0002"]


# --- Backpressure ---


async def test_put_blocks_when_queue_full_until_a_get_happens(tmp_path):
    queue = _queue(tmp_path, maxsize=1, workers=1)
    await queue.put(_chunk(chunk_id="test_bin#0000"))  # fills the queue (maxsize=1)

    second_put = asyncio.ensure_future(queue.put(_chunk(chunk_id="test_bin#0001")))
    await asyncio.sleep(0)  # let the event loop try to schedule second_put
    assert not second_put.done()  # still blocked: queue is full, nothing has been get() yet

    await queue.__anext__()  # drain one item, freeing a slot
    await asyncio.wait_for(second_put, timeout=1.0)  # now it can complete
    assert second_put.done()


# --- ack / nack / retry ---


async def test_ack_records_handle_as_acked(tmp_path):
    queue = _queue(tmp_path)
    handle = await queue.put(_chunk())

    got = await queue.__anext__()
    queue.ack(got)

    assert queue.acked == [handle]
    assert queue.failed == []


async def test_nack_under_max_attempts_requeues_with_incremented_attempt(tmp_path):
    queue = _queue(tmp_path, max_attempts=3)
    await queue.put(_chunk())

    first = await queue.__anext__()
    assert first.attempt == 0
    await queue.nack(first)

    retried = await queue.__anext__()
    assert retried.attempt == 1
    assert retried.chunk_id == first.chunk_id
    assert queue.failed == []


async def test_nack_at_max_attempts_records_permanent_failure_not_requeued(tmp_path):
    queue = _queue(tmp_path, max_attempts=2)
    await queue.put(_chunk())

    first = await queue.__anext__()  # attempt 0
    await queue.nack(first)
    second = await queue.__anext__()  # attempt 1 (retry)
    await queue.nack(second)  # attempts_made = 2 >= max_attempts(2) -> permanent failure

    assert len(queue.failed) == 1
    assert queue.failed[0].attempt == 1
    await queue.close()
    remaining = [h async for h in queue]
    assert remaining == []  # nothing else was ever queued -- confirms no further retry


async def test_nack_task_done_accounting_join_completes(tmp_path):
    """`asyncio.Queue.join()` must eventually resolve after a nack'd chunk
    is retried and finally acked -- proves task_done() bookkeeping across
    the get -> nack -> re-put -> get -> ack cycle stays balanced."""
    queue = _queue(tmp_path, max_attempts=3)
    await queue.put(_chunk())

    async def drain_until_acked():
        async for handle in queue:
            if handle.attempt == 0:
                await queue.nack(handle)
            else:
                queue.ack(handle)
                return

    task = asyncio.ensure_future(drain_until_acked())
    await asyncio.wait_for(queue._queue.join(), timeout=1.0)
    await task
    assert len(queue.acked) == 1


# --- close() ---


async def test_close_pushes_exactly_one_sentinel_per_worker(tmp_path):
    queue = _queue(tmp_path, workers=3)
    await queue.close()

    stopped = 0
    for _ in range(3):
        try:
            await queue.__anext__()
        except StopAsyncIteration:
            stopped += 1
    assert stopped == 3


async def test_multiple_consumers_all_terminate_after_close(tmp_path):
    queue = _queue(tmp_path, workers=3)
    for i in range(5):
        await queue.put(_chunk(chunk_id=f"test_bin#{i:04d}"))

    results: list[list[str]] = []

    async def consume():
        seen = []
        async for handle in queue:
            seen.append(handle.chunk_id)
            queue.ack(handle)
        results.append(seen)

    # Consumers must be running concurrently with close(), not started
    # after it returns: close() now calls join() first (see its docstring
    # for why), which blocks until every put() so far has a matching
    # task_done() -- nothing would ever drain the 5 items above if nobody
    # were consuming while join() waits.
    consumer_tasks = [asyncio.ensure_future(consume()) for _ in range(3)]
    await asyncio.wait_for(queue.close(), timeout=2.0)
    await asyncio.wait_for(asyncio.gather(*consumer_tasks), timeout=2.0)

    all_seen = [cid for r in results for cid in r]
    assert sorted(all_seen) == [f"test_bin#{i:04d}" for i in range(5)]


# --- produce_chunks / run_queue end-to-end ---


def _setup_run(
    tmp_path: Path,
    *,
    source_text: str,
    bin_id: str = "bin_busybox",
    rootfs_path: str = "bin/busybox",
    with_cleaned_artifact: bool = True,
) -> Path:
    """One whitelisted, resolved target whose mirror-tree file holds
    `source_text`. Mirrors test_stage3_runner.py's `_setup_single_target_run`.

    `with_cleaned_artifact=True` (the default) writes a real Stage-2-style
    `cleaned/whole.c` + `functions.json` for `bin_id` (via
    `write_cleaned_artifact`, using the actual production extraction code)
    from `source_text`, and records it in the binary's `artifacts` — what
    `produce_chunks` now reads instead of re-parsing. Pass `False` to
    simulate a binary Stage 2 skipped cleaning for (e.g. missing
    tree-sitter there)."""
    db_subfolder = tmp_path / "db" / "fw"
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True)
    tree_dir = tmp_path / "db" / "fw_decompiled"
    rel_dir = "/".join(rootfs_path.split("/")[:-1])
    (tree_dir / rel_dir).mkdir(parents=True, exist_ok=True)
    (tree_dir / f"{rootfs_path}.c").write_text(source_text, encoding="utf-8")

    cleaned_artifacts = (
        write_cleaned_artifact(stage2_dir, bin_id, source_text) if with_cleaned_artifact else {}
    )

    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "identified_binaries": [{"path": rootfs_path}],
            }
        ),
        encoding="utf-8",
    )
    (stage2_dir / "stage2_summary.json").write_text(
        json.dumps(
            {
                "run_id": "r",
                "status": ExtractionStatus.COMPLETED.value,
                "db_subfolder": str(db_subfolder),
                "rootfs_dir": str(db_subfolder / "rootfs"),
                "stage2_dir": str(stage2_dir),
                "decompiled_tree_dir": "fw_decompiled",
                "ghidra_image": "fw-audit-ghidra:latest",
                "binaries": [
                    {
                        "bin_id": bin_id,
                        "rootfs_path": rootfs_path,
                        "requested_path": rootfs_path,
                        "sha256": "0" * 64,
                        "size_bytes": len(source_text.encode("utf-8")),
                        "status": "succeeded",
                        "function_count": 1,
                        "artifacts": {
                            "decompiled_tree_c": f"{rootfs_path}.c",
                            **cleaned_artifacts,
                        },
                    }
                ],
                "started_at": datetime.now(UTC).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    return summary_path


def _padded_function(name: str, n_statements: int = 60) -> str:
    body = "\n".join(f"  x += {i};" for i in range(n_statements))
    return f"int {name}(int x)\n{{\n{body}\n  return x;\n}}\n"


async def test_run_queue_end_to_end_with_noop_consumer(tmp_path):
    pytest.importorskip("tree_sitter_c")
    source = _padded_function("add") + "\n" + _padded_function("sub")
    summary_path = _setup_run(tmp_path, source_text=source)
    report = ingest(stage1_summary_path=summary_path)
    settings = Settings(_env_file=None, stage3_chunk_lines=50)

    summary = await run_queue(report, settings=settings)

    assert summary.status == "completed"
    assert summary.total_chunks == 2  # each padded function closes its own chunk
    assert summary.total_acked == 2
    assert summary.total_failed == 0
    assert len(summary.chunks) == 2
    assert all(c.status == "acked" for c in summary.chunks)
    assert all(c.attempts == 1 for c in summary.chunks)

    stage3_summary_path = tmp_path / "db" / "fw" / "stage3" / "stage3_summary.json"
    assert stage3_summary_path.is_file()
    written = json.loads(stage3_summary_path.read_text(encoding="utf-8"))
    assert written["total_chunks"] == 2


async def test_run_queue_persists_chunks_regardless_of_debug_flags(tmp_path):
    pytest.importorskip("tree_sitter_c")
    summary_path = _setup_run(tmp_path, source_text="int main(void) { return 0; }\n")
    report = ingest(stage1_summary_path=summary_path)
    settings = Settings(_env_file=None)  # no --debug/--debug-chunks

    await run_queue(report, settings=settings)

    chunks_dir = tmp_path / "db" / "fw" / "stage3" / "chunks"
    assert any(chunks_dir.glob("*.c"))


async def test_run_queue_zero_targets_produces_empty_summary_no_hang(tmp_path):
    db_subfolder = tmp_path / "db" / "fw"
    stage2_dir = db_subfolder / "stage2"
    stage2_dir.mkdir(parents=True)
    (tmp_path / "db" / "fw_decompiled").mkdir(parents=True)
    summary_path = db_subfolder / "stage1_summary.json"
    summary_path.write_text(
        json.dumps(
            {"status": "completed", "db_subfolder": str(db_subfolder), "identified_binaries": []}
        ),
        encoding="utf-8",
    )
    (stage2_dir / "stage2_summary.json").write_text(
        json.dumps(
            {
                "run_id": "r",
                "status": "completed",
                "db_subfolder": str(db_subfolder),
                "rootfs_dir": str(db_subfolder / "rootfs"),
                "stage2_dir": str(stage2_dir),
                "decompiled_tree_dir": "fw_decompiled",
                "ghidra_image": "fw-audit-ghidra:latest",
                "binaries": [],
                "started_at": datetime.now(UTC).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    report = ingest(stage1_summary_path=summary_path)
    settings = Settings(_env_file=None)

    summary = await asyncio.wait_for(run_queue(report, settings=settings), timeout=2.0)

    assert summary.status == "no_targets"
    assert summary.total_chunks == 0


async def test_run_queue_no_cleaned_artifact_degrades_gracefully(tmp_path, caplog):
    """A binary Stage 2 skipped cleaning for (e.g. `tree-sitter`/
    `tree-sitter-c` wasn't installed there) must not crash the queue —
    `produce_chunks` skips that one target with a warning; with only one
    target total, that means zero chunks and `stage3_input_unavailable`
    (see `_build_summary`'s status logic: EVERY target had nothing to
    chunk)."""
    summary_path = _setup_run(
        tmp_path, source_text="int main(void) { return 0; }\n", with_cleaned_artifact=False
    )
    report = ingest(stage1_summary_path=summary_path)
    settings = Settings(_env_file=None)

    with caplog.at_level("WARNING", logger="fw_audit.stage3_analysis"):
        summary = await asyncio.wait_for(run_queue(report, settings=settings), timeout=2.0)

    assert summary.status == "stage3_input_unavailable"
    assert summary.total_chunks == 0
    assert any("no cleaned artifact recorded" in w for w in summary.warnings)


async def test_run_queue_consumer_that_fails_then_succeeds_retries_via_nack(tmp_path):
    pytest.importorskip("tree_sitter_c")
    summary_path = _setup_run(tmp_path, source_text="int main(void) { return 0; }\n")
    report = ingest(stage1_summary_path=summary_path)
    settings = Settings(_env_file=None, stage3_queue_workers=1, stage3_queue_max_attempts=3)

    attempts: dict[str, int] = {}

    async def flaky_consumer(handle: ChunkHandle) -> None:
        attempts[handle.chunk_id] = attempts.get(handle.chunk_id, 0) + 1
        if attempts[handle.chunk_id] < 2:
            raise RuntimeError("transient failure")

    summary = await run_queue(report, settings=settings, consumer=flaky_consumer)

    assert summary.total_acked == 1
    assert summary.total_failed == 0
    assert summary.chunks[0].attempts == 2


async def test_run_queue_consumer_always_fails_records_permanent_failure(tmp_path):
    pytest.importorskip("tree_sitter_c")
    summary_path = _setup_run(tmp_path, source_text="int main(void) { return 0; }\n")
    report = ingest(stage1_summary_path=summary_path)
    settings = Settings(_env_file=None, stage3_queue_workers=1, stage3_queue_max_attempts=2)

    async def always_fails(handle: ChunkHandle) -> None:
        raise RuntimeError("permanent failure")

    summary = await run_queue(report, settings=settings, consumer=always_fails)

    assert summary.total_acked == 0
    assert summary.total_failed == 1
    assert summary.chunks[0].status == "failed"
    assert summary.chunks[0].attempts == 2


async def test_produce_chunks_closes_queue_even_with_no_targets(tmp_path):
    from fw_audit.stage3_analysis.models import IngestionReport

    queue = _queue(tmp_path, workers=2)
    empty_report = IngestionReport(
        db_subfolder=tmp_path / "db" / "fw",
        decompiled_tree_dir=tmp_path / "db" / "fw_decompiled",
        targets=(),
    )
    settings = Settings(_env_file=None)

    warnings = await produce_chunks(empty_report, settings, queue)

    assert warnings == []
    # Both worker sentinels should already be available without hanging --
    # __anext__() raises StopAsyncIteration on a sentinel rather than
    # returning it (that's how "async for handle in queue" knows to stop),
    # so both calls here are expected to raise, not return a handle.
    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(queue.__anext__(), timeout=1.0)
    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(queue.__anext__(), timeout=1.0)
