"""`AnalysisConsumer`: the real `Consumer` that fills `chunk_queue.
run_queue(..., consumer=...)`'s extension point, replacing the no-op
placeholder with actual LLM-backed vulnerability analysis.

A class (not a closure function), because `run_queue()` shares ONE consumer
object across all `settings.stage3_queue_workers` concurrent workers (see
`chunk_queue.py`'s docstring: "one shared active_consumer object across all
N workers"). Per-run state — the accumulated `ChunkAnalysisRecord`s, the
findings output directory, `Settings` — needs somewhere to live; a class
instance is that somewhere, addressable by `agent.orchestrator.run_analysis`
after the run completes.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from fw_audit.common.findings import AnalysisReport, ChunkAnalysisRecord
from fw_audit.config.settings import Settings
from fw_audit.observability import span, trace_context
from fw_audit.stage3_analysis import layout
from fw_audit.stage3_analysis.agent.analyst import AnalysisUnavailableError, analyze_chunk
from fw_audit.stage3_analysis.models import ChunkHandle

logger = logging.getLogger("fw_audit.stage3_analysis.agent")


class AnalysisConsumer:
    """Reads a chunk's persisted `.c` payload, analyzes it, and persists
    the resulting `AnalysisReport` to `stage3/findings/<chunk_id>.json`.

    Failure handling follows `chunk_queue._worker`'s existing contract
    (see that module's docstring): this consumer RAISES on failure rather
    than swallowing it, letting the queue's own broad `except Exception` ->
    `nack()` retry the chunk up to `settings.stage3_queue_max_attempts`
    times. This class does not duplicate that retry loop — it adds three
    things the queue layer doesn't and shouldn't know about: skipping
    chunks too large to analyze, backing off before a retried attempt, and
    writing the findings artifact once a report validates.
    """

    def __init__(self, *, db_subfolder: Path, settings: Settings) -> None:
        self._db_subfolder = db_subfolder
        self._settings = settings
        self._findings_dir = layout.findings_dir(layout.stage3_dir(db_subfolder))
        self.records: list[ChunkAnalysisRecord] = []
        """Appended to only from within `__call__`, which always runs on
        the single asyncio event loop with no `await` between the record's
        construction and its append — safe under concurrent worker tasks
        without a lock, same reasoning `ChunkQueue`'s own bookkeeping
        lists rely on."""

    async def __call__(self, handle: ChunkHandle) -> None:
        # trace_context is entered here, per-call, rather than once around
        # the whole worker pool: chunk_queue fans workers out via
        # asyncio.create_task, and a context set inside one worker's
        # __call__ must not leak into a sibling task processing a different
        # chunk concurrently — see fw_audit.observability.context's
        # docstring. The `stage3.chunk` span is opened here too, OUTSIDE
        # the asyncio.wait_for below: wait_for cancels its inner coroutine
        # on timeout, which would destroy a span opened inside it before
        # the timeout — the single most useful failure to see — could be
        # recorded.
        with trace_context(
            stage="3",
            chunk_id=handle.chunk_id,
            bin_id=handle.bin_id,
        ), span(
            "stage3.chunk",
            run_type="chain",
            inputs={"chunk_id": handle.chunk_id, "attempt": handle.attempt},
            metadata={"queue_attempt": handle.attempt},
        ) as run:
            try:
                await self._process(handle)
            except BaseException as exc:
                if run is not None:
                    run.end(error=str(exc))
                raise
            else:
                if run is not None:
                    run.end(outputs={"status": "ok"})

    async def _process(self, handle: ChunkHandle) -> None:
        if handle.attempt:
            backoff = self._settings.stage3_llm_retry_backoff_seconds * (2 ** (handle.attempt - 1))
            if backoff:
                await asyncio.sleep(backoff)

        if handle.approx_tokens > self._settings.stage3_max_chunk_tokens:
            logger.warning(
                "chunk %s skipped: %d approx tokens exceeds stage3_max_chunk_tokens (%d)",
                handle.chunk_id,
                handle.approx_tokens,
                self._settings.stage3_max_chunk_tokens,
            )
            self.records.append(
                ChunkAnalysisRecord(
                    chunk_id=handle.chunk_id,
                    bin_id=handle.bin_id,
                    rootfs_path=handle.rootfs_path,
                    status="skipped_oversized",
                    attempts=handle.attempt + 1,
                )
            )
            return

        chunk_text = await asyncio.to_thread(
            handle.chunk_path.read_text, encoding="utf-8", errors="replace"
        )

        try:
            report = await asyncio.wait_for(
                analyze_chunk(
                    chunk_text,
                    chunk_id=handle.chunk_id,
                    rootfs_path=handle.rootfs_path,
                    settings=self._settings,
                ),
                timeout=self._settings.stage3_llm_timeout_seconds,
            )
        except TimeoutError as exc:
            # asyncio.wait_for's TimeoutError carries NO message of its
            # own — str(exc) is always "" (confirmed: TimeoutError() takes
            # no args) — so `{exc}` here would silently produce a blank,
            # content-free "analysis failed for X: " log line indistinguishable
            # from any other failure. Name the actual timeout value instead,
            # so this is self-explanatory without knowing that quirk.
            raise RuntimeError(
                f"analysis failed for {handle.chunk_id}: LLM call exceeded "
                f"stage3_llm_timeout_seconds ({self._settings.stage3_llm_timeout_seconds}s)"
            ) from exc
        except AnalysisUnavailableError as exc:
            # Let it propagate: chunk_queue._worker's broad `except
            # Exception` will nack() this handle for a queue-level retry.
            # We do NOT append a "failed" record here — a retry may still
            # succeed. Permanent failure is reconciled from
            # Stage3Summary.chunks by agent.orchestrator.run_analysis
            # after the whole queue drains, using the SAME final
            # acked/failed determination chunk_queue already computed.
            raise RuntimeError(f"analysis failed for {handle.chunk_id}: {exc}") from exc

        target_path = self._findings_dir / layout.finding_filename(handle.chunk_id)
        await asyncio.to_thread(self._write_report, target_path, report)

        self.records.append(
            ChunkAnalysisRecord(
                chunk_id=handle.chunk_id,
                bin_id=handle.bin_id,
                rootfs_path=handle.rootfs_path,
                status="analyzed",
                attempts=handle.attempt + 1,
                finding_count=len(report.findings),
                findings_relpath=str(target_path.relative_to(self._db_subfolder)),
            )
        )

    def _write_report(self, path: Path, report: AnalysisReport) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
