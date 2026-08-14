"""Component 6 — thin local driver: loop over Stage 3 findings, C3 -> C4 ->
C5 -> persist. No LangGraph state machine, no synthesis (that's pipeline
Stage 6's job) — see `MASTERPLAN_STAGE4.md` §10 for why Component 6 was
descoped from the original "Orchestrator & Report Synthesizer" design.

Async worker-pool shape mirrors `stage3_analysis.chunk_queue` — bounded
`asyncio.Queue`, `ack`/`nack` with bounded retry, `join()`-before-sentinels
shutdown — adapted for `SinkCandidate` items (already fully in memory from
`sink_index.discover_sink_candidates`, unlike Stage 3's chunk text, so there
is no disk-backed-handle indirection to replicate here).
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fw_audit.common.taint import FindingRunRecord, Stage4RunSummary, TaintPathReport
from fw_audit.config.settings import Settings, get_settings
from fw_audit.stage4_rag import layout
from fw_audit.stage4_rag.errors import Stage4InputError
from fw_audit.stage4_rag.query.planner import QueryPlannerUnavailableError, generate_queries
from fw_audit.stage4_rag.query.schemas import MultiQueryPlan
from fw_audit.stage4_rag.retrieval.engine import RetrievalBundle, build_c5_prompt, retrieve
from fw_audit.stage4_rag.retrieval.store import load_embedder, load_local_collection
from fw_audit.stage4_rag.sink_index import (
    DEFAULT_DECISIONS,
    SinkCandidate,
    discover_sink_candidates,
)
from fw_audit.stage4_rag.taint.analyst import TaintAnalystUnavailableError, analyze_taint

logger = logging.getLogger("fw_audit.stage4_rag")

_SENTINEL = None


@dataclasses.dataclass(frozen=True)
class _WorkItem:
    candidate: SinkCandidate
    attempt: int = 0


class FindingQueue:
    """Bounded `asyncio.Queue[_WorkItem | None]` — same ack/nack/close shape
    as `stage3_analysis.chunk_queue.ChunkQueue`, minus the disk-backed
    handle indirection (a `SinkCandidate` is small and already fully
    resolved in memory, unlike Stage 3's chunk text)."""

    def __init__(self, *, maxsize: int, workers: int, max_attempts: int) -> None:
        self._queue: asyncio.Queue[_WorkItem | None] = asyncio.Queue(maxsize=maxsize)
        self._workers = workers
        self._max_attempts = max_attempts
        self.produced: list[_WorkItem] = []
        self.acked: list[_WorkItem] = []
        self.failed: list[_WorkItem] = []

    async def put(self, candidate: SinkCandidate) -> None:
        item = _WorkItem(candidate=candidate)
        self.produced.append(item)
        await self._queue.put(item)

    def __aiter__(self) -> FindingQueue:
        return self

    async def __anext__(self) -> _WorkItem:
        item = await self._queue.get()
        if item is _SENTINEL:
            self._queue.task_done()
            raise StopAsyncIteration
        return item

    def ack(self, item: _WorkItem) -> None:
        self.acked.append(item)
        self._queue.task_done()

    async def nack(self, item: _WorkItem) -> None:
        self._queue.task_done()
        attempts_made = item.attempt + 1
        if attempts_made >= self._max_attempts:
            self.failed.append(item)
            return
        await self._queue.put(dataclasses.replace(item, attempt=attempts_made))

    async def close(self) -> None:
        await self._queue.join()
        for _ in range(self._workers):
            await self._queue.put(_SENTINEL)


@dataclasses.dataclass
class _RunContext:
    settings: Settings
    stage4_dir: Path
    collection: object
    embedder: object
    records: dict[str, FindingRunRecord] = dataclasses.field(default_factory=dict)


async def _process_one(candidate: SinkCandidate, *, ctx: _RunContext) -> None:
    """C3 -> C4 -> C5 for one finding, persisting each stage's output."""
    plan: MultiQueryPlan = await generate_queries(candidate, settings=ctx.settings)
    _write_json(
        layout.queries_dir(ctx.stage4_dir) / layout.query_plan_filename(candidate.global_id),
        plan.model_dump_json(indent=2),
    )

    bundle: RetrievalBundle = retrieve(
        plan,
        collection=ctx.collection,
        embedder=ctx.embedder,
        top_k=ctx.settings.stage4_top_k,
    )
    _write_json(
        layout.retrieval_dir(ctx.stage4_dir) / layout.retrieval_filename(candidate.global_id),
        _retrieval_bundle_to_json(bundle),
    )

    c5_prompt = build_c5_prompt(bundle, candidate)
    report: TaintPathReport = await analyze_taint(
        c5_prompt, global_id=candidate.global_id, settings=ctx.settings
    )
    _write_json(
        layout.taint_dir(ctx.stage4_dir) / layout.taint_filename(candidate.global_id),
        report.model_dump_json(indent=2),
    )

    ctx.records[candidate.global_id] = FindingRunRecord(
        global_id=candidate.global_id,
        chunk_id=candidate.chunk_id,
        bin_id=candidate.bin_id,
        status="completed",
        attempts=1,
        retrieved_chunk_count=len(bundle.chunks),
        taint_path_count=len(report.taint_paths),
    )


def _retrieval_bundle_to_json(bundle: RetrievalBundle) -> str:
    import json

    return json.dumps(
        {
            "global_id": bundle.global_id,
            "chunks": [dataclasses.asdict(c) for c in bundle.chunks],
        },
        indent=2,
    )


def _write_json(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


async def _worker(queue: FindingQueue, ctx: _RunContext) -> None:
    async for item in queue:
        try:
            await _process_one(item.candidate, ctx=ctx)
        except (QueryPlannerUnavailableError, TaintAnalystUnavailableError) as exc:
            logger.warning(
                "finding %s failed (attempt %d): %s",
                item.candidate.global_id,
                item.attempt + 1,
                exc,
            )
            ctx.records[item.candidate.global_id] = FindingRunRecord(
                global_id=item.candidate.global_id,
                chunk_id=item.candidate.chunk_id,
                bin_id=item.candidate.bin_id,
                status="failed",
                attempts=item.attempt + 1,
                error=str(exc),
            )
            await queue.nack(item)
        except Exception as exc:  # noqa: BLE001 - unknown per-item failures must not crash the pool
            logger.warning(
                "finding %s failed (attempt %d): %s",
                item.candidate.global_id,
                item.attempt + 1,
                exc,
            )
            ctx.records[item.candidate.global_id] = FindingRunRecord(
                global_id=item.candidate.global_id,
                chunk_id=item.candidate.chunk_id,
                bin_id=item.candidate.bin_id,
                status="failed",
                attempts=item.attempt + 1,
                error=str(exc),
            )
            await queue.nack(item)
        else:
            queue.ack(item)


async def run_queue(
    *,
    db_subfolder: Path,
    settings: Settings | None = None,
    decisions: frozenset = DEFAULT_DECISIONS,
    only_global_ids: frozenset[str] | None = None,
    run_id: str | None = None,
) -> Stage4RunSummary:
    """Component 6's entry point: discovers Stage 3 findings via
    `sink_index.discover_sink_candidates`, then runs C3->C4->C5 for each
    through a bounded worker pool, persisting every stage's output under
    `layout.py`'s paths and writing `stage4_summary.json` itself (mirrors
    `chunk_queue.run_queue`'s "written by the orchestrator function"
    precedent).

    Raises `Stage4InputError`/`VectorStoreUnavailableError` up front if the
    Stage 3 findings directory or the local Chroma collection isn't usable
    — fail fast before spawning any worker, per this stage's `errors.py`
    convention.
    """
    settings = settings or get_settings()
    run_id = run_id or uuid.uuid4().hex[:12]
    started_at = datetime.now(UTC)

    stage3_dir = db_subfolder / "stage3"
    if not (stage3_dir / "findings").is_dir():
        raise Stage4InputError(
            f"No Stage 3 findings directory at {stage3_dir / 'findings'} — run "
            "`fw-analyze ... --analyze` first."
        )

    candidates = discover_sink_candidates(stage3_dir, decisions=decisions)
    if only_global_ids is not None:
        candidates = [c for c in candidates if c.global_id in only_global_ids]

    stage4_dir_ = layout.stage4_dir(db_subfolder)
    if not candidates:
        summary = Stage4RunSummary(
            run_id=run_id,
            status="no_targets",
            db_subfolder=str(db_subfolder),
            embedding_model=settings.stage4_embedding_model,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )
        _write_summary(stage4_dir_, summary)
        return summary

    collection = load_local_collection(
        layout.chroma_dir(stage4_dir_), collection_name=settings.stage4_chroma_collection_name
    )
    embedder = load_embedder(settings=settings)

    ctx = _RunContext(
        settings=settings, stage4_dir=stage4_dir_, collection=collection, embedder=embedder
    )
    queue = FindingQueue(
        maxsize=settings.stage4_queue_maxsize,
        workers=settings.stage4_workers,
        max_attempts=settings.stage4_queue_max_attempts,
    )

    async def _produce() -> None:
        try:
            for candidate in candidates:
                await queue.put(candidate)
        finally:
            await queue.close()

    producer_task = asyncio.create_task(_produce())
    worker_tasks = [
        asyncio.create_task(_worker(queue, ctx)) for _ in range(settings.stage4_workers)
    ]
    await producer_task
    await asyncio.gather(*worker_tasks)

    finished_at = datetime.now(UTC)
    records = list(ctx.records.values())
    summary = Stage4RunSummary(
        run_id=run_id,
        status="completed",
        db_subfolder=str(db_subfolder),
        query_planner_model=_model_label(settings.stage4_query_planner_model),
        taint_analyst_model=_model_label(settings.stage4_taint_analyst_model),
        embedding_model=settings.stage4_embedding_model,
        findings=records,
        total_findings=len(records),
        total_completed=sum(1 for r in records if r.status == "completed"),
        total_failed=sum(1 for r in records if r.status == "failed"),
        started_at=started_at,
        finished_at=finished_at,
    )
    _write_summary(stage4_dir_, summary)
    return summary


def _model_label(override: str | None) -> str:
    return override or "(tier default)"


def _write_summary(stage4_dir_: Path, summary: Stage4RunSummary) -> None:
    """Best-effort write — matches `chunk_queue._write_summary`'s
    discipline: a write failure is recoverable (the caller already has the
    in-memory summary), not a reason to fail the whole run."""
    try:
        stage4_dir_.mkdir(parents=True, exist_ok=True)
        layout.stage4_summary_path(stage4_dir_).write_text(
            summary.model_dump_json(indent=2), encoding="utf-8"
        )
    except OSError:
        pass


__all__ = ["FindingQueue", "run_queue"]
