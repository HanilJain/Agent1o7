"""Stage 5's thin driver: loop over Stage 3 candidates, verify -> persist.

Async worker-pool shape mirrors `stage4_rag.driver` (bounded `asyncio.Queue`,
ack/nack with bounded retry, `join()`-before-sentinels shutdown) — adapted
for `VerificationCandidate` items, which (like Stage 4's `SinkCandidate`)
are already fully in memory from `candidate_index.discover_candidates`, so
there's no disk-backed-handle indirection to replicate here either.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fw_audit.common.verification import (
    CandidateRunRecord,
    VerificationReport,
    VerificationRunSummary,
)
from fw_audit.config.settings import Settings, get_settings
from fw_audit.observability import span, trace_context
from fw_audit.stage5_verification import layout
from fw_audit.stage5_verification.agent.verifier import verify_candidate
from fw_audit.stage5_verification.candidate_index import (
    DEFAULT_DECISIONS,
    VerificationCandidate,
    discover_candidates,
)
from fw_audit.stage5_verification.errors import (
    SandboxUnavailableError,
    Stage5InputError,
    VerifierModelUnavailableError,
)
from fw_audit.stage5_verification.report_writer import render_report

logger = logging.getLogger("fw_audit.stage5_verification")

_SENTINEL = None


@dataclasses.dataclass(frozen=True)
class _WorkItem:
    candidate: VerificationCandidate
    attempt: int = 0


class CandidateQueue:
    """Bounded `asyncio.Queue[_WorkItem | None]` — same ack/nack/close shape
    as `stage4_rag.driver.FindingQueue`."""

    def __init__(self, *, maxsize: int, workers: int, max_attempts: int) -> None:
        self._queue: asyncio.Queue[_WorkItem | None] = asyncio.Queue(maxsize=maxsize)
        self._workers = workers
        self._max_attempts = max_attempts
        self.produced: list[_WorkItem] = []
        self.acked: list[_WorkItem] = []
        self.failed: list[_WorkItem] = []

    async def put(self, candidate: VerificationCandidate) -> None:
        item = _WorkItem(candidate=candidate)
        self.produced.append(item)
        await self._queue.put(item)

    def __aiter__(self) -> CandidateQueue:
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
    db_subfolder: Path
    stage5_dir: Path
    records: dict[str, CandidateRunRecord] = dataclasses.field(default_factory=dict)


async def _process_one(candidate: VerificationCandidate, *, ctx: _RunContext) -> None:
    """Verify one candidate, persisting the JSON report and Markdown
    explanation, then updating the run-level bookkeeping record."""
    # Entered here (not once around the whole worker pool): _worker fans
    # out via asyncio.create_task, and context set inside one task's
    # _process_one must not leak into a sibling task verifying a different
    # candidate concurrently — see fw_audit.observability.context's
    # docstring.
    with trace_context(
        stage="5",
        global_id=candidate.global_id,
        chunk_id=candidate.chunk_id,
        bin_id=candidate.bin_id,
    ), span(
        "stage5.candidate",
        inputs={"global_id": candidate.global_id},
    ) as run:
        report: VerificationReport = await verify_candidate(
            candidate, db_subfolder=ctx.db_subfolder, settings=ctx.settings
        )
        if run is not None:
            run.end(outputs={"verdict": report.verdict.value})

    _write_json(
        layout.verifications_dir(ctx.stage5_dir)
        / layout.verification_filename(candidate.global_id),
        report.model_dump_json(indent=2),
    )
    _write_text(
        layout.reports_dir(ctx.stage5_dir) / layout.report_filename(candidate.global_id),
        render_report(report, finding=candidate.finding),
    )

    if not ctx.settings.stage5_keep_workspace:
        workspace = layout.workspace_dir(ctx.stage5_dir, candidate.global_id)
        shutil.rmtree(workspace, ignore_errors=True)

    ctx.records[candidate.global_id] = CandidateRunRecord(
        global_id=candidate.global_id,
        chunk_id=candidate.chunk_id,
        bin_id=candidate.bin_id,
        status="verified",
        attempts=1,
        verdict=report.verdict.value,
    )


def _write_json(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


async def _worker(queue: CandidateQueue, ctx: _RunContext) -> None:
    async for item in queue:
        try:
            await _process_one(item.candidate, ctx=ctx)
        except (SandboxUnavailableError, VerifierModelUnavailableError) as exc:
            logger.warning(
                "candidate %s failed (attempt %d): %s",
                item.candidate.global_id,
                item.attempt + 1,
                exc,
            )
            ctx.records[item.candidate.global_id] = CandidateRunRecord(
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
                "candidate %s failed (attempt %d): %s",
                item.candidate.global_id,
                item.attempt + 1,
                exc,
            )
            ctx.records[item.candidate.global_id] = CandidateRunRecord(
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
) -> VerificationRunSummary:
    """Stage 5's entry point: discovers Stage 3 candidates via
    `candidate_index.discover_candidates`, then verifies each through a
    bounded worker pool, persisting every candidate's JSON + Markdown
    report and writing `stage5_summary.json` itself.

    Raises `Stage5InputError` up front if Stage 3's findings or Stage 2's
    summary aren't usable — fail fast before spawning any worker, mirroring
    `stage4_rag.driver.run_queue`'s precedent.
    """
    settings = settings or get_settings()
    run_id = run_id or uuid.uuid4().hex[:12]
    started_at = datetime.now(UTC)

    stage3_findings_dir = db_subfolder / "stage3" / "findings"
    if not stage3_findings_dir.is_dir():
        raise Stage5InputError(
            f"No Stage 3 findings directory at {stage3_findings_dir} — run "
            "`fw-analyze ... --analyze` first."
        )

    candidates = discover_candidates(db_subfolder, decisions=decisions)
    if only_global_ids is not None:
        candidates = [c for c in candidates if c.global_id in only_global_ids]

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    if not candidates:
        summary = VerificationRunSummary(
            run_id=run_id,
            status="no_targets",
            db_subfolder=str(db_subfolder),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )
        _write_summary(stage5_dir_, summary)
        return summary

    ctx = _RunContext(settings=settings, db_subfolder=db_subfolder, stage5_dir=stage5_dir_)
    queue = CandidateQueue(
        maxsize=settings.stage5_queue_maxsize,
        workers=settings.stage5_workers,
        max_attempts=settings.stage5_queue_max_attempts,
    )

    async def _produce() -> None:
        try:
            for candidate in candidates:
                await queue.put(candidate)
        finally:
            await queue.close()

    # Entered around the create_task fan-out so every producer/worker task
    # (each copies the context at creation time) inherits run_id — layered
    # under by _process_one's own per-candidate chunk_id/bin_id/global_id.
    with trace_context(stage="5", run_id=run_id):
        producer_task = asyncio.create_task(_produce())
        worker_tasks = [
            asyncio.create_task(_worker(queue, ctx)) for _ in range(settings.stage5_workers)
        ]
        await producer_task
        await asyncio.gather(*worker_tasks)

    finished_at = datetime.now(UTC)
    records = list(ctx.records.values())
    verdicts_by_type: dict[str, int] = {}
    for r in records:
        if r.verdict:
            verdicts_by_type[r.verdict] = verdicts_by_type.get(r.verdict, 0) + 1

    summary = VerificationRunSummary(
        run_id=run_id,
        status="completed",
        db_subfolder=str(db_subfolder),
        model=_model_label(settings.stage5_verifier_model),
        candidates=records,
        total_candidates=len(records),
        total_verified=sum(1 for r in records if r.status == "verified"),
        total_failed=sum(1 for r in records if r.status == "failed"),
        verdicts_by_type=verdicts_by_type,
        started_at=started_at,
        finished_at=finished_at,
    )
    _write_summary(stage5_dir_, summary)
    return summary


def _model_label(override: str | None) -> str:
    return override or "(tier default)"


def _write_summary(stage5_dir_: Path, summary: VerificationRunSummary) -> None:
    """Best-effort write — matches `chunk_queue._write_summary`'s
    discipline: a write failure is recoverable (the caller already has the
    in-memory summary), not a reason to fail the whole run."""
    try:
        stage5_dir_.mkdir(parents=True, exist_ok=True)
        layout.stage5_summary_path(stage5_dir_).write_text(
            summary.model_dump_json(indent=2), encoding="utf-8"
        )
    except OSError:
        pass


__all__ = ["CandidateQueue", "run_queue"]
