"""The fork-join's own driver: `run_fvvw_queue()` — loop over Stage 3
candidates, run `fvvw.graph.run_fvvw`, compose the disclosure report via
`fvvw.report.write_report`, persist `FVVWReport` JSON + Markdown.

Deliberately a SEPARATE module from `stage5_verification.driver` (the
static-only `run_queue`), not an extension of it — `run_queue`/`CandidateQueue`/
`_process_one`/`_worker` there are untouched, so `fw-verify run --joern-only`
keeps working exactly as it did before this package existed. The async
worker-pool shape here mirrors that module closely (same bounded
`asyncio.Queue`, ack/nack-with-bounded-retry, `trace_context` nesting
discipline) since both are draining the SAME `VerificationCandidate` list
from `candidate_index.discover_candidates` — but they persist to disjoint
output subtrees (`stage5/fvvw/*` vs `stage5/verifications/`+`stage5/reports/`)
and never share mutable state.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fw_audit.common.verification import CandidateRunRecord, FVVWReport, VerificationRunSummary
from fw_audit.config.settings import Settings, get_settings
from fw_audit.observability import span, trace_context
from fw_audit.stage5_verification import layout
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
from fw_audit.stage5_verification.fvvw.graph import run_fvvw
from fw_audit.stage5_verification.fvvw.report import write_report

logger = logging.getLogger("fw_audit.stage5_verification.fvvw")

_SENTINEL = None


@dataclasses.dataclass(frozen=True)
class _WorkItem:
    candidate: VerificationCandidate
    attempt: int = 0


class FVVWCandidateQueue:
    """Bounded `asyncio.Queue[_WorkItem | None]` — same ack/nack/close
    shape as `stage5_verification.driver.CandidateQueue`, kept as its own
    class (not reused directly) so this module has zero import coupling
    to `driver.py`'s internals beyond the shared, already-public
    `VerificationCandidate`/`discover_candidates`."""

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

    def __aiter__(self) -> FVVWCandidateQueue:
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
class _FVVWRunContext:
    settings: Settings
    db_subfolder: Path
    stage5_dir: Path
    records: dict[str, CandidateRunRecord] = dataclasses.field(default_factory=dict)


async def _process_one_fvvw(candidate: VerificationCandidate, *, ctx: _FVVWRunContext) -> None:
    """Run the full fork-join for one candidate, compose + persist its
    report, update the run-level bookkeeping record. Mirrors
    `stage5_verification.driver._process_one`'s trace_context/span nesting
    exactly (entered PER-TASK, never once around the whole pool — see that
    function's own comment for why)."""
    started_at = datetime.now(UTC)
    with trace_context(
        stage="5",
        global_id=candidate.global_id,
        chunk_id=candidate.chunk_id,
        bin_id=candidate.bin_id,
    ), span(
        "stage5.fvvw.candidate",
        inputs={"global_id": candidate.global_id},
    ) as run:
        outcome = await run_fvvw(
            candidate, db_subfolder=ctx.db_subfolder, settings=ctx.settings
        )
        deps = outcome["deps"]
        report_markdown = await write_report(
            candidate=candidate,
            finding=candidate.finding,
            static_result=outcome["static_result"],
            dynamic_result=outcome["dynamic_result"],
            agreement=outcome["agreement"],
            mechanism_confidence=outcome["mechanism_confidence"].value,
            reachability_confidence=outcome["reachability_confidence"].value,
            residual_unknowns=outcome["residual_unknowns"],
            dynamic_gdb_transcript=outcome["dynamic_gdb_transcript"],
            llm=deps.report_llm,
            settings=ctx.settings,
        )
        if run is not None:
            run.end(
                outputs={
                    "agreement": outcome["agreement"].value,
                    "mechanism_confidence": outcome["mechanism_confidence"].value,
                }
            )

    command_log_paths = {
        track: str(path)
        for track, path in (
            ("static", deps.static_command_log.path),
            ("dynamic", deps.dynamic_command_log.path),
        )
        if path is not None
    }
    report = FVVWReport(
        global_id=candidate.global_id,
        bin_id=candidate.bin_id,
        static_result=outcome["static_result"],
        dynamic_result=outcome["dynamic_result"],
        agreement=outcome["agreement"],
        mechanism_confidence=outcome["mechanism_confidence"],
        reachability_confidence=outcome["reachability_confidence"],
        residual_unknowns=outcome["residual_unknowns"],
        report_markdown=report_markdown,
        guard_logs=outcome["guard_logs"],
        dynamic_gdb_transcript=outcome["dynamic_gdb_transcript"],
        crosscheck_evidence=outcome["crosscheck_evidence"],
        command_log_paths=command_log_paths,
        started_at=started_at,
        finished_at=datetime.now(UTC),
    )

    fvvw_dir_ = layout.fvvw_dir(ctx.stage5_dir)
    reports_dir_ = layout.fvvw_reports_dir(fvvw_dir_)
    _write_json(
        reports_dir_ / layout.fvvw_report_json_filename(candidate.global_id),
        report.model_dump_json(indent=2),
    )
    _write_text(
        reports_dir_ / layout.fvvw_report_markdown_filename(candidate.global_id),
        report_markdown,
    )

    if not ctx.settings.stage5_keep_workspace:
        shutil.rmtree(deps.static_workspace_dir, ignore_errors=True)
        shutil.rmtree(deps.dynamic_workspace_dir, ignore_errors=True)

    # combined_verdict mirrors the mechanism axis for a single-string
    # summary field on CandidateRunRecord (which predates the two-axis
    # schema) — the FULL two-axis result is in the persisted FVVWReport;
    # this is only a compact bookkeeping label for stage5_summary-style
    # tallies.
    ctx.records[candidate.global_id] = CandidateRunRecord(
        global_id=candidate.global_id,
        chunk_id=candidate.chunk_id,
        bin_id=candidate.bin_id,
        status="verified",
        attempts=1,
        verdict=outcome["mechanism_confidence"].value,
    )


def _write_json(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


async def _worker(queue: FVVWCandidateQueue, ctx: _FVVWRunContext) -> None:
    async for item in queue:
        try:
            await _process_one_fvvw(item.candidate, ctx=ctx)
        except (Stage5InputError, SandboxUnavailableError, VerifierModelUnavailableError) as exc:
            logger.warning(
                "fvvw candidate %s failed (attempt %d): %s",
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
                "fvvw candidate %s failed (attempt %d): %s",
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


async def run_fvvw_queue(
    *,
    db_subfolder: Path,
    settings: Settings | None = None,
    decisions: frozenset = DEFAULT_DECISIONS,
    only_global_ids: frozenset[str] | None = None,
    run_id: str | None = None,
) -> VerificationRunSummary:
    """The fork-join's entry point — same discovery/candidate-filtering
    contract as `stage5_verification.driver.run_queue`, but drives
    `fvvw.graph.run_fvvw` for each candidate and writes `stage5/fvvw/*`
    instead of `stage5/verifications/`+`stage5/reports/`. Reuses
    `VerificationRunSummary` as its return type (same shape the static-only
    path already returns) so `runner.py`'s `_cmd_run` can print either
    result identically.
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

    ctx = _FVVWRunContext(settings=settings, db_subfolder=db_subfolder, stage5_dir=stage5_dir_)
    queue = FVVWCandidateQueue(
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
    try:
        stage5_dir_.mkdir(parents=True, exist_ok=True)
        layout.fvvw_summary_path(stage5_dir_).write_text(
            summary.model_dump_json(indent=2), encoding="utf-8"
        )
    except OSError:
        pass


__all__ = ["FVVWCandidateQueue", "run_fvvw_queue"]
