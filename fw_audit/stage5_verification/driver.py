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
    TrackResult,
    VerificationReport,
    VerificationRunSummary,
    VerificationVerdict,
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
from fw_audit.stage5_verification.fvvw.hitl import (
    HitlAction,
    HitlRequest,
    Prompter,
    prompt_for_track,
    terminal_prompter,
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


def _joern_only_budget_exhausted(report: VerificationReport, settings: Settings) -> bool:
    """The `--joern-only` path's own budget-exhaustion check — mirrors
    `fvvw.static_track.run_static_track`'s tagging exactly (verdict is
    ERROR/INCONCLUSIVE AND every iteration was used), but computed here
    directly against a `VerificationReport` (whose `evidence` field is a
    plain `str`, not the fork-join's `dict` — there's no `budget_exhausted`
    field to tag on this schema, so this is re-derived at the point HITL
    needs it instead)."""
    return (
        report.verdict in (VerificationVerdict.ERROR, VerificationVerdict.INCONCLUSIVE)
        and len(report.attempts) >= settings.stage5_max_agent_iterations
    )


async def _run_hitl_joern_only(
    report: VerificationReport,
    *,
    candidate: VerificationCandidate,
    db_subfolder: Path,
    settings: Settings,
    prompter: Prompter,
) -> VerificationReport:
    """HITL for the `--joern-only` static-only path — offers only the
    static actions (retry/override_plan is not meaningful here since there
    is no `StrategyPlan`/`StaticPlan` in this code path at all; `inject`
    reuses `fvvw.static_track.run_injected_static_script` against the same
    workspace `verify_candidate` already built; `force_verdict` substitutes
    a verdict directly). Bounded by `stage5_hitl_max_rounds`, same as the
    fork-join's own loop."""
    from fw_audit.stage5_verification.fvvw.static_track import run_injected_static_script
    from fw_audit.stage5_verification.tools.joern_tool import joern_executor

    stage5_dir_ = layout.stage5_dir(db_subfolder)
    workspace_dir_ = layout.workspace_dir(stage5_dir_, candidate.global_id)
    round_number = 0

    while (
        _joern_only_budget_exhausted(report, settings)
        and round_number < settings.stage5_hitl_max_rounds
    ):
        round_number += 1
        req = HitlRequest(
            global_id=candidate.global_id,
            track="static",
            result=_report_as_track_result(report),
            plan=None,
            target=None,
            recent_commands=[],
            round_number=round_number,
        )
        decision = await prompt_for_track(req, prompter=prompter)

        if decision.action == HitlAction.SKIP:
            break
        if decision.action == HitlAction.FORCE_VERDICT:
            forced = decision.forced_verdict or VerificationVerdict.INCONCLUSIVE
            report = report.model_copy(
                update={"verdict": forced, "summary": decision.rationale or report.summary}
            )
            break
        if decision.action == HitlAction.INJECT:
            executor = joern_executor(settings)
            result = await run_injected_static_script(
                candidate,
                decision.injected_payload,
                workspace_dir=workspace_dir_,
                executor=executor,
                settings=settings,
            )
            report = report.model_copy(update={"verdict": result.verdict})
        elif decision.action == HitlAction.RETRY:
            extra = decision.extra_iterations or settings.stage5_hitl_extra_iterations
            retry_settings = settings.model_copy(
                update={"stage5_max_agent_iterations": settings.stage5_max_agent_iterations + extra}
            )
            report = await verify_candidate(
                candidate, db_subfolder=db_subfolder, settings=retry_settings
            )
        # override_plan is not offered on --joern-only (see docstring), so
        # any other action is treated as skip.

    return report


def _report_as_track_result(report: VerificationReport) -> TrackResult:
    """Adapt a `VerificationReport` into the bare shape `HitlRequest.result`
    needs (`verdict`/`proved_hypothesis`/`iters_used` are all this path's
    prompter reads) — a real `TrackResult`, since `fvvw.hitl`'s helpers
    already expect one."""
    if report.verdict == VerificationVerdict.CONFIRMED:
        proved = "A"
    elif report.verdict == VerificationVerdict.REFUTED:
        proved = "B"
    else:
        proved = "none"
    return TrackResult(
        verdict=report.verdict,
        proved_hypothesis=proved,
        evidence={},
        iters_used=len(report.attempts),
    )


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
        if ctx.settings.stage5_hitl_mode == "prompt" and _joern_only_budget_exhausted(
            report, ctx.settings
        ):
            report = await _run_hitl_joern_only(
                report,
                candidate=candidate,
                db_subfolder=ctx.db_subfolder,
                settings=ctx.settings,
                prompter=terminal_prompter,
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
