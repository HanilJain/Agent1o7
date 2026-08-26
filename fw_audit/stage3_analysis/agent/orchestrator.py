"""Stage 3 Component 2's entry point: `run_analysis()`.

Resolves the analyst model up front (fail fast on a missing credential/SDK,
before spawning any worker), builds an `AnalysisConsumer`, and delegates
everything else — the worker pool, backpressure, ack/nack retry, sentinel
shutdown — to `chunk_queue.run_queue()` UNCHANGED. This module adds no
concurrency machinery of its own; it only supplies the `consumer` Component
1 was always designed to accept.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fw_audit.common.findings import AnalysisReport, AnalysisRunSummary, ChunkAnalysisRecord
from fw_audit.common.schemas import Stage3Summary
from fw_audit.config.llm_config import AgentRole, resolve_usable_spec
from fw_audit.config.settings import Settings
from fw_audit.observability import trace_context
from fw_audit.stage3_analysis import layout
from fw_audit.stage3_analysis.agent.consumer import AnalysisConsumer
from fw_audit.stage3_analysis.chunk_queue import run_queue
from fw_audit.stage3_analysis.models import IngestionReport

logger = logging.getLogger("fw_audit.stage3_analysis.agent")


class AnalystModelUnavailableError(RuntimeError):
    """Raised before any chunk is processed: the analyst model/credential
    couldn't be resolved at all. Distinct from a per-chunk
    `AnalysisUnavailableError` (which the queue retries) — this means the
    whole run cannot proceed, so it is raised rather than folded into the
    summary as a per-chunk failure."""


async def run_analysis(
    report: IngestionReport,
    *,
    settings: Settings,
    run_id: str | None = None,
) -> tuple[AnalysisRunSummary, Stage3Summary]:
    """Run Stage 3 Component 2 end to end: ingest's `IngestionReport` in,
    chunk -> queue -> LLM-analyze every chunk, `AnalysisRunSummary` +
    `Stage3Summary` out (both are also persisted to disk).

    Raises `AnalystModelUnavailableError` if the configured analyst model
    can't be resolved (missing credential, missing provider SDK) — checked
    up front so a misconfigured run fails immediately rather than after
    the producer has already started chunking every target. This check
    honors `Settings.use_local_model`'s API/local preference and its
    automatic opposite-mode fallback (see `llm_config.resolve_usable_spec`)
    — it only raises if NEITHER mode is usable, matching what the actual
    per-chunk analyst calls (`agent.analyst.analyze_chunk` ->
    `get_llm_for_agent`) will do.
    """
    run_id = run_id or uuid.uuid4().hex[:12]
    started_at = datetime.now(UTC)

    try:
        spec = resolve_usable_spec(AgentRole.STAGE3_VULN_ANALYST, settings=settings)
    except ValueError as exc:
        raise AnalystModelUnavailableError(str(exc)) from exc
    model_label = f"{spec.provider.value}:{spec.model}"

    consumer = AnalysisConsumer(db_subfolder=report.db_subfolder, settings=settings)

    # Entered here, around run_queue's own asyncio.create_task fan-out, so
    # every worker task (each copies the context at creation time) inherits
    # run_id/model — AnalysisConsumer.__call__ then layers per-chunk
    # chunk_id/bin_id on top, isolated per task. See
    # fw_audit.observability.context's docstring for why this can't instead
    # be set once inside a single worker.
    with trace_context(stage="3", run_id=run_id, model=model_label):
        stage3_summary: Stage3Summary = await run_queue(
            report, settings=settings, consumer=consumer, run_id=run_id
        )

    analysis_summary = _build_analysis_summary(
        report=report,
        stage3_summary=stage3_summary,
        records=consumer.records,
        run_id=run_id,
        model_label=model_label,
        started_at=started_at,
    )
    _write_analysis_summary(report.db_subfolder, analysis_summary)
    return analysis_summary, stage3_summary


def _build_analysis_summary(
    *,
    report: IngestionReport,
    stage3_summary: Stage3Summary,
    records: list[ChunkAnalysisRecord],
    run_id: str,
    model_label: str,
    started_at: datetime,
) -> AnalysisRunSummary:
    """Reconcile `AnalysisConsumer.records` (only ever appended to on
    SUCCESS or a deliberate skip — see `consumer.py`) against
    `Stage3Summary.chunks` (the queue's own final acked/failed
    determination) so a chunk that exhausted every retry attempt is
    recorded here too, as `failed`, without `AnalysisConsumer` needing to
    know anything about the queue's retry bookkeeping.
    """
    finished_at = datetime.now(UTC)
    by_chunk_id = {r.chunk_id: r for r in records}

    all_records: list[ChunkAnalysisRecord] = []
    for chunk_record in stage3_summary.chunks:
        existing = by_chunk_id.get(chunk_record.chunk_id)
        if existing is not None:
            all_records.append(existing)
        elif chunk_record.status == "failed":
            all_records.append(
                ChunkAnalysisRecord(
                    chunk_id=chunk_record.chunk_id,
                    bin_id=chunk_record.bin_id,
                    rootfs_path=chunk_record.rootfs_path,
                    status="failed",
                    attempts=chunk_record.attempts,
                    error="chunk exhausted all queue retry attempts",
                )
            )
        # else: acked in the queue but no consumer record and not
        # "failed" shouldn't happen in practice (the consumer always
        # appends a record before returning normally, which is what
        # produces an "acked" outcome) — silently omitted rather than
        # guessed at.

    total_findings = sum(r.finding_count for r in all_records)
    findings_by_decision: dict[str, int] = {}
    findings_by_confidence: dict[str, int] = {}
    for r in all_records:
        if r.status != "analyzed" or not r.findings_relpath:
            continue
        path = report.db_subfolder / r.findings_relpath
        try:
            parsed = AnalysisReport.model_validate_json(path.read_text(encoding="utf-8"))
        except OSError:
            continue
        for finding in parsed.findings:
            findings_by_decision[finding.decision.value] = (
                findings_by_decision.get(finding.decision.value, 0) + 1
            )
            findings_by_confidence[finding.confidence.value] = (
                findings_by_confidence.get(finding.confidence.value, 0) + 1
            )

    if not report.targets:
        status = "no_targets"
    elif stage3_summary.status == "stage3_input_unavailable":
        status = "stage3_input_unavailable"
    else:
        status = "completed"

    return AnalysisRunSummary(
        run_id=run_id,
        status=status,
        db_subfolder=str(report.db_subfolder),
        model=model_label,
        chunks=all_records,
        total_chunks=stage3_summary.total_chunks,
        total_analyzed=sum(1 for r in all_records if r.status == "analyzed"),
        total_failed=sum(1 for r in all_records if r.status == "failed"),
        total_skipped=sum(1 for r in all_records if r.status == "skipped_oversized"),
        total_findings=total_findings,
        findings_by_decision=findings_by_decision,
        findings_by_confidence=findings_by_confidence,
        warnings=list(stage3_summary.warnings),
        errors=list(stage3_summary.errors),
        started_at=started_at,
        finished_at=finished_at,
    )


def _write_analysis_summary(db_subfolder: Path, summary: AnalysisRunSummary) -> None:
    """Best-effort write, matching `chunk_queue._write_summary`'s
    discipline: a write failure is recoverable (the caller already has the
    in-memory summary), not a reason to fail the whole run."""
    stage3_dir = layout.stage3_dir(db_subfolder)
    try:
        stage3_dir.mkdir(parents=True, exist_ok=True)
        layout.analysis_summary_path(stage3_dir).write_text(
            summary.model_dump_json(indent=2), encoding="utf-8"
        )
    except OSError:
        pass
