"""CLI entry point for Stage 3 analysis.

Registered as the `fw-analyze` console script (see pyproject.toml). Usage:

    fw-analyze path/to/stage1_summary.json [--only PATH ...] [--debug]
        [--debug-chunks] [--chunk-lines N] [--queue] [--run-id ID]

`ingestion_report.json` is always written by `ingest()` itself regardless
of any debug flag — it's the machine-readable hand-off a future Component 2
needs every run, not a debug artifact. `--debug` and `--debug-chunks` are
two INDEPENDENT flags, each purely for manual testing/verification, each
either may be passed alone or together:

* `--debug` makes `ingest()` write a verbatim copy of every resolved
  `Target`'s source under `<db_subfolder>/stage3/debug/<bin_id>.c` (Step
  1's file-resolution check) and, if the `stage3` extra is installed,
  Step 2's function-only extraction under `<bin_id>.cleaned.c`. See
  `fw_audit.stage3_analysis.ingest._write_debug_sources`/
  `_write_cleaned_debug_sources`.
* `--debug-chunks` makes `ingest()` chunk every resolved `Target`'s
  function-only extraction (Step 3's `chunk.strategy.chunk_source`) and
  write one file per chunk under `<db_subfolder>/stage3/chunks/
  <chunk_id>.c`. See `fw_audit.stage3_analysis.ingest.
  _write_chunk_debug_sources`.

`--chunk-lines` sets `Settings.stage3_chunk_lines`, the soft per-chunk
line-count target `chunk_source` accumulates against (default:
`FWA_STAGE3_CHUNK_LINES` / 1000) — exercised via `--debug-chunks` or a
direct `chunk_source()` call; `ingest()`'s default (no-flags) path never
computes chunks, so passing `--chunk-lines` alone has no visible effect.

`--queue` runs Step 4 (`chunk_queue.run_queue()`) after `ingest()`: chunks
every resolved target, persists each chunk to `<db_subfolder>/stage3/
chunks/<chunk_id>.c` (the queue's own source of truth — unconditional,
unlike `--debug-chunks`'s manual dump), drains them through an in-process
`asyncio.Queue` with `Settings.stage3_queue_workers` concurrent consumers,
and writes `<db_subfolder>/stage3/stage3_summary.json`. Uses a no-op
placeholder consumer — proves the queue/backpressure/retry/shutdown
mechanism works, does no actual vulnerability analysis. Use `--analyze`
instead to run Component 2's real LLM consumer.

`--analyze` (Component 2) implies `--queue`'s plumbing but swaps the no-op
consumer for `agent.orchestrator.run_analysis()`'s real one: each chunk is
sent to the analyst LLM (`AgentRole.STAGE3_VULN_ANALYST` — Anthropic Claude
Sonnet by default), validated against `common.findings.AnalysisReport`, and
persisted to `<db_subfolder>/stage3/findings/<chunk_id>.json`, with a run
summary at `<db_subfolder>/stage3/analysis_summary.json`. `--model
provider:model` overrides which model is used for this run only (e.g.
`--model ollama:qwen2.5-coder:1.5b` for an offline smoke test). `main()`
stays synchronous except for the queue/analysis bridge, a single
`asyncio.run(...)` call.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from fw_audit.config.settings import get_settings
from fw_audit.observability import configure_tracing, flush_traces
from fw_audit.stage3_analysis import layout
from fw_audit.stage3_analysis.agent.orchestrator import AnalystModelUnavailableError, run_analysis
from fw_audit.stage3_analysis.chunk_queue import run_queue
from fw_audit.stage3_analysis.errors import Stage3InputError
from fw_audit.stage3_analysis.ingest import ingest
from fw_audit.stage3_analysis.models import IngestionReport

logger = logging.getLogger("fw_audit.stage3_analysis")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fw-analyze",
        description=(
            "Stage 3: whitelist Stage 2's decompiled binaries, clean their C for "
            "LLM consumption, chunk it, and queue it for the agent worker pool."
        ),
    )
    parser.add_argument(
        "stage1_summary_path",
        type=str,
        help="Path to stage1_summary.json (written by `fw-ingest`).",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Restrict analysis to binaries whose requested path, resolved rootfs "
            "path, or an alias matches PATH. Repeatable."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Testing/verification only: write a verbatim copy of every resolved "
            "target's source to <db_subfolder>/stage3/debug/<bin_id>.c, plus a "
            "function-only cleaned copy. Independent of --debug-chunks."
        ),
    )
    parser.add_argument(
        "--debug-chunks",
        action="store_true",
        help=(
            "Testing/verification only: chunk each target's function-only "
            "extraction and write one file per chunk to <db_subfolder>/"
            "stage3/chunks/<chunk_id>.c. Independent of --debug (which "
            "dumps raw/cleaned source, never chunk payloads)."
        ),
    )
    parser.add_argument(
        "--chunk-lines",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Soft line-count limit per chunk (default: FWA_STAGE3_CHUNK_LINES / "
            "1000), consumed by chunk_source. Exercised via --debug-chunks."
        ),
    )
    parser.add_argument(
        "--queue",
        action="store_true",
        help=(
            "Run Step 4: chunk every resolved target, persist each chunk to "
            "<db_subfolder>/stage3/chunks/<chunk_id>.c, drain them through an "
            "asyncio.Queue with a no-op placeholder consumer, and write "
            "<db_subfolder>/stage3/stage3_summary.json. Use --analyze for "
            "real LLM-backed vulnerability analysis instead."
        ),
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help=(
            "Run Component 2: like --queue, but each chunk is sent to the "
            "analyst LLM and the result written to <db_subfolder>/stage3/"
            "findings/<chunk_id>.json, with a run summary at "
            "<db_subfolder>/stage3/analysis_summary.json. Implies --queue."
        ),
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        metavar="PROVIDER:MODEL",
        help=(
            "Override the analyst model for this run only, e.g. "
            "'anthropic:claude-sonnet-4-5' or 'ollama:qwen2.5-coder:1.5b' "
            "(offline testing). Only meaningful with --analyze."
        ),
    )
    parser.add_argument(
        "--run-id", type=str, default=None, help="Run identifier for logging (default: random)."
    )
    parser.add_argument(
        "--trace",
        dest="trace",
        action="store_true",
        default=None,
        help=(
            "Force-enable LangSmith tracing for this run, overriding "
            "LANGSMITH_TRACING. Requires LANGSMITH_API_KEY to actually upload."
        ),
    )
    parser.add_argument(
        "--no-trace",
        dest="trace",
        action="store_false",
        help="Force-disable LangSmith tracing for this run, overriding LANGSMITH_TRACING.",
    )
    return parser.parse_args(argv)


def _print_report(report: IngestionReport) -> None:
    print(f"Decompiled tree: {report.decompiled_tree_dir}")

    if report.targets:
        print(f"\nTargets ({len(report.targets)}):")
        for t in report.targets:
            via = (
                f"  (requested: {t.requested_path})" if t.requested_path != t.rootfs_path else ""
            )
            print(
                f"  {t.rootfs_path}  [{t.status.value}]  {t.size_bytes:,} bytes  "
                f"{t.function_count} functions{via}"
            )
            if t.aliases:
                print(f"      aliases: {', '.join(t.aliases)}")

    if report.skipped:
        print(f"\nSkipped ({len(report.skipped)}):")
        for s in report.skipped:
            detail = f"  ({s.detail})" if s.detail else ""
            print(f"  {s.requested_path}  [{s.reason}]{detail}")

    if report.orphans:
        print(f"\nOrphans — present in the mirror tree, not whitelisted ({len(report.orphans)}):")
        for o in report.orphans:
            print(f"  {o}")

    if report.warnings:
        print(f"\nWarnings ({len(report.warnings)}):")
        for w in report.warnings:
            print(f"  - {w}")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=get_settings().log_level, format="%(levelname)s %(name)s: %(message)s"
    )
    args = _parse_args(argv)

    stage1_summary_path = Path(args.stage1_summary_path)
    if not stage1_summary_path.is_file():
        print(
            f"error: stage1_summary_path does not exist or is not a file: {stage1_summary_path}",
            file=sys.stderr,
        )
        return 2

    settings = get_settings()
    if args.debug:
        settings = settings.model_copy(update={"stage3_debug_dump": True})
    if args.debug_chunks:
        settings = settings.model_copy(update={"stage3_chunk_debug_dump": True})
    if args.chunk_lines is not None:
        settings = settings.model_copy(update={"stage3_chunk_lines": args.chunk_lines})
    if args.model is not None:
        settings = settings.model_copy(update={"stage3_analyst_model": args.model})
    if args.trace is not None:
        settings = settings.model_copy(update={"langsmith_tracing": args.trace})
    configure_tracing(settings)

    try:
        report = ingest(
            stage1_summary_path=stage1_summary_path,
            only=tuple(args.only),
            settings=settings,
        )
    except Stage3InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    _print_report(report)
    stage3_dir = layout.stage3_dir(report.db_subfolder)
    print(f"\nMachine-readable report: {stage3_dir}/ingestion_report.json")

    if args.debug and report.targets:
        print(f"Debug source dump: {layout.debug_dir(stage3_dir)}/<bin_id>.c")
    if args.debug_chunks and report.targets:
        print(f"Chunk debug dump: {layout.chunks_dir(stage3_dir)}/<chunk_id>.c")

    if args.analyze:
        try:
            analysis_summary, queue_summary = asyncio.run(
                run_analysis(report, settings=settings, run_id=args.run_id)
            )
        except AnalystModelUnavailableError as exc:
            print(f"error: analyst model unavailable: {exc}", file=sys.stderr)
            return 2
        print(
            f"\nQueue: {queue_summary.total_chunks} chunks, {queue_summary.total_acked} acked, "
            f"{queue_summary.total_failed} failed"
        )
        print(f"Stage 3 summary: {layout.stage3_summary_path(stage3_dir)}")
        print(
            f"Analysis ({analysis_summary.model}): {analysis_summary.total_analyzed} analyzed, "
            f"{analysis_summary.total_failed} failed, {analysis_summary.total_skipped} skipped, "
            f"{analysis_summary.total_findings} findings"
        )
        print(f"Findings: {layout.findings_dir(stage3_dir)}/<chunk_id>.json")
        print(f"Analysis summary: {layout.analysis_summary_path(stage3_dir)}")
    elif args.queue:
        summary = asyncio.run(run_queue(report, settings=settings, run_id=args.run_id))
        print(
            f"\nQueue: {summary.total_chunks} chunks, {summary.total_acked} acked, "
            f"{summary.total_failed} failed"
        )
        print(f"Stage 3 summary: {layout.stage3_summary_path(stage3_dir)}")

    flush_traces()
    return 1 if not report.targets else 0


if __name__ == "__main__":
    raise SystemExit(main())
