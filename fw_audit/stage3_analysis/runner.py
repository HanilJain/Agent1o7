"""CLI entry point for Stage 3 analysis.

Registered as the `fw-analyze` console script (see pyproject.toml). Usage:

    fw-analyze path/to/stage1_summary.json [--only PATH ...] [--debug] [--run-id ID]

This session wires only Step 1 (ingestion & whitelisting). `ingestion_report.
json` is always written by `ingest()` itself regardless of `--debug` — it's
the machine-readable hand-off a future Component 2 needs every run, not a
debug artifact. `--debug` does something narrower, purely for manual
testing/verification: it makes `ingest()` also write a verbatim copy of
every resolved `Target`'s source under `<db_subfolder>/stage3/debug/
<bin_id>.c`, so you can inspect exactly which file Step 1 picked for each
binary without hunting through the mirror tree yourself. No console output
changes based on this flag — see `fw_audit.stage3_analysis.ingest.
_write_debug_sources` for the actual write. `--chunk-lines` is accepted and
threaded into `Settings` now so the CLI surface doesn't need to change
again once Step 3 lands, but does nothing yet — the help text says so.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from fw_audit.config.settings import get_settings
from fw_audit.stage3_analysis import layout
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
            "target's source to <db_subfolder>/stage3/debug/<bin_id>.c. Also "
            "reserved for Step 4's future on-disk chunk-payload dump."
        ),
    )
    parser.add_argument(
        "--chunk-lines",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Soft line-count limit per chunk (default: FWA_STAGE3_CHUNK_LINES / "
            "1000). Not yet implemented (Step 3) — accepted now so the CLI "
            "surface is stable once it is."
        ),
    )
    parser.add_argument(
        "--run-id", type=str, default=None, help="Run identifier for logging (default: random)."
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
    if args.chunk_lines is not None:
        settings = settings.model_copy(update={"stage3_chunk_lines": args.chunk_lines})

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
    stage3_dir = report.db_subfolder / "stage3"
    print(f"\nMachine-readable report: {stage3_dir}/ingestion_report.json")

    if args.debug and report.targets:
        print(f"Debug source dump: {layout.debug_dir(stage3_dir)}/<bin_id>.c")

    return 1 if not report.targets else 0


if __name__ == "__main__":
    raise SystemExit(main())
