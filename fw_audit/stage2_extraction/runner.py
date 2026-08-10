"""CLI entry point for Stage 2 extraction.

Registered as the `fw-extract` console script (see pyproject.toml). Usage:

    fw-extract path/to/stage1_summary.json [--only PATH ...] [--dry-run]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from fw_audit.common.schemas import ExtractionStatus
from fw_audit.config.settings import get_settings
from fw_audit.stage2_extraction.extract import Stage2InputError, run_extraction

logger = logging.getLogger("fw_audit.stage2_extraction")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fw-extract",
        description=(
            "Stage 2: decompile Stage 1's identified binaries with Ghidra "
            "Headless and normalize the output for Joern/LLM consumption."
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
            "Restrict decompilation to binaries whose requested path, resolved "
            "rootfs path, or an alias matches PATH. Repeatable."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve binaries and write resolution_report.json, but run no Ghidra.",
    )
    parser.add_argument(
        "--run-id", type=str, default=None, help="Run identifier for logging (default: random)."
    )
    return parser.parse_args(argv)


def _print_summary(summary) -> None:
    print(f"Status: {summary.status.value}")
    print(f"Ghidra image: {summary.ghidra_image}")

    if summary.binaries:
        print(f"\nDecompiled binaries ({len(summary.binaries)}):")
        for b in summary.binaries:
            print(f"  {b.rootfs_path}  [{b.status.value}]  {b.function_count} functions")

    if summary.unresolved:
        print(f"\nUnresolved ({len(summary.unresolved)}):")
        for u in summary.unresolved:
            print(f"  {u.requested_path}  ({u.problem})")

    if summary.warnings:
        print(f"\nWarnings ({len(summary.warnings)}):")
        for w in summary.warnings:
            print(f"  - {w}")

    if summary.errors:
        print(f"\nErrors ({len(summary.errors)}):")
        for e in summary.errors:
            print(f"  - {e}")


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

    try:
        summary = asyncio.run(
            run_extraction(
                stage1_summary_path=stage1_summary_path,
                run_id=args.run_id,
                only=tuple(args.only),
                dry_run=args.dry_run,
            )
        )
    except Stage2InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    _print_summary(summary)
    print(f"\nMachine-readable summary: {summary.db_subfolder}/stage2/stage2_summary.json")

    return 1 if summary.status == ExtractionStatus.FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
