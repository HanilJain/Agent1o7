"""CLI entry point for Stage 1 ingestion.

Registered as the `fw-ingest` console script (see pyproject.toml). Usage:

    fw-ingest path/to/firmware.bin [--tplink] [--db-subfolder NAME]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import uuid
from pathlib import Path

from fw_audit.common.schemas import extension_from_path
from fw_audit.config.settings import Settings, get_settings
from fw_audit.observability import configure_tracing, flush_traces
from fw_audit.observability import layout as usage_layout
from fw_audit.observability.usage import (
    UsageBudgetExceededError,
    format_usage_summary,
    usage_registry,
)
from fw_audit.stage1_ingestion.graph import get_graph
from fw_audit.stage1_ingestion.state import IngestionStatus, initial_state

logger = logging.getLogger("fw_audit.stage1_ingestion")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fw-ingest",
        description=(
            "Stage 1: unpack a firmware image (Extraction Script) and identify "
            "binaries worth deeper analysis (Identifier Agent)."
        ),
    )
    parser.add_argument("firmware_path", type=str, help="Path to the raw firmware image.")
    parser.add_argument(
        "--tplink",
        action="store_true",
        help=(
            "Explicitly mark this firmware as TP-Link. Required (rule 1 of the "
            "trigger policy) before tp-link-decrypt will ever run — it also "
            "only runs if the first binwalk attempt fails (rule 2)."
        ),
    )
    parser.add_argument(
        "--db-subfolder",
        type=str,
        default=None,
        help=(
            "Override the Database subfolder name (default: the firmware "
            "filename's stem, e.g. router-fw-1.2.bin -> router-fw-1.2/)."
        ),
    )
    parser.add_argument(
        "--run-id", type=str, default=None, help="Run identifier for logging (default: random)."
    )
    parser.add_argument(
        "--usage",
        dest="usage",
        action="store_true",
        default=None,
        help="Print the LLM token/cost usage summary at the end of this run (default: on).",
    )
    parser.add_argument(
        "--no-usage",
        dest="usage",
        action="store_false",
        help="Suppress the LLM token/cost usage summary.",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        metavar="RPS",
        help="Cap LLM requests-per-second for this run (default: FWA_LLM_RATE_LIMIT_RPS).",
    )
    parser.add_argument(
        "--max-cost",
        type=float,
        default=None,
        metavar="USD",
        help="Warn-only budget on estimated USD cost for this run (default: FWA_LLM_MAX_COST_USD).",
    )
    parser.add_argument(
        "--trace",
        dest="trace",
        action="store_true",
        default=None,
        help="Force-enable LangSmith tracing for this run, overriding LANGSMITH_TRACING.",
    )
    parser.add_argument(
        "--no-trace",
        dest="trace",
        action="store_false",
        help="Force-disable LangSmith tracing for this run, overriding LANGSMITH_TRACING.",
    )
    return parser.parse_args(argv)


async def run_ingestion(
    firmware_path: str,
    *,
    is_tplink: bool = False,
    db_subfolder_name: str | None = None,
    run_id: str | None = None,
    settings: Settings | None = None,
):
    """Run the Stage 1 graph end-to-end and return the final state."""
    settings = settings or get_settings()
    settings.ensure_dirs()

    run_id = run_id or uuid.uuid4().hex[:12]
    stem = db_subfolder_name or Path(firmware_path).stem
    db_subfolder = settings.db_subfolder(stem)

    state = initial_state(
        run_id=run_id,
        firmware_path=firmware_path,
        db_subfolder=str(db_subfolder),
        is_tplink=is_tplink,
    )
    graph = get_graph()
    return await graph.ainvoke(state)


def _print_summary(result: dict) -> None:
    status = result.get("status")
    print(f"Status: {status}")

    if result.get("firmware_metadata"):
        meta = result["firmware_metadata"]
        print(
            f"Firmware: {meta.original_filename} "
            f"({meta.size_bytes} bytes, sha256={meta.sha256[:16]}...)"
        )

    if result.get("tree_txt_path"):
        print(f"tree.txt: {result['tree_txt_path']}  (in the Database; Hand-off 1 -> Stage 3 RAG)")

    identified = result.get("identified_binaries") or []
    print(f"Identified binaries: {len(identified)}  (Hand-off 2 -> Stage 2 Ghidra MCP)")
    for b in identified[:15]:
        print(f"  {b.path}  (extension: {extension_from_path(b.path) or 'none'})")

    if result.get("warnings"):
        print(f"\nWarnings ({len(result['warnings'])}):")
        for w in result["warnings"]:
            print(f"  - {w}")

    if result.get("errors"):
        print(f"\nErrors ({len(result['errors'])}):")
        for e in result["errors"]:
            print(f"  - {e}")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=get_settings().log_level, format="%(levelname)s %(name)s: %(message)s")
    args = _parse_args(argv)

    firmware_path = Path(args.firmware_path)
    if not firmware_path.is_file():
        print(f"error: firmware path does not exist or is not a file: {firmware_path}", file=sys.stderr)
        return 2

    settings = get_settings()
    if args.trace is not None:
        settings = settings.model_copy(update={"langsmith_tracing": args.trace})
    if args.rate_limit is not None:
        settings = settings.model_copy(update={"llm_rate_limit_rps": args.rate_limit})
    if args.max_cost is not None:
        settings = settings.model_copy(update={"llm_max_cost_usd": args.max_cost})
    show_usage = args.usage if args.usage is not None else settings.llm_usage_console
    configure_tracing(settings)

    run_id = args.run_id or "run"
    # `db_subfolder` isn't known until `run_ingestion` resolves the stem, so
    # the JSONL path is built from the SAME `settings.db_subfolder(stem)`
    # logic `run_ingestion` uses internally — see that function's body.
    stem = args.db_subfolder or firmware_path.stem
    usage_dir_ = usage_layout.usage_dir(settings.db_subfolder(stem))

    try:
        with usage_registry(
            jsonl_path=(
                usage_layout.usage_jsonl_path(usage_dir_, stage="1", run_id=run_id)
                if settings.llm_usage_artifact
                else None
            ),
            settings=settings,
        ) as registry:
            try:
                result = asyncio.run(
                    run_ingestion(
                        str(firmware_path),
                        is_tplink=args.tplink,
                        db_subfolder_name=args.db_subfolder,
                        run_id=args.run_id,
                        settings=settings,
                    )
                )
            except UsageBudgetExceededError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            finally:
                if settings.llm_usage_artifact:
                    registry.write_report(
                        usage_layout.usage_report_path(usage_dir_, stage="1", run_id=run_id),
                        stage="1",
                        run_id=args.run_id or "",
                    )

            _print_summary(result)

            if show_usage:
                summary_text = format_usage_summary(
                    registry.snapshot(stage="1", run_id=args.run_id or "")
                )
                if summary_text:
                    print(f"\n{summary_text}")
    finally:
        flush_traces()

    # Emit a machine-readable summary alongside the human one, for scripted
    # callers (Stage 2). Per the policy, this JSON — not the Database — is
    # what actually gets consumed downstream; written next to tree.txt for
    # convenience, but Stage 2 only needs identified_binaries.
    db_subfolder = Path(result["db_subfolder"])
    summary_path = db_subfolder / "stage1_summary.json"
    status = result.get("status")
    summary_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run_id": result.get("run_id"),
                # `.value`, not `str()` — `str()` on a `str`-Enum member
                # yields its repr ("IngestionStatus.COMPLETED"), not its
                # value ("completed"). `getattr` guards the case where
                # `status` is already a plain string (defensive only).
                "status": getattr(status, "value", str(status)),
                "db_subfolder": str(db_subfolder),
                "tree_txt_path": result.get("tree_txt_path"),
                "rootfs_dir": result.get("rootfs_dir"),
                "identified_binaries": [
                    b.model_dump(mode="json") for b in result.get("identified_binaries", [])
                ],
                "warnings": result.get("warnings", []),
                "errors": result.get("errors", []),
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    print(f"\nMachine-readable summary: {summary_path}")

    return 1 if result.get("status") == IngestionStatus.FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
