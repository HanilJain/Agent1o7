"""CLI entry point for Stage 3b (external claim ingestion).

Registered as the `fw-claims` console script (see pyproject.toml). Usage:

    fw-claims ingest report.pdf --db-subfolder data/db/<stem> \\
        [--model provider:model] [--pages 4-19] [--run-id ID] [--debug] [--trace]

    fw-claims debug extract report.pdf [--pages 4-19]
    fw-claims debug segment report.pdf [--pages 4-19] [--max-block-chars N]
    fw-claims debug resolve --db-subfolder data/db/<stem> \\
        --binary httpd --function formSetWanNonLogin

`ingest` runs the real pipeline end to end and writes
`<db_subfolder>/stage3b/findings/<chunk_id>.json` (one `AnalysisReport` per
claim) plus `<db_subfolder>/stage3b/claims_summary.json`. `debug extract`
and `debug segment` spend ZERO tokens — run `debug segment` before a real
ingest to see the block count/sizes that determine the run's cost. `debug
resolve` also spends zero tokens.

`main()` stays synchronous except for the ingest bridge, a single
`asyncio.run(...)` call — same discipline as every other stage's runner.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from fw_audit.config.settings import get_settings
from fw_audit.observability import configure_tracing, flush_traces
from fw_audit.stage3b_claims import layout
from fw_audit.stage3b_claims.debug import debug_extract, debug_resolve, debug_segment
from fw_audit.stage3b_claims.driver import ExtractorModelUnavailableError, ingest_report
from fw_audit.stage3b_claims.errors import Stage3bInputError

logger = logging.getLogger("fw_audit.stage3b_claims")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fw-claims",
        description=(
            "Stage 3b: ingest a third-party PDF vulnerability report and transcribe its "
            "claims into Stage-3-compatible findings for Stage 4/5 verification."
        ),
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
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest_parser = subparsers.add_parser(
        "ingest", help="Ingest one PDF report and emit Stage-3-compatible findings."
    )
    ingest_parser.add_argument("pdf_path", type=str, help="Path to the PDF report.")
    ingest_parser.add_argument(
        "--db-subfolder", type=str, required=True, metavar="PATH",
        help="Firmware's <db_subfolder> — output goes to <db_subfolder>/stage3b/.",
    )
    ingest_parser.add_argument(
        "--model", type=str, default=None, metavar="PROVIDER:MODEL",
        help="Override the extractor model for this run only, e.g. 'ollama:qwen2.5-coder:1.5b'.",
    )
    ingest_parser.add_argument(
        "--pages", type=str, default=None, metavar="RANGE",
        help="Restrict extraction to a page range/list, e.g. '4-19' or '1,3,5-8'.",
    )
    ingest_parser.add_argument(
        "--run-id", type=str, default=None, help="Run identifier for logging (default: random)."
    )
    ingest_parser.add_argument(
        "--debug", action="store_true",
        help="Write stage3b/debug/<doc_stem>.blocks.json (segmenter output) alongside the run.",
    )

    debug_parser = subparsers.add_parser("debug", help="Zero-token inspection commands.")
    debug_sub = debug_parser.add_subparsers(dest="debug_command", required=True)

    extract_parser = debug_sub.add_parser("extract", help="Print extracted page text. 0 tokens.")
    extract_parser.add_argument("pdf_path", type=str)
    extract_parser.add_argument("--pages", type=str, default=None, metavar="RANGE")

    segment_parser = debug_sub.add_parser(
        "segment", help="Print claim-block boundaries and sizes. 0 tokens."
    )
    segment_parser.add_argument("pdf_path", type=str)
    segment_parser.add_argument("--pages", type=str, default=None, metavar="RANGE")
    segment_parser.add_argument("--max-block-chars", type=int, default=None, metavar="N")

    resolve_parser = debug_sub.add_parser(
        "resolve", help="Test binary/function hint resolution against Stage 2. 0 tokens."
    )
    resolve_parser.add_argument("--db-subfolder", type=str, required=True, metavar="PATH")
    resolve_parser.add_argument("--binary", type=str, default="", dest="binary_hint")
    resolve_parser.add_argument("--function", type=str, default="", dest="function_hint")

    return parser.parse_args(argv)


def _cmd_ingest(args: argparse.Namespace) -> int:
    pdf_path = Path(args.pdf_path)
    if not pdf_path.is_file():
        print(f"error: PDF not found: {pdf_path}", file=sys.stderr)
        return 2
    db_subfolder = Path(args.db_subfolder)
    if not db_subfolder.is_dir():
        print(f"error: --db-subfolder does not exist: {db_subfolder}", file=sys.stderr)
        return 2

    settings = get_settings()
    if args.model is not None:
        settings = settings.model_copy(update={"stage3b_extractor_model": args.model})
    if args.trace is not None:
        settings = settings.model_copy(update={"langsmith_tracing": args.trace})
    configure_tracing(settings)

    try:
        summary = asyncio.run(
            ingest_report(
                pdf_path,
                db_subfolder=db_subfolder,
                settings=settings,
                run_id=args.run_id,
                pages=args.pages,
                write_debug_blocks=args.debug,
            )
        )
    except Stage3bInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        flush_traces()
        return 2
    except ExtractorModelUnavailableError as exc:
        print(f"error: extractor model unavailable: {exc}", file=sys.stderr)
        flush_traces()
        return 2

    stage3b_dir_ = layout.stage3b_dir(db_subfolder)
    print(
        f"Document: {summary.doc_stem} "
        f"({summary.page_count} pages, {summary.block_count} blocks)"
    )
    print(f"Model: {summary.model}")
    print(
        f"Claims: {summary.total_claims} total, {summary.total_emitted} emitted, "
        f"{summary.total_failed} failed, {summary.total_unresolved_binary} with an "
        f"unresolved binary"
    )
    print(f"Findings: {layout.findings_dir(stage3b_dir_)}/<chunk_id>.json")
    print(f"Summary: {layout.claims_summary_path(stage3b_dir_)}")

    flush_traces()
    return 1 if summary.status in ("no_claims", "pdf_unreadable") else 0


def _cmd_debug_extract(args: argparse.Namespace) -> int:
    pdf_path = Path(args.pdf_path)
    try:
        document = debug_extract(pdf_path, pages=args.pages)
    except Stage3bInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"doc_stem: {document.doc_stem}")
    print(f"pages extracted: {len(document.pages)}")
    for page in document.pages:
        print(f"\n--- page {page.page_number} ({len(page.text)} chars) ---")
        print(page.text)
    return 0


def _cmd_debug_segment(args: argparse.Namespace) -> int:
    pdf_path = Path(args.pdf_path)
    max_block_chars = args.max_block_chars or get_settings().stage3b_max_block_chars
    try:
        blocks = debug_segment(pdf_path, pages=args.pages, max_block_chars=max_block_chars)
    except Stage3bInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    total_chars = sum(b.chars for b in blocks)
    print(
        f"blocks: {len(blocks)}  total_chars: {total_chars:,}  "
        f"(max_block_chars={max_block_chars})"
    )
    print(
        "Each block becomes exactly one LLM call on `fw-claims ingest` — "
        "this is the cost estimate.\n"
    )
    for b in blocks:
        pages = ",".join(str(p) for p in b.page_numbers)
        print(f"  {b.block_id}  pages={pages}  chars={b.chars}")
        print(f"    {b.preview!r}")
    return 0


def _cmd_debug_resolve(args: argparse.Namespace) -> int:
    result = debug_resolve(
        db_subfolder=Path(args.db_subfolder),
        binary_hint=args.binary_hint,
        function_hint=args.function_hint,
    )
    print(
        f"binary_hint={result.binary_hint!r} -> bin_id={result.bin_id!r} "
        f"({result.binary_matched_on})"
    )
    print(
        f"function_hint={result.function_hint!r} -> function_name={result.function_name!r} "
        f"({result.function_matched_on})"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=get_settings().log_level, format="%(levelname)s %(name)s: %(message)s"
    )
    args = _parse_args(argv)

    if args.command == "ingest":
        return _cmd_ingest(args)
    if args.command == "debug":
        if args.debug_command == "extract":
            return _cmd_debug_extract(args)
        if args.debug_command == "segment":
            return _cmd_debug_segment(args)
        if args.debug_command == "resolve":
            return _cmd_debug_resolve(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
