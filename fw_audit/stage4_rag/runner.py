"""CLI entry point for Stage 4 (RAG Sink-to-Source Identifier).

Registered as the `fw-trace` console script (see pyproject.toml). Usage:

    fw-trace build-corpus --db-subfolder DIR --rootfs DIR --stage2-binaries DIR
    fw-trace run --db-subfolder DIR [--only GID ...] [--model-planner P:M] [--model-analyst P:M]
    fw-trace debug corpus --db-subfolder DIR
    fw-trace debug parity
    fw-trace debug sinks --db-subfolder DIR
    fw-trace debug query --db-subfolder DIR --gid GID
    fw-trace debug retrieve --db-subfolder DIR --gid GID
    fw-trace debug search --db-subfolder DIR --query TEXT [--query TEXT ...] [--top-k N]
    fw-trace debug taint --db-subfolder DIR --gid GID

`build-corpus` runs Components 1+2 locally — no zip/upload, straight to
`<db_subfolder>/stage4/{chroma,corpus_report.json}` (see `corpus_build.py`).
`run` runs Components 3-6 (`driver.run_queue`) over every Stage 3 finding
with `decision in {ESCALATE, CONTEXT_REQUIRED}` by default. `debug`
dispatches to `debug.py`'s per-component inspection functions.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from fw_audit.config.settings import get_settings
from fw_audit.observability import configure_tracing, flush_traces
from fw_audit.stage4_rag import debug as debug_mod
from fw_audit.stage4_rag import layout
from fw_audit.stage4_rag.corpus_build import build_corpus
from fw_audit.stage4_rag.driver import run_queue
from fw_audit.stage4_rag.errors import Stage4InputError, VectorStoreUnavailableError
from fw_audit.stage4_rag.query.planner import QueryPlannerUnavailableError
from fw_audit.stage4_rag.taint.analyst import TaintAnalystUnavailableError

logger = logging.getLogger("fw_audit.stage4_rag")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fw-trace",
        description="Stage 4: RAG sink-to-source identifier — local corpus build + C3-C6 driver.",
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
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build-corpus", help="Components 1+2: chunk + embed + index, locally.")
    build.add_argument("--db-subfolder", type=str, required=True)
    build.add_argument("--rootfs", type=str, required=True, help="Stage 1 rootfs directory.")
    build.add_argument(
        "--stage2-binaries", type=str, required=True, help="Stage 2 stage2/binaries/ directory."
    )

    run = sub.add_parser("run", help="Components 3-6: C3->C4->C5 driver over Stage 3 findings.")
    run.add_argument("--db-subfolder", type=str, required=True)
    run.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="GID",
        help="Restrict to this global id. Repeatable.",
    )
    run.add_argument("--model-planner", type=str, default=None, metavar="PROVIDER:MODEL")
    run.add_argument("--model-analyst", type=str, default=None, metavar="PROVIDER:MODEL")
    run.add_argument("--run-id", type=str, default=None)

    dbg = sub.add_parser("debug", help="Inspect/verify one component in isolation.")
    dbg_sub = dbg.add_subparsers(dest="debug_command", required=True)

    dbg_corpus = dbg_sub.add_parser("corpus", help="Report local Chroma collection stats.")
    dbg_corpus.add_argument("--db-subfolder", type=str, required=True)

    dbg_sub.add_parser("parity", help="Sanity-check doc/query embedding parity.")

    dbg_sinks = dbg_sub.add_parser("sinks", help="List discovered Stage 3 finding candidates.")
    dbg_sinks.add_argument("--db-subfolder", type=str, required=True)

    for name, help_text in (
        ("query", "Run Component 3 only for one finding."),
        ("retrieve", "Run Components 3+4 for one finding."),
        ("taint", "Run Components 3-5 for one finding (dry run, not persisted)."),
    ):
        p = dbg_sub.add_parser(name, help=help_text)
        p.add_argument("--db-subfolder", type=str, required=True)
        p.add_argument("--gid", type=str, required=True, help="Global finding id.")

    dbg_search = dbg_sub.add_parser(
        "search", help="Run Component 4 directly against hand-written queries (bypasses C3)."
    )
    dbg_search.add_argument("--db-subfolder", type=str, required=True)
    dbg_search.add_argument(
        "--query",
        action="append",
        required=True,
        metavar="TEXT",
        help="A raw search query. Repeatable — pass multiple for broader coverage.",
    )
    dbg_search.add_argument(
        "--top-k",
        type=int,
        default=None,
        metavar="N",
        help="Per-query result count (default: FWA_STAGE4_TOP_K). Results are merged/deduped "
        "across all --query values, so more queries and/or a higher --top-k both widen the "
        "final result set.",
    )

    return parser.parse_args(argv)


def _cmd_build_corpus(args: argparse.Namespace) -> int:
    report = build_corpus(
        db_subfolder=Path(args.db_subfolder),
        rootfs_dir=Path(args.rootfs),
        stage2_binaries_dir=Path(args.stage2_binaries),
    )
    print(f"Chunks: {report.total_chunks} across {report.total_files} files")
    print(f"By kind: {report.chunks_by_kind}")
    print(f"Embedding model: {report.embedding_model}")
    print(f"Chroma: {report.chroma_dir}")
    print(f"Report: {report.corpus_report_path}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    settings = get_settings()
    updates: dict[str, object] = {}
    if args.model_planner is not None:
        updates["stage4_query_planner_model"] = args.model_planner
    if args.model_analyst is not None:
        updates["stage4_taint_analyst_model"] = args.model_analyst
    if updates:
        settings = settings.model_copy(update=updates)

    db_subfolder = Path(args.db_subfolder)
    only = frozenset(args.only) if args.only else None
    try:
        summary = asyncio.run(
            run_queue(
                db_subfolder=db_subfolder,
                settings=settings,
                only_global_ids=only,
                run_id=args.run_id,
            )
        )
    except (Stage4InputError, VectorStoreUnavailableError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Status: {summary.status}")
    print(
        f"Findings: {summary.total_findings} total, {summary.total_completed} completed, "
        f"{summary.total_failed} failed"
    )
    print(f"Summary: {layout.stage4_summary_path(layout.stage4_dir(db_subfolder))}")
    return 0


def _cmd_debug(args: argparse.Namespace) -> int:
    try:
        if args.debug_command == "corpus":
            stats = debug_mod.debug_corpus(Path(args.db_subfolder))
            print(f"total_chunks: {stats.total_chunks}")
            print(f"chunks_by_kind (sample): {stats.chunks_by_kind}")
            print(f"sample_ids: {stats.sample_ids}")
            print(f"embedding_dim: {stats.embedding_dim}")
        elif args.debug_command == "parity":
            check = debug_mod.debug_embedding_parity()
            print(f"doc:   {check.doc_text!r}")
            print(f"query: {check.query_text!r}")
            print(f"cosine_similarity: {check.cosine_similarity:.4f}")
        elif args.debug_command == "sinks":
            candidates = debug_mod.debug_sinks(Path(args.db_subfolder))
            by_decision: dict[str, int] = {}
            for c in candidates:
                key = c.finding.decision.value
                by_decision[key] = by_decision.get(key, 0) + 1
            print(f"total candidates: {len(candidates)}")
            print(f"by decision: {by_decision}")
            for c in candidates[:20]:
                print(f"  {c.global_id}  [{c.finding.decision.value}]  {c.finding.title}")
        elif args.debug_command == "query":
            plan = asyncio.run(debug_mod.debug_query(Path(args.db_subfolder), args.gid))
            print(plan.model_dump_json(indent=2))
        elif args.debug_command == "retrieve":
            bundle = asyncio.run(debug_mod.debug_retrieve(Path(args.db_subfolder), args.gid))
            print(f"finding: {bundle.global_id}")
            for chunk in bundle.chunks:
                print(f"  [{chunk.distance:.4f}] {chunk.kind} {chunk.source_path}")
        elif args.debug_command == "search":
            bundle = debug_mod.debug_search(
                Path(args.db_subfolder), args.query, top_k=args.top_k
            )
            print(f"queries: {len(args.query)}  results: {len(bundle.chunks)}")
            for chunk in bundle.chunks:
                snippet = chunk.text[:200].replace("\n", " ")
                bin_label = f" bin_id={chunk.bin_id}" if chunk.bin_id else ""
                print(
                    f"  [{chunk.distance:.4f}] {chunk.kind} {chunk.source_path}{bin_label} "
                    f"(matched by {len(chunk.matched_queries)}/{len(args.query)} queries)"
                )
                print(f"      {snippet}...")
        elif args.debug_command == "taint":
            report = asyncio.run(debug_mod.debug_taint(Path(args.db_subfolder), args.gid))
            print(report.model_dump_json(indent=2))
        else:  # pragma: no cover - argparse enforces valid subcommands
            return 2
    except (
        Stage4InputError,
        VectorStoreUnavailableError,
        QueryPlannerUnavailableError,
        TaintAnalystUnavailableError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=get_settings().log_level, format="%(levelname)s %(name)s: %(message)s"
    )
    args = _parse_args(argv)

    settings = get_settings()
    if args.trace is not None:
        settings = settings.model_copy(update={"langsmith_tracing": args.trace})
    configure_tracing(settings)

    try:
        if args.command == "build-corpus":
            return _cmd_build_corpus(args)
        if args.command == "run":
            return _cmd_run(args)
        if args.command == "debug":
            return _cmd_debug(args)
        return 2  # pragma: no cover - argparse enforces valid subcommands
    finally:
        flush_traces()


if __name__ == "__main__":
    raise SystemExit(main())
