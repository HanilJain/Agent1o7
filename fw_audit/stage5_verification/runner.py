"""CLI entry point for Stage 5 (Sandboxed Verification — FVVW v3 fork-join,
with a `--joern-only` fallback to the original static-only pipeline).

Registered as the `fw-verify` console script (see pyproject.toml). Usage:

    fw-verify run --db-subfolder DIR [--only GID ...] [--decisions D[,D...]]
                  [--model P:M] [--keep-workspace] [--joern-only]
    fw-verify debug build-cpg --db-subfolder DIR --bin-id BIN_ID
    fw-verify debug script --workspace DIR --script-file PATH
    fw-verify debug verify --db-subfolder DIR --gid GID [--prompt-file PATH]
                            [--model P:M] [--max-iterations N] [--output PATH]
    fw-verify debug strategy --db-subfolder DIR --gid GID
    fw-verify debug dynamic --db-subfolder DIR --gid GID
    fw-verify debug fvvw --db-subfolder DIR --gid GID [--output PATH]

`run` verifies every Stage 3 finding with `decision == ESCALATE` by default
(`candidate_index.discover_candidates`). By DEFAULT this drives the full
FVVW v3 fork-join (`fvvw.driver.run_fvvw_queue` — strategy plan, static
Joern track + dynamic QEMU+GDB track run independently, joint two-axis
verdict, LLM disclosure report), persisting to `stage5/fvvw/`.
`--joern-only` routes to the ORIGINAL static-only pipeline
(`driver.run_queue`) unchanged, persisting to `stage5/verifications/`+
`stage5/reports/` exactly as it always has — the pre-FVVW-v3 behavior
stays fully reachable. `--decisions` overrides which Stage 3 decision(s)
qualify (e.g. `CONTEXT_REQUIRED`, on the chance a CPG resolves what Stage 3
itself couldn't). `debug` dispatches to `debug.py`'s (Joern-only) and
`fvvw.debug`'s (strategy/dynamic-only/full-fork-join) per-component,
dry-run inspection functions — none of them persist into the pipeline's
own tracked output directories.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from fw_audit.common.findings import Decision
from fw_audit.common.verification import TranscriptEntry
from fw_audit.config.settings import get_settings
from fw_audit.observability import configure_tracing, flush_traces
from fw_audit.stage5_verification import debug as debug_mod
from fw_audit.stage5_verification import layout
from fw_audit.stage5_verification.driver import run_queue
from fw_audit.stage5_verification.errors import (
    SandboxUnavailableError,
    Stage5InputError,
    VerifierModelUnavailableError,
)
from fw_audit.stage5_verification.fvvw import debug as fvvw_debug_mod
from fw_audit.stage5_verification.fvvw.driver import run_fvvw_queue
from fw_audit.stage5_verification.report_writer import render_report


def _print_transcript_entries(entries: list[TranscriptEntry]) -> None:
    """Live console renderer for `agent.verifier.verify_candidate`'s
    `on_step` callback — prints each newly-produced turn as it happens:
    the agent's reasoning, which tool(s) it decided to call and with what
    arguments, and each tool's response. Terminal-friendly plain text, not
    the Markdown `report_writer._render_transcript_section` produces (that
    one is for the saved report; this one is for watching it happen live)."""
    for entry in entries:
        if entry.role == "system":
            print(f"[turn {entry.turn}] (system prompt sent)")
        elif entry.role == "human":
            print(f"[turn {entry.turn}] >> task given to agent")
        elif entry.role == "ai":
            if entry.content.strip():
                print(f"[turn {entry.turn}] agent: {entry.content.strip()}")
            for call in entry.tool_calls:
                args_str = ", ".join(f"{k}={v!r}" for k, v in call.args.items())
                print(f"[turn {entry.turn}] agent calls {call.name}({args_str})")
        elif entry.role == "tool":
            snippet = entry.content.strip()
            if len(snippet) > 500:
                snippet = snippet[:500] + " …(truncated)"
            print(f"[turn {entry.turn}] tool response: {snippet or '(empty)'}")
        print()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fw-verify",
        description="Stage 5: sandboxed verification — Joern generate/run/evaluate pipeline.",
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

    run = sub.add_parser("run", help="Verify every ESCALATE Stage 3 finding.")
    run.add_argument("--db-subfolder", type=str, required=True)
    run.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="GID",
        help="Restrict to this global id. Repeatable. NOTE: this only narrows the "
        "set already selected by --decisions — it does not itself bypass the "
        "decision filter, so a finding excluded by --decisions is still excluded "
        "even if you name it here explicitly.",
    )
    run.add_argument(
        "--decisions",
        type=str,
        default=None,
        metavar="DECISION[,DECISION...]",
        help=(
            "Comma-separated Stage 3 decisions to verify, overriding the default "
            "ESCALATE-only filter — e.g. 'CONTEXT_REQUIRED' or 'ESCALATE,"
            "CONTEXT_REQUIRED'. Valid values: "
            + ", ".join(d.value for d in Decision)
            + ". CONTEXT_REQUIRED findings are excluded by default because they "
            "name context (callers/globals/macros/ABI facts) a single binary's "
            "CPG often can't supply either — passing this flag runs them through "
            "Joern anyway, on the chance the CPG resolves what Stage 3 couldn't."
        ),
    )
    run.add_argument("--model", type=str, default=None, metavar="PROVIDER:MODEL")
    run.add_argument("--run-id", type=str, default=None)
    run.add_argument(
        "--keep-workspace", action="store_true", help="Don't delete stage5/workspace/<gid>/ after."
    )
    run.add_argument(
        "--joern-only",
        action="store_true",
        help="Run ONLY the original static-only Joern pipeline (pre-FVVW-v3 behavior), "
        "persisting to stage5/verifications/+stage5/reports/ exactly as before — skips "
        "the strategy plan, the dynamic QEMU+GDB track, and the joint two-axis verdict "
        "entirely. Without this flag, `run` drives the full FVVW v3 fork-join by default.",
    )

    dbg = sub.add_parser("debug", help="Inspect/verify one component in isolation.")
    dbg_sub = dbg.add_subparsers(dest="debug_command", required=True)

    dbg_cpg = dbg_sub.add_parser("build-cpg", help="Build a CPG for one binary. No LLM.")
    dbg_cpg.add_argument("--db-subfolder", type=str, required=True)
    dbg_cpg.add_argument("--bin-id", type=str, required=True)

    dbg_script = dbg_sub.add_parser(
        "script", help="Run one hand-written Joern script against an already-built CPG. No LLM."
    )
    dbg_script.add_argument(
        "--workspace", type=str, required=True, help="Directory containing cpg.bin."
    )
    dbg_script.add_argument("--script-file", type=str, required=True)

    dbg_verify = dbg_sub.add_parser(
        "verify", help="Run the full agent loop for one finding (dry run, not persisted)."
    )
    dbg_verify.add_argument("--db-subfolder", type=str, required=True)
    dbg_verify.add_argument("--gid", type=str, required=True, help="Global finding id.")
    dbg_verify.add_argument(
        "--prompt-file", type=str, default=None, help="Override the system prompt."
    )
    dbg_verify.add_argument("--model", type=str, default=None, metavar="PROVIDER:MODEL")
    dbg_verify.add_argument("--max-iterations", type=int, default=None)
    dbg_verify.add_argument(
        "--output", type=str, default=None, help="Write the JSON report here (default: stdout)."
    )
    dbg_verify.add_argument(
        "--no-live",
        action="store_true",
        help="Don't print the agent's reasoning/tool calls as they happen — "
        "just wait and show the finished report (the transcript is still in "
        "the JSON/Markdown output either way).",
    )

    dbg_strategy = dbg_sub.add_parser(
        "strategy",
        help="Run ONLY the strategy agent for one finding — emits the StrategyPlan, "
        "runs neither track.",
    )
    dbg_strategy.add_argument("--db-subfolder", type=str, required=True)
    dbg_strategy.add_argument("--gid", type=str, required=True, help="Global finding id.")

    dbg_dynamic = dbg_sub.add_parser(
        "dynamic",
        help="Run ONLY the dynamic (QEMU+GDB) track for one finding — no static track, "
        "no crosscheck, no joint evaluation, no report. The QEMU-only counterpart to "
        "`debug build-cpg`/`debug script`'s Joern-only path.",
    )
    dbg_dynamic.add_argument("--db-subfolder", type=str, required=True)
    dbg_dynamic.add_argument("--gid", type=str, required=True, help="Global finding id.")

    dbg_fvvw = dbg_sub.add_parser(
        "fvvw",
        help="Run the COMPLETE fork-join (both tracks + joint_evaluate + write_report) "
        "for one finding, dry run — not persisted to stage5/fvvw/reports/.",
    )
    dbg_fvvw.add_argument("--db-subfolder", type=str, required=True)
    dbg_fvvw.add_argument("--gid", type=str, required=True, help="Global finding id.")
    dbg_fvvw.add_argument(
        "--output", type=str, default=None, help="Write the JSON report here (default: stdout)."
    )

    return parser.parse_args(argv)


def _parse_decisions(raw: str) -> frozenset[Decision]:
    """Parse `--decisions`' comma-separated string into a `frozenset[Decision]`,
    raising `ValueError` with the exact bad token named on a typo rather than
    letting an unrecognized value silently fall through as an empty filter."""
    values = [v.strip() for v in raw.split(",") if v.strip()]
    if not values:
        raise ValueError("--decisions given but empty after parsing — pass at least one value.")
    result = set()
    for value in values:
        try:
            result.add(Decision(value))
        except ValueError as exc:
            valid = ", ".join(d.value for d in Decision)
            raise ValueError(
                f"Unknown --decisions value {value!r}. Valid values: {valid}."
            ) from exc
    return frozenset(result)


def _cmd_run(args: argparse.Namespace) -> int:
    settings = get_settings()
    updates: dict[str, object] = {}
    if args.model is not None:
        updates["stage5_verifier_model"] = args.model
    if args.keep_workspace:
        updates["stage5_keep_workspace"] = True
    if updates:
        settings = settings.model_copy(update=updates)

    db_subfolder = Path(args.db_subfolder)
    only = frozenset(args.only) if args.only else None

    decisions_kwargs: dict[str, object] = {}
    if args.decisions is not None:
        try:
            decisions_kwargs["decisions"] = _parse_decisions(args.decisions)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    joern_only = getattr(args, "joern_only", False)
    queue_fn = run_queue if joern_only else run_fvvw_queue
    summary_path_fn = (
        layout.stage5_summary_path if joern_only else layout.fvvw_summary_path
    )

    try:
        summary = asyncio.run(
            queue_fn(
                db_subfolder=db_subfolder,
                settings=settings,
                only_global_ids=only,
                run_id=args.run_id,
                **decisions_kwargs,
            )
        )
    except Stage5InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Status: {summary.status}")
    print(
        f"Candidates: {summary.total_candidates} total, {summary.total_verified} verified, "
        f"{summary.total_failed} failed"
    )
    label = "Verdicts" if joern_only else "Mechanism confidence tallies"
    print(f"{label}: {summary.verdicts_by_type}")
    print(f"Summary: {summary_path_fn(layout.stage5_dir(db_subfolder))}")
    if not joern_only:
        print(
            "(Full FVVW v3 fork-join run — pass --joern-only for the original "
            "static-only pipeline.)"
        )
    return 0


def _cmd_debug(args: argparse.Namespace) -> int:
    try:
        if args.debug_command == "build-cpg":
            result = asyncio.run(debug_mod.debug_build_cpg(Path(args.db_subfolder), args.bin_id))
            print(f"workspace: {result.workspace_dir}")
            print(f"ok: {result.record.ok}")
            print(f"duration_seconds: {result.record.duration_seconds:.1f}")
            if not result.record.ok:
                print(f"stderr:\n{result.record.stderr}")
        elif args.debug_command == "script":
            script_text = Path(args.script_file).read_text(encoding="utf-8")
            attempt = asyncio.run(
                debug_mod.debug_run_script(Path(args.workspace), script_text)
            )
            print(f"ok: {attempt.ok}  returncode: {attempt.returncode}")
            print(attempt.stdout if attempt.ok else attempt.stderr)
        elif args.debug_command == "verify":
            settings = get_settings()
            updates: dict[str, object] = {}
            if args.model is not None:
                updates["stage5_verifier_model"] = args.model
            if args.max_iterations is not None:
                updates["stage5_max_agent_iterations"] = args.max_iterations
            if updates:
                settings = settings.model_copy(update=updates)

            prompt_override = None
            if args.prompt_file is not None:
                prompt_override = Path(args.prompt_file).read_text(encoding="utf-8")

            on_step = None if args.no_live else _print_transcript_entries
            if on_step is not None:
                print(f"--- verifying {args.gid} (live) ---\n")

            report = asyncio.run(
                debug_mod.debug_verify(
                    Path(args.db_subfolder),
                    args.gid,
                    prompt_override=prompt_override,
                    settings=settings,
                    on_step=on_step,
                )
            )
            payload = report.model_dump_json(indent=2)
            if on_step is not None:
                print(f"--- verdict: {report.verdict.value} ---\n")
            if args.output:
                Path(args.output).write_text(payload, encoding="utf-8")
                print(f"Report written to {args.output}")
                print(render_report(report))
            else:
                print(payload)
        elif args.debug_command == "strategy":
            result = asyncio.run(
                fvvw_debug_mod.debug_strategy(Path(args.db_subfolder), args.gid)
            )
            print(f"target: {result.target.model_dump_json(indent=2)}")
            print(f"plan: {result.plan.model_dump_json(indent=2)}")
        elif args.debug_command == "dynamic":
            result = asyncio.run(
                fvvw_debug_mod.debug_dynamic(Path(args.db_subfolder), args.gid)
            )
            print(f"verdict: {result.result.verdict.value}")
            print(f"proved_hypothesis: {result.result.proved_hypothesis}")
            print(f"guard_logs: {result.guard_logs}")
            print(f"gdb_transcript:\n{result.gdb_transcript}")
        elif args.debug_command == "fvvw":
            outcome = asyncio.run(fvvw_debug_mod.debug_fvvw(Path(args.db_subfolder), args.gid))
            print(f"agreement: {outcome['agreement'].value}")
            print(f"mechanism_confidence: {outcome['mechanism_confidence'].value}")
            print(f"reachability_confidence: {outcome['reachability_confidence'].value}")
            if args.output:
                Path(args.output).write_text(outcome["report_markdown"], encoding="utf-8")
                print(f"Report written to {args.output}")
            else:
                print(outcome["report_markdown"])
        else:  # pragma: no cover - argparse enforces valid subcommands
            return 2
    except (
        Stage5InputError,
        SandboxUnavailableError,
        VerifierModelUnavailableError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    import logging

    logging.basicConfig(
        level=get_settings().log_level, format="%(levelname)s %(name)s: %(message)s"
    )
    args = _parse_args(argv)

    settings = get_settings()
    if args.trace is not None:
        settings = settings.model_copy(update={"langsmith_tracing": args.trace})
    configure_tracing(settings)

    try:
        if args.command == "run":
            return _cmd_run(args)
        if args.command == "debug":
            return _cmd_debug(args)
        return 2  # pragma: no cover - argparse enforces valid subcommands
    finally:
        flush_traces()


if __name__ == "__main__":
    raise SystemExit(main())
