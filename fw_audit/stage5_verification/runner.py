"""CLI entry point for Stage 5 (Sandboxed Verification — FVVW v3 fork-join,
with a `--joern-only` fallback to the original static-only pipeline).

Registered as the `fw-verify` console script (see pyproject.toml). Usage:

    fw-verify run --db-subfolder DIR [--only GID ...] [--decisions D[,D...]]
                  [--model P:M] [--keep-workspace] [--joern-only | --dynamic-only]
                  [--live]
    fw-verify debug build-cpg --db-subfolder DIR --bin-id BIN_ID
    fw-verify debug script --workspace DIR --script-file PATH
    fw-verify debug verify --db-subfolder DIR --gid GID [--prompt-file PATH]
                            [--model P:M] [--max-iterations N] [--output PATH]
    fw-verify debug strategy --db-subfolder DIR --gid GID [--no-live]
    fw-verify debug dynamic --db-subfolder DIR --gid GID [--no-live]
                             [--stop-after NODE]
    fw-verify debug fvvw --db-subfolder DIR --gid GID [--output PATH] [--no-live]

`run` verifies every Stage 3 finding with `decision == ESCALATE` by default
(`candidate_index.discover_candidates`). By DEFAULT this drives the full
FVVW v3 fork-join (`fvvw.driver.run_fvvw_queue` — strategy plan, static
Joern track + dynamic QEMU+GDB track run independently, joint two-axis
verdict, LLM disclosure report), persisting to `stage5/fvvw/`.
`--joern-only` routes to the ORIGINAL static-only pipeline
(`driver.run_queue`) unchanged, persisting to `stage5/verifications/`+
`stage5/reports/` exactly as it always has — the pre-FVVW-v3 behavior
stays fully reachable. `--dynamic-only` routes to the dynamic (QEMU+GDB)
track ALONE (`fvvw.driver.run_dynamic_only_queue` — no static track, no
crosscheck, no joint two-axis verdict), persisting to
`stage5/fvvw/dynamic_only/` — the production counterpart to
`--joern-only`, for when only the dynamic track's own verdict is wanted.
`--joern-only` and `--dynamic-only` are mutually exclusive. `--live`
(default off in production; every `debug` subcommand below defaults it ON
instead, `--no-live` there to quiet it) prints chain-of-thought console
output — every LLM call's raw prompt/response, every tool/sandbox command
and its result, every parsed agentic action/decision, every dynamic-graph
node update — tagged `[gid]` so concurrent `stage5_workers` stay
attributable; the full, untruncated record is always in
`stage5/fvvw/logs/<gid>.<track>.jsonl` regardless of `--live`.
`--decisions` overrides which Stage 3 decision(s) qualify (e.g.
`CONTEXT_REQUIRED`, on the chance a CPG resolves what Stage 3 itself
couldn't). `debug` dispatches to `debug.py`'s (Joern-only) and
`fvvw.debug`'s (strategy/dynamic-only/full-fork-join) per-component,
dry-run inspection functions — none of them persist into the pipeline's
own tracked output directories. `debug dynamic --stop-after NODE` halts
the dynamic graph right after that node fires (one of `plan_emulation`/
`bringup`/`health_gate`/`gdb_attach`/`trigger`/`evaluate_route`/
`plan_emulation_escalate`) — per-node diagnosis without running the rest
of the track.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from fw_audit.common.findings import Decision
from fw_audit.config.settings import Settings, get_settings
from fw_audit.observability import configure_tracing, flush_traces
from fw_audit.observability import layout as usage_layout
from fw_audit.observability.usage import (
    UsageBudgetExceededError,
    UsageRegistry,
    format_usage_summary,
    usage_registry,
)
from fw_audit.stage5_verification import debug as debug_mod
from fw_audit.stage5_verification import layout
from fw_audit.stage5_verification.driver import run_queue
from fw_audit.stage5_verification.errors import (
    SandboxUnavailableError,
    Stage5InputError,
    VerifierModelUnavailableError,
)
from fw_audit.stage5_verification.fvvw import debug as fvvw_debug_mod
from fw_audit.stage5_verification.fvvw.driver import run_dynamic_only_queue, run_fvvw_queue
from fw_audit.stage5_verification.live_console import make_transcript_on_step
from fw_audit.stage5_verification.report_writer import render_report

_DYNAMIC_GRAPH_NODES = (
    "plan_emulation",
    "bringup",
    "health_gate",
    "gdb_attach",
    "trigger",
    "evaluate_route",
    "plan_emulation_escalate",
)


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
        "entirely. Without this flag, `run` drives the full FVVW v3 fork-join by default. "
        "Mutually exclusive with --dynamic-only.",
    )
    run.add_argument(
        "--dynamic-only",
        action="store_true",
        help="Run ONLY the dynamic (QEMU+GDB) track — no static track, no crosscheck, no "
        "joint two-axis verdict — persisting to stage5/fvvw/dynamic_only/ instead of "
        "stage5/fvvw/reports/. The production counterpart to --joern-only. Mutually "
        "exclusive with --joern-only.",
    )
    run.add_argument(
        "--live",
        dest="live",
        action="store_true",
        default=None,
        help="Print chain-of-thought console output for this run — every LLM call's raw "
        "prompt/response, every tool/sandbox command and result, every parsed agentic "
        "action/decision, every dynamic-graph node update — tagged [gid]. Default off "
        "(Settings.stage5_live_console); the full untruncated record is always in "
        "stage5/fvvw/logs/<gid>.<track>.jsonl regardless of this flag.",
    )
    run.add_argument(
        "--no-live",
        dest="live",
        action="store_false",
        help="Force chain-of-thought console output off for this run, overriding "
        "Settings.stage5_live_console.",
    )
    run.add_argument(
        "--hitl",
        choices=["off", "prompt"],
        default=None,
        metavar="{off,prompt}",
        help="'prompt' pauses after a track exhausts its own budget without a decisive "
        "verdict and offers the operator retry/override_plan/inject/force_verdict/skip. "
        "FORCES stage5_workers=1 (a blocking terminal prompt cannot safely interleave "
        "with a concurrent candidate's own stdout) — a notice is printed when this "
        "happens. Default 'off' (unattended, today's behavior, unchanged).",
    )
    run.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        metavar="N",
        help="Override the static track's stage5_max_agent_iterations for this run.",
    )
    run.add_argument(
        "--dynamic-max-iterations",
        type=int,
        default=None,
        metavar="N",
        help="Override the dynamic track's stage5_dynamic_max_iterations for this run.",
    )
    run.add_argument(
        "--dynamic-wall-clock",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Override stage5_dynamic_wall_clock_seconds — the hard real-elapsed-time "
        "budget for the WHOLE dynamic-track graph invocation (Nodes 2-8, across every "
        "loop-back), independent of --dynamic-max-iterations' round count. Minimum 60. "
        "Exceeding it ends the dynamic track INCONCLUSIVE/budget_exhausted rather than "
        "hanging the candidate indefinitely.",
    )
    run.add_argument(
        "--benign-only",
        action="store_true",
        help="Flip the stage5_allow_real_payloads kill-switch OFF for this run — the Node 6 "
        "trigger agent crafts only a benign, distinguishing marker (e.g. "
        "';touch /tmp/<id>_proof;') instead of the actual malicious input a hypothesis "
        "calls for, restoring the original benign-marker-only invariant "
        "(validate_benign_marker). Default: real payloads ARE allowed (Settings."
        "stage5_allow_real_payloads=True) inside the disposable, network-isolated sandbox.",
    )
    run.add_argument(
        "--no-command-log",
        action="store_true",
        help="Disable stage5/fvvw/logs/<gid>.<track>.jsonl command logging for this run "
        "(Settings.stage5_command_log=False) — the LangSmith span record (if --trace is "
        "also passed) is unaffected either way.",
    )
    run.add_argument(
        "--claims",
        action="store_true",
        help=(
            "Read <db_subfolder>/stage3b/findings/ (Stage 3b's externally-sourced PDF "
            "report claims — see `fw-claims ingest`) instead of Stage 3's own "
            "<db_subfolder>/stage3/findings/."
        ),
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
    dbg_strategy.add_argument(
        "--no-live",
        action="store_true",
        help="Don't print the raw prompt/response and parsed StrategyPlan/parse "
        "failures as they happen — just show the finished plan.",
    )

    dbg_dynamic = dbg_sub.add_parser(
        "dynamic",
        help="Run ONLY the dynamic (QEMU+GDB) track for one finding — no static track, "
        "no crosscheck, no joint evaluation, no report. The QEMU-only counterpart to "
        "`debug build-cpg`/`debug script`'s Joern-only path.",
    )
    dbg_dynamic.add_argument("--db-subfolder", type=str, required=True)
    dbg_dynamic.add_argument("--gid", type=str, required=True, help="Global finding id.")
    dbg_dynamic.add_argument(
        "--no-live",
        action="store_true",
        help="Don't print every LLM call/tool call/parsed action/node update as it "
        "happens — just wait and show the finished (or stopped-after) result.",
    )
    dbg_dynamic.add_argument(
        "--stop-after",
        choices=_DYNAMIC_GRAPH_NODES,
        default=None,
        metavar="NODE",
        help="Halt the dynamic graph right after this node fires, for per-node "
        "diagnosis without running the rest of the track — one of: "
        + ", ".join(_DYNAMIC_GRAPH_NODES)
        + ". If the node never fires this round (e.g. a conditional edge skips it), "
        "the graph simply runs to completion as if this were not passed.",
    )

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
    dbg_fvvw.add_argument(
        "--no-live",
        action="store_true",
        help="Don't print every LLM call/tool call/parsed result/node update from "
        "both tracks as it happens — just wait and show the finished report.",
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


def _cmd_run(
    args: argparse.Namespace,
    *,
    settings: Settings | None = None,
    registry: UsageRegistry | None = None,
) -> int:
    settings = settings or get_settings()
    updates: dict[str, object] = {}
    if args.model is not None:
        updates["stage5_verifier_model"] = args.model
    if args.keep_workspace:
        updates["stage5_keep_workspace"] = True
    if getattr(args, "max_iterations", None) is not None:
        updates["stage5_max_agent_iterations"] = args.max_iterations
    if getattr(args, "dynamic_max_iterations", None) is not None:
        updates["stage5_dynamic_max_iterations"] = args.dynamic_max_iterations
    if getattr(args, "dynamic_wall_clock", None) is not None:
        updates["stage5_dynamic_wall_clock_seconds"] = args.dynamic_wall_clock
    if getattr(args, "benign_only", False):
        updates["stage5_allow_real_payloads"] = False
    if getattr(args, "no_command_log", False):
        updates["stage5_command_log"] = False
    if getattr(args, "hitl", None) is not None:
        updates["stage5_hitl_mode"] = args.hitl
        if args.hitl == "prompt" and settings.stage5_workers != 1:
            print(
                "note: --hitl=prompt forces stage5_workers=1 — a blocking terminal "
                "prompt cannot safely interleave with a concurrent candidate's stdout.",
                file=sys.stderr,
            )
            updates["stage5_workers"] = 1
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
    dynamic_only = getattr(args, "dynamic_only", False)
    if joern_only and dynamic_only:
        print("error: --joern-only and --dynamic-only are mutually exclusive.", file=sys.stderr)
        return 2

    if joern_only:
        queue_fn = run_queue
        summary_path_fn = layout.stage5_summary_path
    elif dynamic_only:
        queue_fn = run_dynamic_only_queue
        summary_path_fn = layout.fvvw_dynamic_only_summary_path
    else:
        queue_fn = run_fvvw_queue
        summary_path_fn = layout.fvvw_summary_path
    findings_dir = (
        (db_subfolder / "stage3b" / "findings") if getattr(args, "claims", False) else None
    )
    live = args.live if getattr(args, "live", None) is not None else settings.stage5_live_console

    try:
        summary = asyncio.run(
            queue_fn(
                db_subfolder=db_subfolder,
                settings=settings,
                only_global_ids=only,
                run_id=args.run_id,
                findings_dir=findings_dir,
                live=live,
                **decisions_kwargs,
            )
        )
    except Stage5InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except UsageBudgetExceededError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Status: {summary.status}")
    print(
        f"Candidates: {summary.total_candidates} total, {summary.total_verified} verified, "
        f"{summary.total_failed} failed"
    )
    label = "Mechanism confidence tallies" if not (joern_only or dynamic_only) else "Verdicts"
    print(f"{label}: {summary.verdicts_by_type}")
    print(f"Summary: {summary_path_fn(layout.stage5_dir(db_subfolder))}")
    if dynamic_only:
        print("(Dynamic-track-only run — pass no flag for the full FVVW v3 fork-join.)")
    elif not joern_only:
        print(
            "(Full FVVW v3 fork-join run — pass --joern-only for the original "
            "static-only pipeline.)"
        )

    show_usage = args.usage if args.usage is not None else settings.llm_usage_console
    if show_usage and registry is not None:
        summary_text = format_usage_summary(
            registry.snapshot(stage="5", run_id=args.run_id or "")
        )
        if summary_text:
            print(f"\n{summary_text}")
    return 0


def _cmd_debug(
    args: argparse.Namespace,
    *,
    settings: Settings | None = None,
    registry: UsageRegistry | None = None,
) -> int:
    settings = settings or get_settings()
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

            on_step = None if args.no_live else make_transcript_on_step(args.gid)
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
                fvvw_debug_mod.debug_strategy(
                    Path(args.db_subfolder), args.gid, live=not args.no_live
                )
            )
            print(f"target: {result.target.model_dump_json(indent=2)}")
            print(f"plan: {result.plan.model_dump_json(indent=2)}")
        elif args.debug_command == "dynamic":
            stop_after = getattr(args, "stop_after", None)
            result = asyncio.run(
                fvvw_debug_mod.debug_dynamic(
                    Path(args.db_subfolder),
                    args.gid,
                    live=not args.no_live,
                    stop_after=stop_after,
                )
            )
            if stop_after is not None:
                print(f"--- stopped after node {stop_after!r} ---")
            print(f"verdict: {result.result.verdict.value}")
            print(f"proved_hypothesis: {result.result.proved_hypothesis}")
            print(f"guard_logs: {result.guard_logs}")
            print(f"gdb_transcript:\n{result.gdb_transcript}")
        elif args.debug_command == "fvvw":
            outcome = asyncio.run(
                fvvw_debug_mod.debug_fvvw(
                    Path(args.db_subfolder), args.gid, live=not args.no_live
                )
            )
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
    except UsageBudgetExceededError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    show_usage = args.usage if args.usage is not None else settings.llm_usage_console
    if show_usage and registry is not None:
        summary_text = format_usage_summary(registry.snapshot(stage="5-debug", run_id=""))
        if summary_text:
            print(f"\n{summary_text}")
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
    if args.rate_limit is not None:
        settings = settings.model_copy(update={"llm_rate_limit_rps": args.rate_limit})
    if args.max_cost is not None:
        settings = settings.model_copy(update={"llm_max_cost_usd": args.max_cost})
    configure_tracing(settings)

    run_id = getattr(args, "run_id", None) or "run"
    db_subfolder = Path(args.db_subfolder) if getattr(args, "db_subfolder", None) else None
    jsonl_path = None
    if settings.llm_usage_artifact and db_subfolder is not None:
        usage_dir_ = usage_layout.usage_dir(db_subfolder)
        jsonl_path = usage_layout.usage_jsonl_path(usage_dir_, stage="5", run_id=run_id)

    try:
        with usage_registry(jsonl_path=jsonl_path, settings=settings) as registry:
            try:
                if args.command == "run":
                    return _cmd_run(args, settings=settings, registry=registry)
                if args.command == "debug":
                    return _cmd_debug(args, settings=settings, registry=registry)
                return 2  # pragma: no cover - argparse enforces valid subcommands
            finally:
                if settings.llm_usage_artifact and db_subfolder is not None:
                    registry.write_report(
                        usage_layout.usage_report_path(
                            usage_layout.usage_dir(db_subfolder), stage="5", run_id=run_id
                        ),
                        stage="5",
                        run_id=getattr(args, "run_id", None) or "",
                    )
    finally:
        flush_traces()


if __name__ == "__main__":
    raise SystemExit(main())
