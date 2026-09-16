# Stage 5 — Sandboxed Verification (FVVW v3 fork-join)

Proves or disproves one Stage 3 finding by verifying it **two independent
ways** — actually building a Code Property Graph (CPG) and running Joern/
CPGQL queries against it (the **static track**), and actually emulating the
real binary under QEMU with GDB attached (the **dynamic track**) — under
one LLM-authored strategy plan, then reconciling both witnesses into a
two-axis verdict (mechanism confidence × reachability confidence) plus a
disclosure report. This is the first stage in the pipeline that executes
anything, rather than reasoning over static text alone.

`fw-verify run` drives the full fork-join **by default**.
`fw-verify run --joern-only` reaches the original static-only pipeline
(build/run/evaluate against Joern, nothing else) as the fork-join's
static-track building block — reused unmodified by FVVW feature work, with
one correctness exception (see "What changed from v1" below).
`fw-verify run --dynamic-only` is the production counterpart for the
dynamic (QEMU+GDB) track alone. `--live` (any mode; default on for every
`debug` subcommand) prints chain-of-thought console output — every LLM
call's raw prompt/response, every tool/sandbox command+result, every
parsed agentic action/decision, every dynamic-graph node update — tagged
`[gid]`, as it happens.

## What it does

- **`candidate_index.py`**: reads `stage3/findings/*.json` (ESCALATE by
  default) and resolves each finding's binary to Stage 2's
  `normalized/joern/whole.c` (for the static track) — and now ALSO to the
  real ELF + `rootfs_dir` + Stage 2's already-computed `elf`/`functions`
  facts (for `characterize_target`/the dynamic track), via
  `resolve_binary_target()`.
- **`tools/characterize_tool.py`**: `characterize_target()` builds
  `mem.target` — arch/endianness/stripped/libc seeded from Stage 2's
  already-computed `ELFInfo`, plus PIE (a cheap, dependency-free ELF-header
  read) and function-offset validation the earlier stages never captured.
- **`fvvw/strategy.py`**: one LLM pass (`strategy_agent`) produces a
  `StrategyPlan` — a threat model, a hypothesis A/B pair with one decisive
  observable, and BOTH tracks' plans (`StaticPlan`, `DynamicPlan`) —
  translating the finding's prose guards into the dynamic track's
  structured `guards` list.
- **`fvvw/static_track.py`**: wraps the ORIGINAL Joern
  `build_verifier_graph()` unchanged, feeding it a strategy-enriched brief.
- **`tools/crosscheck_tool.py`**: `static_crosscheck()` independently
  disassembles the real ELF to confirm/refute the static plan's expected
  calls and sanitizer patterns — a signal from the real binary, not the
  decompiled C the Joern track works from.
- **`tools/qemu_gdb_tool.py`** + **`fvvw/dynamic_track.py`** +
  **`fvvw/dynamic_agents.py`** + **`fvvw/dynamic_graph.py`** +
  **`fvvw/dynamic_prompts.py`**: the QEMU+GDB dynamic track — a compiled
  **9-node agentic `StateGraph`** (Node 1 is the shared strategy agent
  above; Nodes 2-8 are `fvvw/dynamic_graph.py::build_dynamic_graph()`; Node
  9 is `joint_evaluate`/`write_report` below). `plan_emulation` picks
  user-/system-/direct-call-mode; `bringup_agent` (Node 3, an LLM agent) and
  `trigger_agent` (Node 6, an LLM agent) drive the live QEMU+GDB session
  themselves via a bounded JSON-action tool-calling loop — discovering
  missing files via `strace`, creating dummy fixes, then crafting and
  delivering the actual payload — with `bringup_stabilize`/`reach_target`/
  `satisfy_guards`/`instrument_trigger`/`collect_observation`
  (`fvvw/dynamic_track.py`) doing the deterministic legwork underneath
  them; `health_gate` (Node 4) is a deterministic liveness check between
  the two. Node 8 (`_run_evaluate_route`) tries a deterministic oracle-match
  first, and only calls an LLM router (`route_observation`) when that's
  ambiguous — its decision drives real conditional loop-back edges (retry
  bring-up/GDB-attach/trigger, or escalate to a direct-call harness) instead
  of a fixed retry count. `Settings.stage5_allow_real_payloads` (default
  `True`) governs whether the trigger agent crafts the actual malicious
  input (containment comes from the disposable, network-isolated sandbox,
  not the payload content) or falls back to the original benign-marker-only
  posture (`--benign-only`). `Settings.stage5_dynamic_wall_clock_seconds`
  bounds the whole graph invocation's real elapsed time, independent of its
  iteration count.
- **`fvvw/joint.py`**: `joint_evaluate()` — the ONE function that reads
  both tracks' results — classifies their agreement
  (concordant/discordant/one-sided/**neither**, when NEITHER track reached a
  definite verdict), the mechanism-confidence axis (a `discordant`
  disagreement NEVER auto-resolves to trusting one track), and the
  reachability-confidence axis (a forced guard caps this and never raises
  it).
- **`fvvw/graph.py`**: `run_fvvw()` wires it all together — characterize →
  strategy → fork the static and dynamic tracks (running concurrently) →
  await both → `joint_evaluate`. `run_dynamic_only()` is the dynamic-only
  counterpart (characterize → strategy → the dynamic track alone), backing
  `--dynamic-only`. Every one of the seven LLM roles is wrapped in
  `llm_logging.LoggingChatModel` for before/after-parser visibility, and
  `run_dynamic_track_only()` streams the dynamic graph via
  `streaming.stream_graph_live()` instead of a bare `ainvoke`, giving live
  per-node output and an optional `stop_after` early-exit.
- **`fvvw/report.py`**: `write_report()` — one LLM call composing the
  seven-layer disclosure document plus a reconciliation section, with every
  raw tool output (Joern script output, GDB transcript) quoted verbatim.
  `static_result=None` (the dynamic-only path) composes a dynamic-track-only
  disclosure instead, skipping the reconciliation section entirely.
- **`fvvw/driver.py`**: `run_fvvw_queue()` — a bounded worker pool over
  candidates, persisting `FVVWReport` JSON + Markdown for each, entirely
  separate from the original `driver.py`'s own queue. `run_dynamic_only_queue()`
  is the `--dynamic-only` counterpart, persisting
  `common.verification.DynamicOnlyReport` to its own `fvvw/dynamic_only/`
  subtree.
- **`cmdlog.py`**: `CommandLog` — per-track, append-only JSONL of every
  command either track executes plus its full result, always on by default
  (unlike LangSmith, not gated by `--trace`) so a failed run stays
  diagnosable from disk alone. An optional `live` console (`live_console.py`)
  echoes every record — LLM call, tool call, parsed action, node update —
  to the terminal as it's written, even when the JSONL write itself is
  disabled (`--no-command-log --live`).
- **`fvvw/hitl.py`**: human-in-the-loop — when a track exhausts its own
  iteration/repair budget without a decisive verdict (or when NEITHER track
  proves anything even without exhausting its budget —
  `neither_proved()`), `run_fvvw` (with `--hitl=prompt`) pauses after the
  fork-join barrier and offers the operator one of four interventions:
  retry with more iterations, override plan values, inject a raw
  payload/script, or force the verdict by hand with a rationale. A forced
  verdict is durably marked `evidence["human_attributed"]=True` and
  surfaces as an explicit caveat in the disclosure report — never presented
  as machine-derived.

## Files

See [CLAUDE.md](CLAUDE.md) for the full file-by-file table (static track
and fork-join sections).

## How to run

```bash
# Fork-join (default) — both tracks, joint verdict, disclosure report
fw-verify run --db-subfolder data/db/<stem>

# Original static-only pipeline
fw-verify run --db-subfolder data/db/<stem> --joern-only --model ollama:qwen3:32b

# Dynamic-track-only, persisted — the production counterpart to --joern-only
fw-verify run --db-subfolder data/db/<stem> --dynamic-only

# Chain-of-thought console output for a production run (default off)
fw-verify run --db-subfolder data/db/<stem> --live

# Each track individually — live console output defaults ON for every
# debug subcommand (--no-live to quiet it)
fw-verify debug build-cpg --db-subfolder data/db/<stem> --bin-id <bin_id>   # Joern, no LLM
fw-verify debug verify --db-subfolder data/db/<stem> --gid "<gid>"          # Joern track only
fw-verify debug dynamic --db-subfolder data/db/<stem> --gid "<gid>"        # QEMU+GDB track only
fw-verify debug dynamic --db-subfolder data/db/<stem> --gid "<gid>" \
    --stop-after health_gate                    # halt right after one node, for diagnosis
fw-verify debug fvvw --db-subfolder data/db/<stem> --gid "<gid>" --output report.json  # both, dry run

# Human-in-the-loop: pauses when a track exhausts its budget without a
# decisive verdict, forces stage5_workers=1
fw-verify run --db-subfolder data/db/<stem> --hitl=prompt \
    --max-iterations 10 --dynamic-max-iterations 8

# Dynamic-track containment/budget overrides
fw-verify run --db-subfolder data/db/<stem> --benign-only              # restore the pre-v3 benign-marker-only posture
fw-verify run --db-subfolder data/db/<stem> --dynamic-wall-clock 900   # cap the whole dynamic graph's real elapsed time (min 60s)

# Token usage / cost controls
fw-verify run --db-subfolder data/db/<stem> --rate-limit 2 --max-cost 5.00 --no-usage

# Verify Stage 3b's externally-sourced PDF report claims instead of
# Stage 3's own findings (see fw_audit/stage3b_claims/README.md)
fw-verify run --db-subfolder data/db/<stem> --claims
```

## Input

`stage3/findings/*.json` (Stage 3), or `stage3b/findings/*.json` (Stage 3b,
with `--claims`) + `stage2/stage2_summary.json` (Stage 2 — resolves the
static track's decompiled C AND, new for the dynamic track, the real
ELF/rootfs/arch facts).

## Output

`data/db/<stem>/stage5/`:

- **Static track** (`--joern-only`): `verifications/<gid>.json`
  (`common.verification.VerificationReport`), `reports/<gid>.md`,
  `stage5_summary.json` — unchanged from before FVVW v3.
- **Fork-join** (default), a SEPARATE subtree: `fvvw/reports/<gid>.json`
  (`common.verification.FVVWReport` — both tracks' results, the two-axis
  verdict, residual unknowns, and, from the dynamic track's 9-node graph:
  `arbitration_log` (every fix Node 3's bring-up agent applied),
  `observation` (Node 7's final signal/crash capture), `iteration_history`
  (every routing decision Node 8 made across the run), `emulation_mode`),
  `fvvw/reports/<gid>.md` (the LLM-composed disclosure document),
  `fvvw_summary.json`, and `fvvw/logs/<gid>.static.jsonl` /
  `fvvw/logs/<gid>.dynamic.jsonl` — every command either track ran plus its
  full result, for when a candidate needs debugging beyond what the report
  quotes.
- **Dynamic-only** (`--dynamic-only`), a THIRD, separate subtree:
  `fvvw/dynamic_only/reports/<gid>.json` (`common.verification.
  DynamicOnlyReport` — no `static_result`/`agreement`/confidence axes, since
  there's no static track to reconcile against), `fvvw/dynamic_only/reports/
  <gid>.md`, `fvvw_dynamic_only_summary.json`. Shares
  `fvvw/dynamic_workspace/`/`fvvw/logs/<gid>.dynamic.jsonl` with the
  fork-join.

None of the three paths writes into an earlier stage's tree, and no two
output subtrees collide even against the same `db_subfolder`.

## Debugging

Every control point is exposed independently: `fw-verify debug build-cpg`/
`debug script` bypass the LLM entirely for the Joern mechanics;
`fw-verify debug strategy` runs just the strategy agent; `fw-verify debug
dynamic` runs ONLY the QEMU+GDB track (`--stop-after NODE` halts right
after one of its 7 nodes fires, for per-node diagnosis without running the
rest); `fw-verify debug verify` runs the Joern track alone; `fw-verify
debug fvvw` runs the complete fork-join as a dry run. `--live` (on by
default for every `debug` subcommand) is a third, purely local visibility
sink alongside LangSmith (`--trace`, cloud) and `cmdlog` (disk JSONL) — see
[CLAUDE.md](CLAUDE.md)'s Debugging section for the full command reference
and common errors.

`--trace` additionally traces every LLM call and sandboxed tool call in
LangSmith — one root run per candidate (`stage5.fvvw.candidate` or
`stage5.candidate` for `--joern-only`), with `run_type="tool"` spans around
every Docker/QEMU/GDB call. See the project root `CLAUDE.md`'s
Observability section.

## What changed from v1 (pre-FVVW-v3)

The original v1 pipeline (Joern-only, `agent/graph.py`'s generate/run/
evaluate loop) is reused verbatim BY FVVW FEATURE WORK — every file it
touches stays untouched for the sake of adding fork-join capability, and
it remains directly reachable via `--joern-only`. It has since gained a
**positive-proof discipline fix** (CONFIRMED/REFUTED now requires the
evaluator to have actually named which hypothesis it proved, not just
printed a marker) — a correctness fix, not FVVW feature work. A SECOND,
narrowly-scoped exception: `agent/verifier.py` wraps its two LLMs in
`llm_logging.LoggingChatModel` for chain-of-thought visibility, and
`driver.py` starts exercising `verify_candidate`'s own pre-existing
`on_step` parameter — both purely additive, composition-based, and never
touching `agent/graph.py`/`agent/prompts.py`'s actual loop logic. See
[CLAUDE.md](CLAUDE.md)'s hard-constraints section for both exceptions'
exact rules and rationale. Everything else described above is additive: a
new `fvvw/` package (now including the dynamic track's own 9-node agentic
`StateGraph` — `fvvw/dynamic_graph.py`/`dynamic_agents.py`/
`dynamic_prompts.py`), new `tools/characterize_tool.py`/`crosscheck_tool.py`/
`qemu_gdb_tool.py`/`verification_sandbox.py`, a session capability added
alongside (never replacing) `SandboxExecutor`'s one-shot `run()`, a second
Docker image (`docker/Dockerfile.verification`) kept separate from
`docker/Dockerfile.joern`, and the chain-of-thought/live-console layer
(`live_console.py`/`llm_logging.py`/`streaming.py`).

## Explicitly deferred (not designed away)

- A real MCP server exposing these tools over JSON-RPC, if cross-client
  interop is ever wanted.
- `Settings.stage5_checkpoint_backend="sqlite"` needs
  `pip install -e ".[stage5-fvvw]"` (`langgraph-checkpoint-sqlite`) — the
  default `"memory"` backend needs nothing extra.

See the [project CLAUDE.md](../../CLAUDE.md) and
[project README.md](../../README.md) for the overall pipeline, the
Executor abstraction, and LLM provider setup.
