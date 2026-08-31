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
(build/run/evaluate against Joern, nothing else) exactly as it behaved
before FVVW v3 — that pipeline is reused **completely unmodified** as the
fork-join's static-track building block.

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
- **`tools/qemu_gdb_tool.py`** + **`fvvw/dynamic_track.py`**: the QEMU+GDB
  dynamic track. `plan_emulation` picks user- vs system-mode; `bringup_
  stabilize` starts (and repairs) a session container running the target
  under QEMU; `reach_target`/`satisfy_guards`/`instrument_trigger`/
  `collect_signals` drive a shared GDB session to reach the claimed
  vulnerable path, force each guard (logging its real default value
  first), inject a validated BENIGN marker at the sink, and gather ≥3
  independent corroborating signals; `dynamic_evaluate` is a deterministic
  rule engine implementing the hypothesis A/B switch — keep testing A;
  if it stalls, switch to proving B; terminate the moment either is
  proved.
- **`fvvw/joint.py`**: `joint_evaluate()` — the ONE function that reads
  both tracks' results — classifies their agreement
  (concordant/discordant/one-sided), the mechanism-confidence axis (a
  `discordant` disagreement NEVER auto-resolves to trusting one track), and
  the reachability-confidence axis (a forced guard caps this and never
  raises it).
- **`fvvw/graph.py`**: `run_fvvw()` wires it all together — characterize →
  strategy → fork the static and dynamic tracks (running concurrently) →
  await both → `joint_evaluate`.
- **`fvvw/report.py`**: `write_report()` — one LLM call composing the
  seven-layer disclosure document plus a reconciliation section, with every
  raw tool output (Joern script output, GDB transcript) quoted verbatim.
- **`fvvw/driver.py`**: `run_fvvw_queue()` — a bounded worker pool over
  candidates, persisting `FVVWReport` JSON + Markdown for each, entirely
  separate from the original `driver.py`'s own queue.
- **`cmdlog.py`**: `CommandLog` — per-track, append-only JSONL of every
  command either track executes plus its full result, always on by default
  (unlike LangSmith, not gated by `--trace`) so a failed run stays
  diagnosable from disk alone.
- **`fvvw/hitl.py`**: human-in-the-loop — when a track exhausts its own
  iteration/repair budget without a decisive verdict, `run_fvvw` (with
  `--hitl=prompt`) pauses after the fork-join barrier and offers the
  operator one of four interventions: retry with more iterations, override
  plan values, inject a raw payload/script, or force the verdict by hand
  with a rationale. A forced verdict is durably marked
  `evidence["human_attributed"]=True` and surfaces as an explicit caveat in
  the disclosure report — never presented as machine-derived.

## Files

See [CLAUDE.md](CLAUDE.md) for the full file-by-file table (static track
and fork-join sections).

## How to run

```bash
# Fork-join (default) — both tracks, joint verdict, disclosure report
fw-verify run --db-subfolder data/db/<stem>

# Original static-only pipeline
fw-verify run --db-subfolder data/db/<stem> --joern-only --model ollama:qwen3:32b

# Each track individually
fw-verify debug build-cpg --db-subfolder data/db/<stem> --bin-id <bin_id>   # Joern, no LLM
fw-verify debug verify --db-subfolder data/db/<stem> --gid "<gid>"          # Joern track only
fw-verify debug dynamic --db-subfolder data/db/<stem> --gid "<gid>"        # QEMU+GDB track only
fw-verify debug fvvw --db-subfolder data/db/<stem> --gid "<gid>" --output report.json  # both, dry run

# Human-in-the-loop: pauses when a track exhausts its budget without a
# decisive verdict, forces stage5_workers=1
fw-verify run --db-subfolder data/db/<stem> --hitl=prompt \
    --max-iterations 10 --dynamic-max-iterations 8
```

## Input

`stage3/findings/*.json` (Stage 3) + `stage2/stage2_summary.json` (Stage 2
— resolves the static track's decompiled C AND, new for the dynamic track,
the real ELF/rootfs/arch facts).

## Output

`data/db/<stem>/stage5/`:

- **Static track** (`--joern-only`): `verifications/<gid>.json`
  (`common.verification.VerificationReport`), `reports/<gid>.md`,
  `stage5_summary.json` — unchanged from before FVVW v3.
- **Fork-join** (default), a SEPARATE subtree: `fvvw/reports/<gid>.json`
  (`common.verification.FVVWReport` — both tracks' results, the two-axis
  verdict, residual unknowns), `fvvw/reports/<gid>.md` (the LLM-composed
  disclosure document), `fvvw_summary.json`, and
  `fvvw/logs/<gid>.static.jsonl` / `fvvw/logs/<gid>.dynamic.jsonl` — every
  command either track ran plus its full result, for when a candidate
  needs debugging beyond what the report quotes.

Neither path writes into an earlier stage's tree, and the two output
subtrees never collide even against the same `db_subfolder`.

## Debugging

Every control point is exposed independently: `fw-verify debug build-cpg`/
`debug script` bypass the LLM entirely for the Joern mechanics;
`fw-verify debug strategy` runs just the strategy agent; `fw-verify debug
dynamic` runs ONLY the QEMU+GDB track; `fw-verify debug verify` runs the
Joern track alone; `fw-verify debug fvvw` runs the complete fork-join as a
dry run. See [CLAUDE.md](CLAUDE.md)'s Debugging section for the full
command reference and common errors.

`--trace` additionally traces every LLM call and sandboxed tool call in
LangSmith — one root run per candidate (`stage5.fvvw.candidate` or
`stage5.candidate` for `--joern-only`), with `run_type="tool"` spans around
every Docker/QEMU/GDB call. See the project root `CLAUDE.md`'s
Observability section.

## What changed from v1 (pre-FVVW-v3)

The original v1 pipeline (Joern-only, `agent/graph.py`'s generate/run/
evaluate loop) is **completely unchanged** — every file it touches is
reused verbatim by the fork-join's static track, and remains directly
reachable via `--joern-only`. Everything else described above is additive:
a new `fvvw/` package, new `tools/characterize_tool.py`/
`crosscheck_tool.py`/`qemu_gdb_tool.py`/`verification_sandbox.py`, a
session capability added alongside (never replacing) `SandboxExecutor`'s
one-shot `run()`, and a second Docker image
(`docker/Dockerfile.verification`) kept separate from `docker/
Dockerfile.joern`.

## Explicitly deferred (not designed away)

- A real MCP server exposing these tools over JSON-RPC, if cross-client
  interop is ever wanted.
- `Settings.stage5_checkpoint_backend="sqlite"` needs
  `pip install -e ".[stage5-fvvw]"` (`langgraph-checkpoint-sqlite`) — the
  default `"memory"` backend needs nothing extra.

See the [project CLAUDE.md](../../CLAUDE.md) and
[project README.md](../../README.md) for the overall pipeline, the
Executor abstraction, and LLM provider setup.
