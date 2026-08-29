# CLAUDE.md — Stage 5: Sandboxed Verification (FVVW v3 fork-join)

Read this file first for Stage 5 work. Stage 5 verifies one Stage 3
finding **two independent ways** — the original **Joern static track**
(unchanged since v1) and a new **QEMU+GDB dynamic track** — under one
LLM-authored strategy plan, reconciled by a deterministic **joint
evaluator** into a two-axis verdict (mechanism confidence × reachability
confidence) plus an LLM-composed disclosure report. `fw-verify run` drives
this fork-join **by default**; `--joern-only` routes to the original
static-only pipeline, byte-for-byte unchanged. Root `CLAUDE.md` covers only
cross-cutting concerns (Executor abstraction, LLM routing, Settings).

## Hard constraints — never violate

- Never write into `stage2/`, `stage3/`, or `stage4/` — only into this
  stage's own `stage5/` directory.
- `candidate_index.discover_candidates()` reads **Stage 3 findings only**
  (`stage3/findings/*.json`) — never `stage4/taint/*.json`, even when
  present. A deliberate scope choice, not an oversight.
- **Never reintroduce `--param cpgPath=`.** The CPG is bound POSITIONALLY
  as `cpg` (`joern --script q.sc cpg.bin`) — `--param` only binds to a
  script-declared `@main def`, which a plain expression script doesn't
  have, and fails with an "unknown arguments" error. See
  `tools/joern_tool.py`'s module docstring for the full post-mortem.
- **The existing Joern pipeline (`agent/`, `tools/joern_tool.py`,
  `driver.py`, `debug.py`, `report_writer.py`, `docker/Dockerfile.joern`,
  `SandboxExecutor.run()`) is reused UNCHANGED as the static track's
  building block.** `fvvw/static_track.py` is a thin adapter that renders
  a strategy-enriched brief and invokes `build_verifier_graph()` verbatim —
  it never edits the generator/evaluator prompts, the graph, or the tool.
  Do not "improve" the static track's generate/run/evaluate loop into a
  template-first design as part of FVVW work; that divergence from the
  design doc's script-first ideal is accepted deliberately, as the cost of
  reuse.
- Command composition for the dynamic track lives entirely in
  `tools/qemu_gdb_tool.py` — the strategy LLM supplies only `DynamicPlan`
  DATA (addresses, guard names/forced values, the payload marker), never a
  shell command line.
- **Benign-marker-only, hard-enforced.** `fvvw.dynamic_track.
  validate_benign_marker()` rejects any `payload_marker` that isn't a
  scoped `touch`/`echo`/`mkdir -p` side effect — checked BEFORE
  `instrument_trigger` issues any command. Never weaken this validator to
  accommodate a "more realistic" payload; the dynamic track produces
  verification infrastructure, never an exploit.
- `SandboxExecutor.run()` (Joern's one-shot call) is **not modified** by
  the dynamic track's session capability (`start()`/`exec_in_session()`/
  `stop()`, added alongside it) — see `executors/sandbox_executor.py`'s
  module docstring.
- `debug.py`'s and `fvvw/debug.py`'s functions never persist into
  `verifications/`/`reports/`/`fvvw/reports/` — every debug function is a
  dry run.
- `joint_evaluate` (`fvvw/joint.py`) is the ONLY function permitted to read
  both `static_result` and `dynamic_result` — see `fvvw/state.py`'s key
  tuples for the mechanical isolation this enforces.

## Files

### Static track (v1, unchanged — never edit for FVVW work)

| File | Purpose |
|---|---|
| `layout.py` | Pure path algebra for `stage5/` — **now also carries the separate `fvvw/` subtree's paths** (additive; the original static-track paths are untouched). |
| `candidate_index.py` | Resolves `stage3/findings/*.json` into `VerificationCandidate`s. Resolves `source_path` (the Joern C, for the static track) via `stage2_summary.json` — **and now also resolves `binary_path`/`rootfs_dir`/`elf`/`functions`** (the real ELF + Stage 2's already-computed facts, for `characterize_target`/the dynamic track) via `resolve_binary_target()`. |
| `errors.py` | `Stage5InputError`, `SandboxUnavailableError`, `VerifierModelUnavailableError`. |
| `tools/joern_tool.py` | `build_cpg_async`/`run_joern_script_async` + `joern_executor()`. Owns the exact Joern CLI command strings. |
| `agent/cleaning.py` | Strips `<think>` blocks/markdown fences from a local model's response — reused by `fvvw/strategy.py`. |
| `agent/transcript.py`, `agent/prompts.py`, `agent/graph.py`, `agent/verifier.py` | The unmodified generate/run/evaluate loop — see the old v1 description below. |
| `driver.py` | The original static-only worker pool — `run_queue()`, reachable via `fw-verify run --joern-only`. |
| `report_writer.py` | Renders one `VerificationReport` to Markdown (the static track's own artifact). |
| `debug.py` | `debug_build_cpg`/`debug_run_script`/`debug_verify` — Joern-only debug entry points. `find_candidate()` (public; `_find_candidate` kept as an alias) is reused by `fvvw/debug.py`. |

`agent/graph.py`'s loop: `build_cpg` → `generate_script` → `run_script` →
`evaluate`, looping back to `generate_script` on `FAIL_RETRY` until
`evaluate` returns `PASS`/`FAIL_STOP` or `stage5_max_agent_iterations`
forces the downgrade, then `conclude` derives the final
`VerificationVerdict`. Neither the generator nor the evaluator does
tool-calling — both are plain text in/text out, for local-model reliability.

### FVVW v3 fork-join (new — `fvvw/`)

| File | Purpose |
|---|---|
| `fvvw/state.py` | `FVVWState` (the LangGraph state / STM) + the `STATIC_TRACK_*`/`DYNAMIC_TRACK_*`/`JOINT_EVALUATE_READABLE_KEYS` tuples that make track isolation mechanical. |
| `tools/characterize_tool.py` | `characterize_target()` — builds `mem.target` (`TargetMeta`), seeded from Stage 2's `DecompiledBinary.elf`/`.functions`; only computes PIE (dependency-free ELF header read, no `readelf`) and `dispatch_resolvable` itself. Raises `Stage5InputError` ("target mismatch") if the claimed function offset doesn't resolve against the real binary's function table. |
| `fvvw/strategy.py` | `strategy_agent()` — one LLM pass producing `StrategyPlan` (threat model, hypothesis A/B pair, `StaticPlan`, `DynamicPlan`) as plain-text JSON, parsed via the EXISTING `agent.cleaning.clean_json_payload`. `validate_decisive_observable()` is the deterministic post-check. |
| `fvvw/static_track.py` | `run_static_track()` — renders a strategy-enriched brief (`render_static_brief`, layered on top of the existing `agent.prompts.render_finding_brief`) and invokes `build_verifier_graph()` **unmodified**; maps the terminal state into a `TrackResult`. |
| `tools/crosscheck_tool.py` | `static_crosscheck()` — disassembles the REAL ELF (`objdump -d -C`) and confirms/refutes `StaticPlan.expected_intermediate_calls`/`.sanitizer_patterns` against it — an independent signal from the decompiled-C-based Joern track. |
| `tools/qemu_gdb_tool.py` | Owns every `qemu-*`/`gdb-multiarch` command: the full arch table (`QEMU_ARCH_TABLE` — arm/armeb/aarch64/mips/mipsel/mips64/mips64el/ppc/ppc64, user+system binaries, per-arch argument registers, CPU-probe env fixes), launch-command assembly, the GDB batch-recipe renderer. |
| `fvvw/dynamic_track.py` | The seven dynamic-track functions: `plan_emulation`, `bringup_stabilize`/`BringupContext`/`BringupExhausted` (session stand-up + repair), `reach_target`/`satisfy_guards`/`instrument_trigger`/`collect_signals` (drive the GDB session via `exec_in_session`), `dynamic_evaluate` (the hypothesis A/B rule engine). `validate_benign_marker`/`BenignMarkerViolation` — the hard safety invariant. |
| `fvvw/joint.py` | `joint_evaluate()` — the only function reading both `TrackResult`s. `classify_agreement`/`classify_mechanism_confidence`/`classify_reachability_confidence`/`collect_residual_unknowns`. |
| `fvvw/graph.py` | `run_fvvw()` — the actual fork-join: `characterize → strategy → fork(static_track, static_crosscheck, run_dynamic_track_only running concurrently) → await both → joint_evaluate`. `resolve_checkpointer()`, `FVVWDeps`/`resolve_fvvw_deps()`. |
| `fvvw/report.py` | `write_report()` — one LLM call composing the seven-layer disclosure document + reconciliation section, with every raw tool output (Joern attempts, GDB transcript) quoted verbatim. |
| `fvvw/driver.py` | `run_fvvw_queue()` — a SEPARATE worker-pool queue (not an extension of `driver.py`) persisting `FVVWReport` JSON + disclosure Markdown to `stage5/fvvw/reports/`. |
| `fvvw/debug.py` | `debug_strategy` (strategy only), `debug_dynamic` (dynamic track ONLY — the per-track debug path), `debug_fvvw` (full fork-join, dry run). |
| `tools/verification_sandbox.py` | `verification_executor()`/`verification_session_executor()` — resolve an `Executor`/session-capable `SandboxExecutor` pointed at `stage5_verification_image` (a SEPARATE image from Joern's). |

## Invoke

```bash
# Fork-join (default)
fw-verify run --db-subfolder data/db/<stem>
fw-verify run --db-subfolder data/db/<stem> --only "<chunk_id>::<finding_id>"
fw-verify run --db-subfolder data/db/<stem> --decisions CONTEXT_REQUIRED,ESCALATE

# Static-only, pre-FVVW-v3 behavior
fw-verify run --db-subfolder data/db/<stem> --joern-only --model ollama:qwen3:32b --keep-workspace

# Per-track debug — each track runnable individually
fw-verify debug build-cpg --db-subfolder data/db/<stem> --bin-id <bin_id>          # Joern, no LLM
fw-verify debug script --workspace data/db/<stem>/stage5/workspace/<gid> --script-file q.sc  # Joern, no LLM
fw-verify debug verify --db-subfolder data/db/<stem> --gid "<gid>" \
    --prompt-file my_prompt.txt --output report.json                              # Joern track only
fw-verify debug strategy --db-subfolder data/db/<stem> --gid "<gid>"              # strategy_agent only
fw-verify debug dynamic --db-subfolder data/db/<stem> --gid "<gid>"               # QEMU+GDB track only
fw-verify debug fvvw --db-subfolder data/db/<stem> --gid "<gid>" --output report.json  # full fork-join, dry run
```

`--model` sets `FWA_STAGE5_VERIFIER_MODEL`, which every Stage 5 LLM role
falls back to unless its own `FWA_STAGE5_*_MODEL` (`GENERATOR`/`EVALUATOR`/
`STRATEGY`/`REPORT`) is set independently.

## Input

`stage3/findings/*.json` (Stage 3) + `stage2/stage2_summary.json` (Stage 2
— resolves both the static track's `normalized/joern/whole.c` AND, new for
the dynamic track, the real ELF via `rootfs_dir`/`DecompiledBinary.
rootfs_path` plus `.elf`/`.functions`).

## Output — `data/db/<stem>/stage5/`

**Static track (`--joern-only`, unchanged):** `verifications/<gid>.json` →
`reports/<gid>.md` → `workspace/<gid>/` → `stage5_summary.json`.

**Fork-join (default), a SEPARATE subtree — never collides with the
above:** `fvvw/reports/<gid>.json` (`common.verification.FVVWReport`) →
`fvvw/reports/<gid>.md` (disclosure Markdown) →
`fvvw/dynamic_workspace/<gid>/` → `fvvw_summary.json`.

## Debugging

- `--trace` traces every LLM call and every sandboxed tool call
  (`run_type="tool"` spans: `stage5.build_cpg`, `stage5.run_joern_script`,
  `stage5.characterize_target`, `stage5.static_crosscheck`,
  `stage5.bringup_stabilize`, `stage5.reach_target`, `stage5.satisfy_guards`,
  `stage5.instrument_trigger`, `stage5.collect_signals`), plus
  `run_config()`-tagged LLM runs (`stage5.strategy_agent`,
  `stage5.generate_script`, `stage5.evaluate`, `stage5.fvvw.write_report`).
  Root run: `stage5.fvvw.candidate` (fork-join) or `stage5.candidate`
  (`--joern-only`). See root `CLAUDE.md`'s Observability section.
- `docker build -f docker/Dockerfile.joern -t fw-audit-joern:latest .` —
  the static track's image, unchanged.
- `docker build -f docker/Dockerfile.verification -t
  fw-audit-verification-sandbox:latest .` — the dynamic track's (and
  `characterize_target`/`static_crosscheck`'s) SEPARATE image. Reuses
  `Dockerfile.joern`'s fetch stage; needs the same pre-fetched
  `docker/.joern-cli.zip`.
- `Stage5InputError` on `run`/`debug verify`/`debug fvvw` → `stage3/findings/`
  or `stage2/stage2_summary.json` missing; run `fw-analyze --analyze` /
  `fw-extract` first. `debug_fvvw`/`run_fvvw` additionally raise this if a
  candidate's `source_path` never resolved (needed by the static track even
  in the fork-join).
- `characterize_target`'s "target mismatch" `Stage5InputError` → the
  finding's `evidence_span.function_id` doesn't resolve against the real
  binary's `DecompiledBinary.functions` table — the claim itself is wrong,
  not a tooling failure.
- `BenignMarkerViolation` from `instrument_trigger`/`dynamic_evaluate` →
  the strategy agent produced a `payload_marker` that failed the benign-only
  check — this is a hard stop, never worked around by loosening the
  validator; investigate why the strategy prompt produced it.
- `SandboxUnavailableError` → Docker unreachable, or a candidate's `bin_id`
  never resolved a `normalized_joern_c` path.
- `VerifierModelUnavailableError` → no usable credential for one of the
  FOUR Stage 5 roles now (`STAGE5_SCRIPT_GENERATOR`, `STAGE5_RESULT_EVALUATOR`,
  `STAGE5_STRATEGY_AGENT`, `STAGE5_REPORT_WRITER`); set `ANTHROPIC_API_KEY`
  or `FWA_STAGE5_VERIFIER_MODEL=ollama:qwen3:32b` (the shared fallback
  covers all four unless overridden individually).
- `Status: no_targets` with 0 candidates → check each finding's `decision`
  field (`grep -o '"decision": *"[A-Z_]*"' stage3/findings/*.json`); only
  `ESCALATE` is verified by default — pass `--decisions` to widen it.
- `fw-verify debug build-cpg`/`debug script` bypass the LLM entirely for
  the Joern mechanics; `fw-verify debug dynamic` runs ONLY the QEMU+GDB
  track (needs the strategy agent for a `DynamicPlan`, but not the static
  track); `fw-verify debug strategy` emits just the `StrategyPlan`.
- Unit: `pytest -m "not integration" tests/test_stage5_*.py
  tests/test_fvvw_*.py tests/test_sandbox_executor.py
  tests/test_sandbox_session_executor.py` — no Docker/LLM/QEMU/GDB required
  (`FakeExecutor` + duck-typed fake chat models + a fake session executor).

## Adding a feature here

- New STATIC-track tool behavior goes in `tools/`, never inline in
  `agent/graph.py` — and per the hard constraint above, don't touch
  `agent/graph.py`/`agent/prompts.py` for FVVW work at all.
- New DYNAMIC-track command composition goes in `tools/qemu_gdb_tool.py`,
  never inline in `fvvw/dynamic_track.py`'s node functions.
- New report fields go in `common/verification.py` (not `common/findings.py`
  or `common/taint.py`).
- A new repair case for `bringup_stabilize` goes in
  `fvvw/dynamic_track.py`'s `bringup_stabilize()`/`BringupContext` — write
  the fix to `ctx.applied_fixes` so a retry within the same run reuses it.
- A new arch for the dynamic track is one `QEMU_ARCH_TABLE` entry in
  `tools/qemu_gdb_tool.py`, not a new `if`/`elif` branch anywhere.
