# CLAUDE.md — Stage 5: Sandboxed Verification (FVVW v3 fork-join)

Read this file first for Stage 5 work. Stage 5 verifies one Stage 3
finding **two independent ways** — the original **Joern static track**
(unchanged since v1) and a **QEMU+GDB dynamic track** — under one
LLM-authored strategy plan, reconciled by a deterministic **joint
evaluator** into a two-axis verdict (mechanism confidence × reachability
confidence) plus an LLM-composed disclosure report. `fw-verify run` drives
this fork-join **by default**; `--joern-only` routes to the original
static-only pipeline, byte-for-byte unchanged. Root `CLAUDE.md` covers only
cross-cutting concerns (Executor abstraction, LLM routing, Settings).

**The dynamic track is a compiled 9-node agentic `StateGraph`** (spec
Nodes 1-9; Node 1 is the shared `strategy_agent` upstream, Node 9 stays
downstream in `joint_evaluate`/`write_report` — Nodes 2-8 are the compiled
graph itself, `fvvw/dynamic_graph.py::build_dynamic_graph`). Bring-up
(Node 3) and trigger crafting (Node 6) are **agentic tool-calling loops**
(`fvvw/dynamic_agents.py`) driving the persistent QEMU+GDB session
themselves via a bounded JSON-action ReAct cycle; Node 8 (Evaluator +
Router) runs a deterministic oracle-match first pass, falling through to
an LLM router only when that doesn't settle the round, and its
`RouteDecision` drives REAL conditional loop-back edges (Node 4/5/6 → Node
3) instead of the old in-function retry loops. See "The 9 nodes" section
below for the full node table and the architecture rationale.

## Hard constraints — never violate

- Never write into `stage2/`, `stage3/`, or `stage4/` — only into this
  stage's own `stage5/` directory.
- `candidate_index.discover_candidates()` reads **Stage 3 (or, with
  `--claims`, Stage 3b's externally-sourced) findings only**
  (`stage3/findings/*.json`, or `stage3b/findings/*.json` when
  `findings_dir=` is explicitly passed) — never `stage4/taint/*.json`, even
  when present. A deliberate scope choice, not an oversight: `--claims`
  swaps WHICH `AnalysisReport`-shaped directory is read, it never chains in
  Stage 4's derived taint output.
- **Never reintroduce `--param cpgPath=`.** The CPG is bound POSITIONALLY
  as `cpg` (`joern --script q.sc cpg.bin`) — `--param` only binds to a
  script-declared `@main def`, which a plain expression script doesn't
  have, and fails with an "unknown arguments" error. See
  `tools/joern_tool.py`'s module docstring for the full post-mortem.
- **The existing Joern pipeline (`agent/`, `tools/joern_tool.py`,
  `driver.py`, `debug.py`, `report_writer.py`, `docker/Dockerfile.joern`,
  `SandboxExecutor.run()`) is reused unchanged BY FVVW FEATURE WORK.**
  `fvvw/static_track.py` is a thin adapter that renders a strategy-enriched
  brief and invokes `build_verifier_graph()` verbatim. Do not "improve" the
  static track's generate/run/evaluate loop into a template-first design as
  part of FVVW work; that divergence from the design doc's script-first
  ideal is accepted deliberately, as the cost of reuse.
  **This constraint is scoped to FVVW feature work, not to correctness
  fixes in the static track's own loop** — those ARE in scope for edits to
  `agent/graph.py`/`agent/prompts.py`, and must be recorded here. As of the
  positive-proof fix below, the loop enforces: a verdict of
  CONFIRMED/REFUTED requires `EvaluatorVerdict.hypothesis_proved` to be
  `"A"`/`"B"` respectively (see `final_status()`); a round that proves
  neither (`hypothesis_proved == "none"`) is converted to a retry rather
  than accepted as a conclusion, reusing the existing `FAIL_RETRY` loop and
  its `stage5_max_agent_iterations` cap; at that cap, a round that DID print
  a marker but proved nothing exhausts to `INCONCLUSIVE` (not `ERROR` — see
  `evaluate_node`'s `unproven` distinction), tagging `budget_exhausted` so
  HITL still fires. The marker vocabulary grew from three to five:
  `FLOW_FOUND` (A), `FLOW_BLOCKED` (B, a named sanitizer/guard/constant),
  `FLOW_NOT_FOUND` (B, the weaker form — only legal once the generator's
  CHECK-1/2/3 health checks and, where a propagator sits on the path, a
  two-legged bridging query all corroborate it), `INDETERMINATE` (neither
  proved, health checks failed), `QUERY_ERROR` (script couldn't run). See
  `agent/prompts.py`'s `GENERATOR_SYSTEM_PROMPT`/`EVALUATOR_SYSTEM_PROMPT`
  for the full rationale — a bare empty `reachableByFlows` result must
  never mint a refutation, since it's equally consistent with a malformed
  query, an unmodeled propagator (`sprintf`/`strcpy`/`memcpy`/...), or a
  method the CPG's `ReachingDefPass` silently skipped (watch for "has more
  than N definitions" / "Skipping" in the CPG build stderr).
  `fvvw/static_track.py::run_static_track` mirrors this: `proved_hypothesis`
  is read directly from the evaluator's own judgement
  (`final_state["hypothesis_proved"]`), never relabelled from `verdict`.
  The strategy prompt (`fvvw/strategy.py`) requires the SAME positive-proof
  discipline for hypothesis B — it must name what would have to be observed
  to prove it (a specific sanitizer/guard/constant), never "the A-observable
  wasn't seen". The dynamic track's (pre-9-node-rewrite) `dynamic_evaluate()`
  (`fvvw/dynamic_track.py` — UNUSED by `dynamic_graph.py`'s Node 8, see
  "The 9 nodes" above; kept only for any code still calling it directly)
  applied the identical `>= required` multi-signal corroboration bar to
  BOTH hypotheses (previously B could fire off a single absence signal)
  and no longer threaded an `active_hypothesis` switch through the rule
  engine — that mechanism never actually changed what evidence was
  gathered, so it was removed rather than kept as a parameter that looked
  like it did something it didn't; both hypotheses' rules were evaluated
  identically every round. Node 8's CURRENT equivalent discipline lives in
  `dynamic_graph._build_track_result`'s `_TERMINAL_ROUTES` mapping (route
  → verdict + `proved_hypothesis`) and `dynamic_track.match_oracle`'s
  deterministic-first-pass gate — same positive-proof spirit, different
  mechanism. `fvvw/joint.py` gained
  `Agreement.NEITHER` (both tracks non-definite — distinct from
  `ONE_SIDED`, which requires exactly one definite verdict) and a
  `collect_residual_unknowns` defense-in-depth caveat for any REFUTED
  result lacking a positively-proved `"B"` (should be structurally
  impossible now, but flagged rather than silently trusted). `fvvw/hitl.py`
  gained `neither_proved()` — a THIRD HITL trigger (alongside each track's
  own `is_budget_exhausted`) that offers the static track for review when
  BOTH tracks settle on `"none"` without either individually exhausting its
  budget, via `_run_hitl_for_track`'s now-generalized `trigger` parameter.
- Command composition for the dynamic track lives entirely in
  `tools/qemu_gdb_tool.py` — the strategy LLM supplies only `DynamicPlan`
  DATA (addresses, guard names/forced values, the payload marker), never a
  shell command line.
- **Containment is structural, not content-based — the safety boundary
  the dynamic track actually enforces.** `Settings.
  stage5_allow_real_payloads` (default `True`) governs which validator
  `instrument_trigger`/the Node 6 trigger agent runs on a proposed
  payload: `True` (default) — the trigger agent may craft and deliver the
  ACTUAL malicious input a hypothesis calls for (overlong buffers,
  command-injection sequences, path-traversal sequences), checked by
  `validate_real_payload`, which HARD-blocks only weaponized content
  (reverse shells, exfiltration, destructive host commands — see
  `dynamic_track.py`'s deny-list), not "realistic" content in general.
  `False` (`--benign-only` / `FWA_STAGE5_ALLOW_REAL_PAYLOADS=false`)
  restores the ORIGINAL v1 invariant — `validate_benign_marker()` rejects
  any `payload_marker` that isn't a scoped `touch`/`echo`/`mkdir -p` side
  effect. Either way, containment comes from the SANDBOX, not the payload
  content: every dynamic-track run happens inside a disposable,
  `stage5_sandbox_*`-resource-capped, `--network=none` (unless
  `stage5_allow_network_grant`) container — see `docker/Dockerfile.
  verification`. Never weaken `validate_real_payload`'s deny-list or
  `validate_benign_marker` to accommodate a payload that needs MORE than
  what's already allowed; widen the sandbox's containment instead if a
  legitimate test needs it.
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
- **HITL never runs inside a track's own concurrent task.** The prompt is
  hoisted to `fvvw.graph.run_fvvw`, strictly AFTER the fork-join's barrier
  and BEFORE `joint_evaluate` — a blocking prompt inside a track would
  interleave stdout with a sibling candidate's own task in the worker pool.
  `--hitl=prompt` FORCES `stage5_workers=1` in `runner.py` for exactly this
  reason; don't relax that.
- **An operator-injected raw GDB recipe (HITL's "inject" action) gets its
  OWN gate**, `dynamic_track.validate_injected_recipe()` — never
  `validate_benign_marker`/`validate_real_payload` (which only understand
  payload TEXT, not a full recipe). The GDB-escape-hatch check inside it
  (`shell`/`!`/`pipe`/`python`/`define`/`source`/`dump` — host-execution
  prevention, a container-INTEGRITY concern) is enforced UNCONDITIONALLY,
  regardless of `stage5_allow_real_payloads`. Never weaken it to
  accommodate a "more capable" recipe.
- **The dynamic graph's node bodies never write graph state with a live
  object** (a `SessionHandle`, a `BaseChatModel`) — only DATA
  (`TrackResult`, `ArbitrationLog`, `ObservationRecord`, `RouteDecision`,
  strings, dicts). Every node closure captures the SAME long-lived
  `BringupContext` (built once per `build_dynamic_graph()` call) to carry
  the mutable session/launch state instead — a loop-back edge re-enters a
  node, which mutates that shared `ctx`, so `ctx.handle` never round-trips
  through `FVVWState` as a value. See `fvvw/dynamic_graph.py`'s module
  docstring.
- **Node 8's terminal routes (`confirmed`/`refuted`/`inconclusive`) are the
  ONLY place a `TrackResult` gets constructed for the dynamic track** —
  `dynamic_graph._build_track_result()`, fed by `_TERMINAL_ROUTES`. A
  `RouteDecision` itself carries no verdict, only a routing instruction —
  never read `decision.route` as a stand-in for a `VerificationVerdict`
  anywhere else.
- **`Settings.stage5_dynamic_wall_clock_seconds` bounds the WHOLE dynamic
  graph invocation's real elapsed time**, independent of
  `stage5_dynamic_max_iterations`' round count — enforced via
  `asyncio.wait_for` around `compiled.ainvoke(...)` in
  `fvvw.graph.run_dynamic_track_only`, not inside the graph itself (no
  partial `FVVWState` survives a timeout — a fixed INCONCLUSIVE/
  `budget_exhausted` `TrackResult` is synthesized instead). Never remove
  this wrapper; a stuck agentic loop (bring-up or trigger) must still
  terminate the candidate rather than hang the whole worker pool.

## The 9 nodes (dynamic track)

| # | Node | Type | Function(s) |
|---|---|---|---|
| 1 | Hypothesis + Oracle | LLM | `fvvw.strategy.strategy_agent` — shared with the static track; emits `Hypotheses.oracle`/`.disconfirm_condition` + `DynamicPlan.oracle`/`.disconfirm_condition` alongside the existing `decisive_observable` triple. `validate_decisive_observable` requires all of them non-empty. |
| 2 | Plan Emulation | Deterministic | `dynamic_track.plan_emulation` — `emulation_mode` incl. `direct_call` (the Node 8 router's `escalate_direct_call` route forces it via `plan_emulation_escalate_node`). |
| 3 | Bring-Up & Arbitration | **LLM agent + tools** | `dynamic_agents.bringup_agent` (a bounded JSON-action loop: `run_strace_discovery`/`inspect_binary`/`create_dummy_file`/`create_dummy_dir`/`create_device_node`/`force_env_var`/`relaunch_and_check`/`done`) driving `ctx.session_executor.exec_in_session` directly, THEN the deterministic `dynamic_track.bringup_stabilize`/`_launch_qemu_and_wait` underneath it. `dynamic_graph._run_bringup` retries a bare `DynamicFault` from `bringup_stabilize` itself in a bounded loop (bounded by `bringup_stabilize`'s own `repair_count` check) — this must never escape uncaught (see "Fixed bugs" below). |
| 4 | Health Gate | Deterministic | `dynamic_track.health_gate`/`HealthGateFailure` — `pgrep` liveness + a SECOND `/proc/net/tcp` gdbstub-rebind probe (distinct from `_launch_qemu_and_wait`'s own readiness probe). Failure routes back to Node 3 via `route_after_bringup`/`route_after_health_gate`. |
| 5 | GDB Attach & Instrument | Deterministic | `dynamic_track.reach_target` (reused). Stripped-symbol → address agent fallback is NOT implemented in this revision (`reach_target` already resolves its entry address from `Settings`-independent facts supplied upstream) — flagged in `dynamic_graph.py`'s module docstring as a future extension point, not silently omitted. |
| 6 | Trigger / PoC | **LLM agent** | `dynamic_agents.trigger_agent` (`craft_payload`/`apply_precondition`/`deliver_via_argv`/`deliver_via_network`/`deliver_via_direct_call`/`observe_result`/`done`) when `stage5_allow_real_payloads`, else the deterministic `instrument_trigger` (benign-marker) path — both live in `dynamic_graph._run_trigger`. Every crafted payload is validated (`validate_real_payload`/`validate_benign_marker`) BEFORE delivery; a rejection is reported back to the LLM as feedback, not silently downgraded. |
| 7 | Run & Observe | Deterministic | `dynamic_track.collect_observation` (benign path) or `TriggerAgentResult.observation` (agentic path — the trigger agent calls `collect_observation` itself as part of `observe_result`) → `common.verification.ObservationRecord` (signal/faulting_pc/registers/memory diff/stdout/stderr/filesystem_artifacts). |
| 8 | Evaluator + Router | **Deterministic first pass + LLM** | `dynamic_graph._run_evaluate_route`: `dynamic_track.match_oracle` (deterministic oracle-string match) first: HIT → `confirmed` with no LLM call. Else a hard `dynamic_iteration >= stage5_dynamic_max_iterations` cutoff → `inconclusive`, ALSO with no LLM call (never trust the router alone to stop looping). Else `dynamic_agents.route_observation` (the LLM router) diagnoses and picks one of the spec's seven routes. `_build_track_result` converts a terminal route into the actual `TrackResult`. |
| 9 | Report | Deterministic assembly | Outside this graph — `fvvw.graph.run_fvvw` assembles `common.verification.FVVWReport` (`arbitration_log`/`observation`/`iteration_history`/`emulation_mode` — Node 9's required contents #3/#4/#6/#7) from `run_dynamic_track_only`'s `dynamic_extras` bag; `fvvw.report.write_report` composes the disclosure Markdown, unchanged. |

`fvvw/dynamic_graph.py::build_dynamic_graph` compiles Nodes 2-8 into one
`StateGraph(FVVWState)` per candidate (closure-based factory, mirroring
`agent.graph.build_verifier_graph`'s shape). `fvvw.graph.
run_dynamic_track_only` is the thin wrapper: builds `BringupContext` +
`DynamicGraphDeps`, compiles, `ainvoke`s (wrapped in the wall-clock
`asyncio.wait_for`), unpacks the terminal `FVVWState` into the same
`(TrackResult, guard_logs, dynamic_reached_sink, gdb_transcript,
dynamic_extras)` 5-tuple every caller (`fvvw.graph.run_fvvw`'s fork,
HITL's dynamic-track retry, `fvvw.debug.debug_dynamic`) already expects —
the fork-join, `joint_evaluate`, HITL, and both drivers are otherwise
UNTOUCHED by the rewrite.

## Files

### Static track (v1, unchanged — never edit for FVVW work)

| File | Purpose |
|---|---|
| `layout.py` | Pure path algebra for `stage5/` — **now also carries the separate `fvvw/` subtree's paths**, including `fvvw/logs/` (additive; the original static-track paths are untouched). |
| `cmdlog.py` | `CommandLog` — per-track, append-only JSONL of every command either track executes plus its full result, written to `stage5/fvvw/logs/<gid>.<static\|dynamic>.jsonl`. `LoggingSessionExecutor` wraps the dynamic track's session executor BY COMPOSITION (never edits `SandboxExecutor`) so every `exec_in_session` call is captured centrally. `JsonlRecordingList` intercepts `agent.graph.build_verifier_graph`'s `cpg_build_holder`/`attempts` list parameters so the static track gets full logging with ZERO edits to `agent/graph.py`. `phase()`/`aphase()` (sync/async) tag records with the active node name via a `ContextVar`, isolated per `asyncio` task the same way `observability.context.trace_context` is. Always on by default (`Settings.stage5_command_log`) — unlike LangSmith spans, NOT gated by `langsmith_tracing`; the whole point is a diagnosable run with no `--trace`. |
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
| `tools/qemu_gdb_tool.py` | Owns every `qemu-*`/`gdb-multiarch` command: the full arch table (`QEMU_ARCH_TABLE` — arm/armeb/aarch64/mips/mipsel/mips64/mips64el/ppc/ppc64, user+system binaries, per-arch argument registers, CPU-probe env fixes), launch-command assembly, the GDB batch-recipe renderer, plus the 9-node rewrite's new builders: `build_qemu_strace_command` (Node 3's `-strace` discovery), memory-dump (`x/32xb` before/after) and crash-capture (`handle SIGSEGV/SIGABRT/SIGILL stop`, `info registers`, `bt`, `$pc`) recipe bodies, `render_direct_call_recipe_body` (the `direct_call` emulation-mode harness). |
| `fvvw/dynamic_track.py` | The dynamic track's reusable node bodies/helpers, now consumed by `fvvw/dynamic_graph.py` rather than called in a hand-written sequence: `plan_emulation` (Node 2, incl. `direct_call`), `bringup_stabilize`/`BringupContext`/`BringupExhausted`/`_launch_qemu_and_wait` (Node 3's deterministic underlayer), `health_gate`/`HealthGateFailure` (Node 4), `reach_target` (Node 5), `satisfy_guards`/`instrument_trigger` (Node 6's benign-marker path), `collect_observation`/`collect_signals` (Node 7), `match_oracle` (Node 8's deterministic first pass). `validate_benign_marker`/`BenignMarkerViolation` (the benign-only posture) and `validate_real_payload`/`PayloadContainmentViolation` (the default real-payload posture, deny-list-only) — both gated by `Settings.stage5_allow_real_payloads`. `validate_injected_recipe` — HITL-inject's own, unconditional GDB-escape-hatch gate. `direct_call_trigger` — the GDB `call` harness (spec's explicit last resort). The pre-rewrite `dynamic_evaluate()` rule engine is UNUSED by the graph (kept only for any code still calling it directly) — Node 8's verdict now comes from `dynamic_graph._build_track_result`. |
| `fvvw/dynamic_agents.py` | The three agentic tool-calling loops: `bringup_agent` (Node 3), `trigger_agent` (Node 6), `route_observation` (Node 8's LLM router, called only when the deterministic first pass doesn't settle a round). Each is a bounded JSON-action ReAct loop (`_parse_action` via the SAME `agent.cleaning.clean_json_payload` discipline) whose dispatcher `await`s `ctx.session_executor.exec_in_session` directly — the "QEMU/GDB session driven async by the agents that need it" requirement. Command composition still lives entirely in `tools/qemu_gdb_tool.py`; these loops only call into it and into `dynamic_track.py`'s node functions. |
| `fvvw/dynamic_prompts.py` | System prompts + the JSON action/observation contract for all four dynamic-track LLM roles (bring-up, trigger, router) — mirrors `fvvw/strategy.py`'s prompt+render shape. `render_bringup_brief`/`render_trigger_brief`/`render_router_brief`. |
| `fvvw/dynamic_graph.py` | `build_dynamic_graph()` — the compiled `StateGraph(FVVWState)` for Nodes 2-8 (see "The 9 nodes" above for the full mapping). `DynamicGraphDeps` (the three new LLMs + session executor, narrower than `fvvw.graph.FVVWDeps`). `route_after_bringup`/`_health_gate`/`_gdb_attach`/`_trigger`/`_evaluate` — the pure conditional-edge functions implementing the spec's §10 decision table. `_build_track_result`/`_TERMINAL_ROUTES` — the ONLY place a dynamic-track `TrackResult` is constructed. |
| `fvvw/joint.py` | `joint_evaluate()` — the only function reading both `TrackResult`s. `classify_agreement`/`classify_mechanism_confidence`/`classify_reachability_confidence`/`collect_residual_unknowns`. |
| `fvvw/graph.py` | `run_fvvw()` — the actual fork-join: `characterize → strategy → fork(static_track, static_crosscheck, run_dynamic_track_only running concurrently) → await both → joint_evaluate`. `resolve_checkpointer()`, `FVVWDeps`/`resolve_fvvw_deps()` (now resolves SEVEN LLM roles — the original four plus `bringup_llm`/`trigger_llm`/`dynamic_evaluator_llm`). `run_dynamic_track_only()` — compiles + `ainvoke`s `dynamic_graph.build_dynamic_graph()` under a `stage5_dynamic_wall_clock_seconds` timeout, unpacking the terminal `FVVWState` into the `(TrackResult, guard_logs, dynamic_reached_sink, gdb_transcript, dynamic_extras)` tuple every caller expects. |
| `fvvw/report.py` | `write_report()` — one LLM call composing the seven-layer disclosure document + reconciliation section, with every raw tool output (Joern attempts, GDB transcript) quoted verbatim. |
| `fvvw/driver.py` | `run_fvvw_queue()` — a SEPARATE worker-pool queue (not an extension of `driver.py`) persisting `FVVWReport` JSON + disclosure Markdown to `stage5/fvvw/reports/`. |
| `fvvw/debug.py` | `debug_strategy` (strategy only), `debug_dynamic` (dynamic track ONLY — the per-track debug path; `DebugDynamicResult` now also surfaces `arbitration_log`/`observation`/`iteration_history` for inspection, never persisted), `debug_fvvw` (full fork-join, dry run). |
| `tools/verification_sandbox.py` | `verification_executor()`/`verification_session_executor()` — resolve an `Executor`/session-capable `SandboxExecutor` pointed at `stage5_verification_image` (a SEPARATE image from Joern's). |
| `cmdlog.py` | `CommandLog` — per-track, append-only JSONL of every command either track executes plus its full result, written to `stage5/fvvw/logs/<gid>.<static\|dynamic>.jsonl`. `LoggingSessionExecutor` wraps the dynamic session executor by COMPOSITION; `JsonlRecordingList` intercepts the static track's `cpg_build_holder`/`attempts` lists with zero edits to `agent/graph.py`. Always on by default (`Settings.stage5_command_log`), unlike LangSmith — the point is a diagnosable run with no `--trace`. |
| `fvvw/hitl.py` | Human-in-the-loop: `HitlAction`/`HitlDecision`/`HitlRequest`, `Prompter` (an injectable callable — `terminal_prompter` for real use, a scripted fake in tests), `is_budget_exhausted()` (the trigger — reads the `evidence["budget_exhausted"]` fact tagged by the producing track), `force_verdict_result()`, `build_human_review_record()`. Hooked into `fvvw.graph.run_fvvw` AFTER the fork-join barrier, never inside a track. |

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

# Human-in-the-loop — pauses AFTER the barrier when a track exhausts its
# own budget without a decisive verdict; forces stage5_workers=1
fw-verify run --db-subfolder data/db/<stem> --hitl=prompt \
    --max-iterations 10 --dynamic-max-iterations 8 --no-command-log

# Dynamic-track containment/budget overrides
fw-verify run --db-subfolder data/db/<stem> --benign-only              # restore the v1 benign-marker-only invariant
fw-verify run --db-subfolder data/db/<stem> --dynamic-wall-clock 900   # override stage5_dynamic_wall_clock_seconds (min 60)

# --claims: verify Stage 3b's externally-sourced PDF report claims instead
# of Stage 3's own findings — reads stage3b/findings/ instead of
# stage3/findings/; every other flag composes with it normally.
fw-verify run --db-subfolder data/db/<stem> --claims
```

`--model` sets `FWA_STAGE5_VERIFIER_MODEL`, which every Stage 5 LLM role
falls back to unless its own `FWA_STAGE5_*_MODEL` (`GENERATOR`/`EVALUATOR`/
`STRATEGY`/`REPORT`) is set independently.

## Input

`stage3/findings/*.json` (Stage 3), or `stage3b/findings/*.json` (Stage 3b,
with `--claims` — see `fw-claims ingest`) + `stage2/stage2_summary.json`
(Stage 2 — resolves both the static track's `normalized/joern/whole.c` AND,
new for the dynamic track, the real ELF via `rootfs_dir`/`DecompiledBinary.
rootfs_path` plus `.elf`/`.functions`).

## Output — `data/db/<stem>/stage5/`

**Static track (`--joern-only`, unchanged):** `verifications/<gid>.json` →
`reports/<gid>.md` → `workspace/<gid>/` → `stage5_summary.json`.

**Fork-join (default), a SEPARATE subtree — never collides with the
above:** `fvvw/reports/<gid>.json` (`common.verification.FVVWReport`) →
`fvvw/reports/<gid>.md` (disclosure Markdown) →
`fvvw/dynamic_workspace/<gid>/` → `fvvw_summary.json`. Plus
`fvvw/logs/<gid>.static.jsonl` / `fvvw/logs/<gid>.dynamic.jsonl` — every
command either track ran and its full result (`cmdlog.CommandLog`); a
sibling of `dynamic_workspace/`, so it survives `--keep-workspace=False`'s
cleanup even though the workspace itself doesn't. `FVVWReport.
command_log_paths` points at both files directly. `FVVWReport.human_review`
(`common.verification.HumanReviewRecord`) is set only when `--hitl=prompt`
led to an operator intervention on this candidate — `None` for every
ordinary, unattended run.

## Debugging

- `--trace` traces every LLM call and every sandboxed tool call
  (`run_type="tool"` spans: `stage5.build_cpg`, `stage5.run_joern_script`,
  `stage5.characterize_target`, `stage5.static_crosscheck`,
  `stage5.bringup_stabilize`, `stage5.reach_target`, `stage5.satisfy_guards`,
  `stage5.instrument_trigger`, `stage5.collect_signals`, `stage5.health_gate`),
  plus `run_config()`-tagged LLM runs: `stage5.strategy_agent`,
  `stage5.generate_script`, `stage5.evaluate`, `stage5.fvvw.write_report`,
  and the 9-node rewrite's three new agentic roles —
  `stage5.bringup_agent` (Node 3), `stage5.trigger_agent` (Node 6),
  `stage5.dynamic_evaluate` (Node 8's LLM router, `route_observation` —
  note this run_name is SHARED with the pre-rewrite `dynamic_evaluate`
  rule engine's conceptual role, but is now the LLM call, not a
  deterministic function). `run_dynamic_track_only`'s own `ainvoke` is
  tagged `stage5.dynamic_track`; the dynamic graph's individual nodes are
  auto-traced by LangGraph's native instrumentation under it with no
  manual span needed (`bringup`/`health_gate`/`gdb_attach`/`trigger`/
  `evaluate_route`/`plan_emulation`/`plan_emulation_escalate` node names).
  `cmdlog`'s `aphase()` tags (same names as the graph nodes, plus
  `bringup_agent`/`trigger_agent` for the two agentic loops specifically)
  are a SEPARATE mechanism — the `node` field in `fvvw/logs/<gid>.
  dynamic.jsonl`, not a LangSmith span; both exist independently (see
  Command Log below). Root run: `stage5.fvvw.candidate` (fork-join) or
  `stage5.candidate` (`--joern-only`). See root `CLAUDE.md`'s Observability
  section.
- `docker build -f docker/Dockerfile.joern -t fw-audit-joern:latest .` —
  the static track's image, unchanged.
- `docker build -f docker/Dockerfile.verification -t
  fw-audit-verification-sandbox:latest .` — the dynamic track's (and
  `characterize_target`/`static_crosscheck`'s) SEPARATE image. Reuses
  `Dockerfile.joern`'s fetch stage; needs the same pre-fetched
  `docker/.joern-cli.zip`.
- `Stage5InputError` on `run`/`debug verify`/`debug fvvw` → `stage3/findings/`
  or `stage2/stage2_summary.json` missing; run `fw-analyze --queue` then
  `fw-analyze --analyze --chunks-file <stage3/chunk_index.json>` / `fw-extract`
  first (see `fw_audit/stage3_analysis/CLAUDE.md` — `--analyze` never chunks
  on its own). `debug_fvvw`/`run_fvvw` additionally raise this if a
  candidate's `source_path` never resolved (needed by the static track even
  in the fork-join).
- `characterize_target`'s "target mismatch" `Stage5InputError` → the
  finding's `evidence_span.function_id` doesn't resolve against the real
  binary's `DecompiledBinary.functions` table — the claim itself is wrong,
  not a tooling failure.
- `BenignMarkerViolation` (only reachable with `--benign-only`/
  `stage5_allow_real_payloads=False`) → the trigger agent/strategy plan
  produced a `payload_marker` that failed the benign-only check — a hard
  stop, never worked around by loosening the validator.
  `PayloadContainmentViolation` (the DEFAULT real-payload posture) → the
  Node 6 trigger agent proposed weaponized content (reverse shell,
  exfiltration, destructive host command) that matched `validate_real_
  payload`'s deny-list — the agent sees this as a rejection and gets a
  chance to propose a different payload within its own step budget; it is
  NOT necessarily a hard stop for the candidate the way `BenignMarkerViolation`
  is. `dynamic_track.validate_injected_recipe`'s GDB-escape-hatch check
  (HITL's "inject" action only) is a separate, ALWAYS-enforced gate — see
  the hard constraints section above.
- `SandboxUnavailableError` → Docker unreachable, or a candidate's `bin_id`
  never resolved a `normalized_joern_c` path.
- `VerifierModelUnavailableError` → no usable credential for one of the
  SEVEN Stage 5 roles now (`STAGE5_SCRIPT_GENERATOR`, `STAGE5_RESULT_EVALUATOR`,
  `STAGE5_STRATEGY_AGENT`, `STAGE5_REPORT_WRITER`, plus the dynamic
  track's `STAGE5_BRINGUP_AGENT`, `STAGE5_TRIGGER_AGENT`,
  `STAGE5_DYNAMIC_EVALUATOR`); set `ANTHROPIC_API_KEY` or
  `FWA_STAGE5_VERIFIER_MODEL=ollama:qwen3:32b` (the shared fallback covers
  all seven unless overridden individually via each role's own
  `FWA_STAGE5_BRINGUP_MODEL`/`FWA_STAGE5_TRIGGER_MODEL`/
  `FWA_STAGE5_DYNAMIC_EVALUATOR_MODEL`).
- `Status: no_targets` with 0 candidates → check each finding's `decision`
  field (`grep -o '"decision": *"[A-Z_]*"' stage3/findings/*.json`); only
  `ESCALATE` is verified by default — pass `--decisions` to widen it.
- `fw-verify debug build-cpg`/`debug script` bypass the LLM entirely for
  the Joern mechanics; `fw-verify debug dynamic` runs ONLY the QEMU+GDB
  track (needs the strategy agent for a `DynamicPlan`, but not the static
  track); `fw-verify debug strategy` emits just the `StrategyPlan`.
- **`fw-verify debug verify` is the pre-FVVW v1, Joern-only entry point** —
  it calls `agent.verifier.verify_candidate` directly and imports NOTHING
  from `fvvw/`. It constructs no `StrategyPlan`, `Hypotheses`, or
  `TrackResult` — there is no A/B machinery on this path at all, only the
  hypothesis-proof discipline built directly into `agent/graph.py`'s
  `final_status`/`evaluate_node` (see the hard-constraints section above).
  To exercise the strategy agent's hypothesis pair or the full fork-join,
  use `fw-verify debug strategy` or `fw-verify debug fvvw` instead.
- A REFUTED verdict on a finding whose `evidence_span` visibly shows the
  source reaching the sink through `sprintf`/`strcpy`/`memcpy`/similar →
  suspect a false refutation from the dataflow engine not modeling that
  call's argument -> output-buffer taint propagation, NOT a genuine
  absence. Check the attempt's `evaluator_reasoning`/`hypothesis_proved` —
  a legitimate REFUTED must cite a specific sanitizer/guard/constant or the
  CHECK-1/2/3 health-check corroboration; if it doesn't, that's a bug, not
  a correct verdict (see the regression tests guarding this:
  `tests/test_stage5_graph.py::test_pass_with_flow_not_found_and_hypothesis_none_retries_not_refutes`,
  `tests/test_fvvw_static_track.py::test_run_static_track_flow_not_found_without_positive_proof_is_not_refuted`).
- `UnknownHostException`/"Could not determine local host name" stack traces
  in Joern stdout/stderr are container-hostname log4j noise
  (`--network=none` containers have no DNS and no `/etc/hosts` entry for
  their own default hostname) — non-fatal, and both the evaluator prompt
  and `executors/docker_executor.py::_hostname_flags()` account for it
  (the latter forces a deterministic, locally-resolvable hostname at the
  `docker run`/`start()` call sites, so this should no longer appear in new
  runs at all). Never treat it as a script failure if it does.
- Unit: `pytest -m "not integration" tests/test_stage5_*.py
  tests/test_fvvw_*.py tests/test_sandbox_executor.py
  tests/test_sandbox_session_executor.py` — no Docker/LLM/QEMU/GDB required
  (`FakeExecutor` + duck-typed fake chat models + a fake session executor).
  `tests/test_fvvw_hitl.py` exercises all four HITL actions via a scripted
  `Prompter` (no real stdin); `test_fvvw_graph.py`'s `test_run_fvvw_hitl_*`
  tests exercise the full hook end-to-end (mode off, both tracks decisive,
  force_verdict, skip, and the `stage5_hitl_max_rounds` bound).
- A dynamic-track run stuck INCONCLUSIVE with no obvious cause → read
  `fvvw/logs/<gid>.dynamic.jsonl` (one JSON object per command: `node`,
  `kind`, `command`, `payload` for GDB recipe/Joern script text, full
  `stdout`/`stderr`, `notes`). `kind:"exec_in_session"` records cover
  every QEMU/GDB command including the ones the LangSmith span never
  captured (`pkill`, the backgrounded launch, the readiness probe).
  `jq 'select(.kind=="exec_in_session")' fvvw/logs/<gid>.dynamic.jsonl`
  is the fastest way to replay a run's exact GDB batches. Instead of (or
  before) re-running with more iterations, `--hitl=prompt` pauses exactly
  at this point and offers retry/override_plan/inject/force_verdict — the
  same JSONL is what the prompt itself shows as "recent commands".
- GDB recipes and the QEMU stdout/stderr log live under
  `tools.qemu_gdb_tool.CONTAINER_SCRATCH` (`/tmp/fvvw` inside the
  session container), never under `CONTAINER_WORKDIR` — that path is a
  bind mount of the extracted firmware rootfs itself, so writing recipes
  there would pollute the firmware being analyzed. Nothing needs to be
  copied out: the recipe text and full stdout/stderr are captured verbatim
  in the host-side JSONL instead.
- `BenignMarkerViolation` from HITL's "inject" action (a raw GDB recipe,
  not a bare marker) → the recipe matched `dynamic_track.
  validate_injected_recipe`'s deny-list — either one of `_DENY_PATTERNS`
  (the same list `validate_benign_marker` uses) or a GDB escape hatch
  (`shell`, `!`, `pipe`, `python`, `define`, `source`, `dump`, ...). Never
  worked around by loosening the validator; the operator's recipe should
  stick to `break`/`continue`/`printf`/`set $reg = ...`.
- **Fixed bugs worth knowing about if you're re-deriving from an older
  trace or report:** `collect_signals` used to read a file
  (`target_stdout.log`) nothing ever wrote — it now reads the QEMU log
  `_launch_qemu_and_wait` actually redirects to; the filesystem-artifact
  check used to probe only the pre-chroot marker path, which is
  unreachable from inside the chroot the emulated process actually runs
  under — it now probes both; a stale marker artifact from an earlier run
  is now removed (`cleanup_marker_artifact`) before each dynamic-track run
  starts, not left to produce a false `FOUND` forever; a `DynamicFault`
  raised by `bringup_stabilize` itself (not just by
  reach/guards/trigger) used to escape `run_dynamic_track_only` uncaught —
  it's now retried like every other dynamic-track fault. All four were
  plausible root causes of "always inconclusive" on real firmware.
- **9-node rewrite regression, same bug class as the one above:** when
  `dynamic_track.bringup_stabilize`/`_launch_qemu_and_wait`'s own bare
  `DynamicFault` (a staging failure, or its readiness-probe timeout) was
  first ported into `dynamic_graph._run_bringup`, it was left uncaught —
  the agentic `bringup_agent` call was wrapped in a `try/except
  DynamicFault`, but the SUBSEQUENT `bringup_stabilize` call underneath it
  was not, so the same fault class escaped the graph node entirely and
  crashed the whole `ainvoke`. Fixed the same way as the original bug: a
  bounded retry loop around `bringup_stabilize` inside `_run_bringup`,
  bounded by `bringup_stabilize`'s own `repair_count` check (raises
  `BringupExhausted`, which IS caught). Regression test:
  `tests/test_fvvw_graph.py::test_run_fvvw_recovers_from_dynamic_fault_raised_by_bringup_itself`
  (reused unchanged from the pre-rewrite suite — it caught this on the
  first run against the rewritten graph).
- **The new graph's terminal routes originally never constructed a
  `TrackResult` at all** — `RouteDecision` (Node 8's own output) carries
  only a routing instruction (`route`/`diagnosis`/`confidence`), never a
  verdict. `dynamic_graph._build_track_result`/`_TERMINAL_ROUTES` is what
  closes that gap, called from `_run_evaluate_route` whenever the decision
  is `confirmed`/`refuted`/`inconclusive`. Similarly, `bringup ->
  health_gate` was originally an UNCONDITIONAL edge — once bring-up
  exhausted its OWN repair budget (`_bringup_exhausted=True`, with a
  terminal `dynamic_result` already set), the graph still proceeded into
  `health_gate` anyway, which fails against a session that never started
  and loops back to `bringup`, repeatedly overwriting the already-terminal
  result rather than ending immediately — `route_after_bringup` makes this
  a conditional edge (`__end__` when exhausted) instead.

## Adding a feature here

- New STATIC-track tool behavior goes in `tools/`, never inline in
  `agent/graph.py` — and per the hard constraint above, don't touch
  `agent/graph.py`/`agent/prompts.py` for FVVW work at all.
- New DYNAMIC-track command composition goes in `tools/qemu_gdb_tool.py`,
  never inline in `fvvw/dynamic_track.py`'s node functions or
  `fvvw/dynamic_agents.py`'s tool dispatchers.
- New report fields go in `common/verification.py` (not `common/findings.py`
  or `common/taint.py`).
- A new repair case for `bringup_stabilize` goes in
  `fvvw/dynamic_track.py`'s `bringup_stabilize()`/`BringupContext` — write
  the fix to `ctx.applied_fixes` so a retry within the same run reuses it.
  A new AGENTIC bring-up tool (something the LLM can choose to do, not a
  fixed deterministic repair) goes in `fvvw/dynamic_agents.py`'s
  `_dispatch_bringup_tool` instead, plus a description of it in
  `fvvw/dynamic_prompts.py`'s `BRINGUP_AGENT_SYSTEM_PROMPT` so the LLM
  actually knows the tool exists.
- A new arch for the dynamic track is one `QEMU_ARCH_TABLE` entry in
  `tools/qemu_gdb_tool.py`, not a new `if`/`elif` branch anywhere.
- A new Node 8 route (beyond the spec's existing seven) needs: a new
  `Literal` value on `common.verification.RouteDecision.route`, a new
  entry in `dynamic_graph._TERMINAL_ROUTES` if it's a terminal
  disposition (with the `(VerificationVerdict, proved_hypothesis)` pair
  `_build_track_result` should stamp) or a new `_ROUTE_TO_NODE`/
  conditional-edge mapping if it's a repair route, and a description of
  when to choose it in `dynamic_prompts.py`'s `DYNAMIC_ROUTER_SYSTEM_PROMPT`.
  Never let a new route bypass the hard iteration-budget cutoff in
  `_run_evaluate_route` (checked BEFORE the LLM router is even called).
- A new agentic loop (a fourth `dynamic_agents.py`-shaped role, beyond
  bring-up/trigger/router) needs: an `AgentRole` in `config/llm_config.py`
  (`ROLE_TO_TIER` + `_ROLE_OVERRIDE_SETTINGS_FIELD`), a `Settings` model
  override field, resolution in `fvvw.graph.resolve_fvvw_deps` and a new
  field on `DynamicGraphDeps`, a system prompt in `dynamic_prompts.py`, and
  a bounded JSON-action loop in `dynamic_agents.py` following `bringup_
  agent`/`trigger_agent`'s exact shape (`_parse_action`, a step budget, a
  dispatcher that `await`s `ctx.session_executor.exec_in_session`, every
  `.ainvoke` call passing `config=run_config(run_name="stage5.<role>", ...)`).
  Document its new LangSmith span/spec-node mapping in "The 9 nodes" table
  above.
- A new dynamic-track command that should be logged needs no explicit
  `cmdlog` call at the site that issues it — `LoggingSessionExecutor`
  (wrapping `deps.dynamic_session_executor`) captures every
  `exec_in_session()` call automatically. Wrap the new code in
  `cmdlog.aphase("<node_name>")` (or `phase()` for a sync block) so the
  resulting records carry the right `node` tag.
- A new HITL action goes in `fvvw/hitl.py`'s `HitlAction` enum plus a new
  branch in `fvvw/graph.py`'s `_run_hitl_for_track` (fork-join path) and
  `driver.py`'s `_run_hitl_joern_only` (`--joern-only` path) — both read
  the SAME `HitlDecision`, so a new action needs a branch in both unless
  it's genuinely fork-join-only. Never let an action bypass
  `validate_benign_marker`/`validate_injected_recipe` for the dynamic
  track's own safety invariant.
- New recipe/scratch files the dynamic track writes go under
  `tools.qemu_gdb_tool.CONTAINER_SCRATCH`, never under `CONTAINER_WORKDIR`
  (the bind-mounted firmware rootfs) — see that constant's own docstring.
