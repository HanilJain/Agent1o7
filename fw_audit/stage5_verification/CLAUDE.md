# CLAUDE.md — Stage 5: Sandboxed Verification (Joern generate/evaluate pipeline, v1)

Read this file first for Stage 5 work. **v1 implements the Joern half
only** — a generator LLM writes a Joern/CPGQL script per round, a separate
evaluator LLM judges the output, and the loop retries on a broken script
until it settles or hits its iteration cap. Neither LLM does tool-calling or
structured-output — both are plain text in/text out, specifically so this
runs reliably on a local model (e.g. Ollama qwen3:32b) and not only Claude
via the Anthropic API (a paid `ANTHROPIC_API_KEY` — a Claude Code/claude.ai
login does not work here). QEMU+GDB dynamic verification, a real MCP
protocol server, and a persistent/session sandbox are **not implemented** —
see "Explicitly deferred" below. Root `CLAUDE.md` covers only cross-cutting
concerns (Executor abstraction, LLM routing, Settings).

## Hard constraints — never violate

- Never write into `stage2/`, `stage3/`, or `stage4/` — only into this
  stage's own `stage5/` directory.
- `candidate_index.discover_candidates()` reads **Stage 3 findings only**
  (`stage3/findings/*.json`) — never `stage4/taint/*.json`, even when
  present. A deliberate scope choice, not an oversight.
- **Never reintroduce `--param cpgPath=`.** The CPG is bound POSITIONALLY
  as `cpg` (`joern --script q.sc cpg.bin`) — `--param` only binds to a
  script-declared `@main def`, which a plain expression script doesn't
  have, and fails with an "unknown arguments" error. Verified against a
  real Joern 4.0.420 build; see `tools/joern_tool.py`'s module docstring
  for the full post-mortem, and `agent/prompts.py`'s
  `GENERATOR_SYSTEM_PROMPT` for how this is taught to the generator.
- The generator LLM never constructs the underlying `docker run`/
  `joern-parse`/`joern --script` command line — only the Scala/CPGQL script
  BODY. Command composition lives entirely in `tools/joern_tool.py`, called
  directly by `agent/graph.py`'s nodes.
- `debug.py`'s functions never write into `verifications/`/`reports/` —
  those are `driver.py`'s persisted, tracked output; every debug function
  is a dry run (same discipline as `stage4_rag.debug`).
- `SandboxExecutor` (`fw_audit/executors/sandbox_executor.py`) is one-shot
  by design in v1 — a fresh `docker run` per script execution, state
  carried via the host-mounted workspace directory, not a live container.
  Do not retrofit a persistent session onto it for Joern; that need
  (interactive QEMU+GDB) gets its own new capability later, not a patch to
  this one.

## Files

| File | Purpose |
|---|---|
| `layout.py` | Pure path algebra for `stage5/`. |
| `candidate_index.py` | Resolves `stage3/findings/*.json` (decision `ESCALATE` by default) into `VerificationCandidate`s, resolving each `bin_id`'s `normalized/joern/whole.c` via `stage2_summary.json`. |
| `errors.py` | `Stage5InputError`, `SandboxUnavailableError`, `VerifierModelUnavailableError`. |
| `tools/joern_tool.py` | `build_cpg_async`/`run_joern_script_async` + `joern_executor()` (image-override wrapper over `SandboxExecutor`, mirrors `ghidra_executor()`). Owns the exact Joern CLI command strings — called directly by `agent/graph.py`, not via LangChain tool-calling. |
| `agent/cleaning.py` | Strips `<think>` reasoning blocks and markdown fences from a local model's raw response before it's used as a script or parsed as evaluator JSON. |
| `agent/transcript.py` | Builds `TranscriptEntry` objects for each graph node — the CPG build, generated script (with a synthesized tool-call record), Joern output, evaluator verdict, and final conclusion. |
| `agent/prompts.py` | `GENERATOR_SYSTEM_PROMPT` + `EVALUATOR_SYSTEM_PROMPT`, `render_finding_brief()`, and the two message builders. The generator prompt is overridable via `--prompt-file`. |
| `agent/graph.py` | LangGraph `StateGraph`: `build_cpg` -> `generate_script` -> `run_script` -> `evaluate`, looping back to `generate_script` on `FAIL_RETRY` until `evaluate` returns `PASS`/`FAIL_STOP` or `stage5_max_agent_iterations` forces the downgrade, then `conclude` (no LLM call) derives the final `VerificationVerdict`. |
| `agent/verifier.py` | `verify_candidate()` — workspace setup, resolving both LLM roles, graph invocation, `VerificationReport` assembly. |
| `driver.py` | Bounded async worker pool over candidates (mirrors `stage4_rag.driver`), persists JSON + Markdown per candidate, writes `stage5_summary.json`. |
| `report_writer.py` | Renders one `VerificationReport` to human-readable Markdown, including an exact reproduction command. |
| `debug.py` | `debug_build_cpg`/`debug_run_script` (bypass the LLM entirely) / `debug_verify` (full pipeline, dry run) — all read/write-controllable independent of a real pipeline run. |
| `runner.py` | `fw-verify` CLI entry point. |

## Invoke

```bash
fw-verify run --db-subfolder data/db/<stem>
fw-verify run --db-subfolder data/db/<stem> --only "<chunk_id>::<finding_id>"
fw-verify run --db-subfolder data/db/<stem> --model ollama:qwen3:32b --keep-workspace
fw-verify run --db-subfolder data/db/<stem> --decisions CONTEXT_REQUIRED,ESCALATE

fw-verify debug build-cpg --db-subfolder data/db/<stem> --bin-id <bin_id>
fw-verify debug script --workspace data/db/<stem>/stage5/workspace/<gid> --script-file q.sc
fw-verify debug verify --db-subfolder data/db/<stem> --gid "<gid>" \
    --prompt-file my_prompt.txt --output report.json
```

`--model` sets `FWA_STAGE5_VERIFIER_MODEL`, which both the generator and
evaluator roles fall back to unless `FWA_STAGE5_GENERATOR_MODEL`/
`FWA_STAGE5_EVALUATOR_MODEL` is set independently.

## Input

`stage3/findings/*.json` (Stage 3) + `stage2/stage2_summary.json` (Stage 2,
to resolve each binary's `normalized/joern/whole.c`).

## Output — `data/db/<stem>/stage5/`

`verifications/<gid>.json` (`common.verification.VerificationReport`) →
`reports/<gid>.md` → `workspace/<gid>/` (kept only if
`FWA_STAGE5_KEEP_WORKSPACE=true` / `--keep-workspace`) →
`stage5_summary.json`.

## Debugging

- `--trace` (or `LANGSMITH_TRACING=true` + `LANGSMITH_API_KEY`) traces every
  `run`: one `stage5.candidate` root run per candidate, with the compiled
  graph's own generate/run/evaluate loop nested beneath it, plus
  `run_type="tool"` spans around `build_cpg_async`/`run_joern_script_async`
  (Joern's two `docker run` calls — otherwise untimed). A persisted
  `verifications/<gid>.json`'s `trace_url` field links back to the live
  trace when tracing was on; `agent/transcript.py`'s hand-rolled transcript
  remains the offline artifact of record either way. See root `CLAUDE.md`'s
  Observability section.
- `docker build -f docker/Dockerfile.joern -t fw-audit-joern:latest .` —
  the `JOERN_CLI_SHA256` build arg is already populated with a
  locally-verified hash; build context must be the repo root (the
  Dockerfile `COPY`s `docker/.joern-cli.zip`, fetched host-side first —
  see the Dockerfile's own header comment).
- `Stage5InputError` on `run`/`debug verify` → `stage3/findings/` or
  `stage2/stage2_summary.json` missing; run `fw-analyze --analyze` /
  `fw-extract` first.
- `SandboxUnavailableError` → Docker unreachable, or a candidate's
  `bin_id` never resolved a `normalized_joern_c` path (Stage 2 skipped it,
  or the binary was removed since).
- `VerifierModelUnavailableError` → no usable credential for either
  `AgentRole.STAGE5_SCRIPT_GENERATOR` or `AgentRole.STAGE5_RESULT_EVALUATOR`;
  set `ANTHROPIC_API_KEY` (paid API key — a Claude Code/claude.ai login does
  not work here) or `FWA_STAGE5_VERIFIER_MODEL=ollama:qwen3:32b`.
- `Status: no_targets` with 0 candidates, even though `stage3/findings/*.json`
  clearly has content → check each finding's `decision` field
  (`grep -o '"decision": *"[A-Z_]*"' stage3/findings/*.json`). Only
  `ESCALATE` is verified by default; `CONTEXT_REQUIRED`/`MERGE`/`DISCARD`
  findings are silently excluded — pass `--decisions CONTEXT_REQUIRED` (or
  a comma-separated list) to force them through. `--only` alone does NOT
  bypass this filter — it only narrows the set `--decisions` already
  selected.
- `fw-verify debug build-cpg` / `debug script` bypass the LLM entirely —
  use these first to confirm the Joern image/tool mechanics work, and to
  validate the `println("RESULT: ...")` contract with a hand-written
  script, before trusting the generator.
- Unit: `pytest -m "not integration" tests/test_stage5_*.py
  tests/test_sandbox_executor.py` — no Docker/LLM required (FakeExecutor +
  a duck-typed fake chat model).

## Adding a feature here

New tool behavior goes in `tools/`, never inline in `agent/graph.py`. New
report fields go in `common/verification.py` (not `common/findings.py` or
`common/taint.py`). The QEMU+GDB tool, when it lands, gets its own
`tools/qemu_gdb_tool.py` and reuses `agent/graph.py`'s shape rather than a
parallel graph — see this package's `README.md` for what that needs from
`SandboxExecutor` first (a real session API, not the current one-shot
`run()`).
