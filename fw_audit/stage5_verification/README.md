# Stage 5 — Sandboxed Verification (Joern agent, v1)

Proves or disproves one Stage 3 finding by actually building a Code
Property Graph (CPG) for its binary and running Joern/CPGQL queries against
it — the first stage in this pipeline that executes anything, rather than
reasoning over static text alone.

**v1 scope: the Joern tool only.** An agent (Claude Sonnet by default, or a
local Ollama model such as qwen3) has real tool access — `build_cpg` and
`run_joern_script`, bound via LangGraph — and iterates: build the CPG, write
a query, read the result, and if it errored or didn't settle the question,
write another query, up to a bounded number of attempts. QEMU+GDB dynamic
verification is a planned second tool, not built yet.

## What it does

- **`candidate_index.py`**: reads `stage3/findings/*.json` (ESCALATE
  findings by default) and resolves each one's binary to Stage 2's
  `normalized/joern/whole.c` via `stage2_summary.json`.
- **`tools/joern_tool.py`**: the two tools the agent calls, backed by
  `SandboxExecutor` (Docker, `--network=none`, resource-limited). `build_cpg`
  parses the binary's source into a CPG once, persisted to a per-candidate
  workspace directory on the host; every `run_joern_script` call is its own
  fresh one-shot container loading that CPG back from disk.
- **`agent/graph.py`**: a LangGraph loop — agent decides to call a tool or
  stop, tools execute, loop, until the agent stops or a bounded iteration
  cap is hit, then a final structured-output call produces a `VerifierVerdict`
  (CONFIRMED / REFUTED / INCONCLUSIVE / ERROR) with cited evidence.
- **`driver.py`**: runs this for every candidate through a bounded worker
  pool, persisting a JSON report and a human-readable Markdown explanation
  for each.

## Files

See [CLAUDE.md](CLAUDE.md) for the full file-by-file table.

## How to run

```bash
fw-verify run --db-subfolder data/db/<stem>
fw-verify run --db-subfolder data/db/<stem> --model ollama:qwen3:8b
fw-verify debug build-cpg --db-subfolder data/db/<stem> --bin-id <bin_id>
fw-verify debug verify --db-subfolder data/db/<stem> --gid "<gid>" --output report.json
```

## Input

`stage3/findings/*.json` (Stage 3) + `stage2/stage2_summary.json` (Stage 2).

## Output

`data/db/<stem>/stage5/`: `verifications/<gid>.json` (the standard JSON
report — `common.verification.VerificationReport`), `reports/<gid>.md`
(human-readable, includes an exact reproduction command), and
`stage5_summary.json` (run-level bookkeeping). Never writes into an earlier
stage's tree.

## Debugging

Every control point you'd want while iterating on this is exposed
independently: `fw-verify debug build-cpg` and `debug script` bypass the
LLM entirely (test the Joern tool mechanics on their own); `fw-verify debug
verify --prompt-file ... --output ...` runs the full agent loop for one
finding with the system prompt, model, and output location all overridable,
without touching `stage5/verifications/`. See [CLAUDE.md](CLAUDE.md)'s
Debugging section for the full command reference and common errors.

## Explicitly deferred (not designed away)

- QEMU+GDB dynamic verification — a second tool module reusing
  `agent/graph.py`'s shape.
- A real MCP server exposing these tools over JSON-RPC, if cross-client
  interop is ever wanted.
- A persistent/session-based `SandboxExecutor` capability — needed once an
  interactive debugging session (not a one-shot command) is required.

See the [project CLAUDE.md](../../CLAUDE.md) and
[project README.md](../../README.md) for the overall pipeline, the
Executor abstraction, and LLM provider setup.
