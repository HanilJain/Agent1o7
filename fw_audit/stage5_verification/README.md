# Stage 5 — Sandboxed Verification (Joern generate/evaluate pipeline, v1)

Proves or disproves one Stage 3 finding by actually building a Code
Property Graph (CPG) for its binary and running Joern/CPGQL queries against
it — the first stage in this pipeline that executes anything, rather than
reasoning over static text alone.

**v1 scope: the Joern tool only.** Two independently-configurable LLM
roles — a **generator** that writes a Joern/CPGQL script per round, and an
**evaluator** that judges that round's output — iterate: build the CPG,
generate a query, run it, evaluate the result, and if the script itself was
broken (not just "the finding wasn't confirmed"), regenerate with feedback,
up to a bounded number of rounds. Neither role does tool-calling or
structured-output — both are plain text in/text out, specifically so this
runs reliably on a local model (e.g. Ollama qwen3:32b), not just Claude via
the Anthropic API (which requires a paid `ANTHROPIC_API_KEY` — a Claude
Code/claude.ai login does not work here). QEMU+GDB dynamic verification is a
planned second tool, not built yet.

## What it does

- **`candidate_index.py`**: reads `stage3/findings/*.json` (ESCALATE
  findings by default) and resolves each one's binary to Stage 2's
  `normalized/joern/whole.c` via `stage2_summary.json`.
- **`tools/joern_tool.py`**: the Joern invocation primitives `agent/graph.py`
  calls directly, backed by `SandboxExecutor` (Docker, `--network=none`,
  resource-limited). `build_cpg_async` parses the binary's source into a CPG
  once, persisted to a per-candidate workspace directory on the host; every
  `run_joern_script_async` call is its own fresh one-shot container loading
  that CPG back from disk.
- **`agent/cleaning.py`**: strips `<think>` reasoning blocks and markdown
  fences from a local model's raw response before it's treated as a script
  or parsed as evaluator JSON.
- **`agent/graph.py`**: a LangGraph loop — `build_cpg` -> `generate_script` ->
  `run_script` -> `evaluate`, looping back to `generate_script` on a
  `FAIL_RETRY` verdict, until the evaluator settles the question or the
  iteration cap forces a `FAIL_STOP`. `conclude` mechanically derives the
  final `VerificationVerdict` (CONFIRMED / REFUTED / INCONCLUSIVE / ERROR)
  from the evaluator's verdict plus the script's `RESULT:` marker — no LLM
  call at that step.
- **`driver.py`**: runs this for every candidate through a bounded worker
  pool, persisting a JSON report and a human-readable Markdown explanation
  for each.

## Files

See [CLAUDE.md](CLAUDE.md) for the full file-by-file table.

## How to run

```bash
fw-verify run --db-subfolder data/db/<stem>
fw-verify run --db-subfolder data/db/<stem> --model ollama:qwen3:32b
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
verify --prompt-file ... --output ...` runs the full generate/run/evaluate
loop for one finding with the generator system prompt, model, and output
location all overridable, without touching `stage5/verifications/`. See
[CLAUDE.md](CLAUDE.md)'s Debugging section for the full command reference
and common errors.

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
