# CLAUDE.md — Stage 5: Sandboxed Verification (Joern agent, v1)

Read this file first for Stage 5 work. **v1 implements the Joern half
only** — an agent (Claude Sonnet or a local Ollama model) with real tool
access (`build_cpg`, `run_joern_script`) verifies one Stage 3 finding at a
time by building a CPG and running Joern/CPGQL queries against it. QEMU+GDB
dynamic verification, a real MCP protocol server, and a persistent/session
sandbox are **not implemented** — see "Explicitly deferred" below. Root
`CLAUDE.md` covers only cross-cutting concerns (Executor abstraction, LLM
routing, Settings).

## Hard constraints — never violate

- Never write into `stage2/`, `stage3/`, or `stage4/` — only into this
  stage's own `stage5/` directory.
- `candidate_index.discover_candidates()` reads **Stage 3 findings only**
  (`stage3/findings/*.json`) — never `stage4/taint/*.json`, even when
  present. A deliberate scope choice, not an oversight.
- The LLM never constructs the underlying `docker run`/`joern-parse`/
  `joern --script` command line — only WHEN to call a tool and, for
  `run_joern_script`, the Scala/CPGQL script BODY. Command composition
  lives entirely in `tools/joern_tool.py`.
- `debug.py`'s functions never write into `verifications/`/`reports/` —
  those are `driver.py`'s persisted, tracked output; every debug function
  is a dry run (same discipline as `stage4_rag.debug`).
- `SandboxExecutor` (`fw_audit/executors/sandbox_executor.py`) is one-shot
  by design in v1 — a fresh `docker run` per tool call, state carried via
  the host-mounted workspace directory, not a live container. Do not
  retrofit a persistent session onto it for Joern; that need (interactive
  QEMU+GDB) gets its own new capability later, not a patch to this one.

## Files

| File | Purpose |
|---|---|
| `layout.py` | Pure path algebra for `stage5/`. |
| `candidate_index.py` | Resolves `stage3/findings/*.json` (decision `ESCALATE` by default) into `VerificationCandidate`s, resolving each `bin_id`'s `normalized/joern/whole.c` via `stage2_summary.json`. |
| `errors.py` | `Stage5InputError`, `SandboxUnavailableError`, `VerifierModelUnavailableError`. |
| `tools/joern_tool.py` | `build_cpg`/`run_joern_script` `@tool` functions + `joern_executor()` (image-override wrapper over `SandboxExecutor`, mirrors `ghidra_executor()`). Owns the exact Joern CLI command strings. |
| `agent/prompts.py` | `SYSTEM_PROMPT` (verification brief) + `build_messages()`. Overridable via `--prompt-file`. |
| `agent/graph.py` | LangGraph `StateGraph`: agent (bound to the two tools) ⇄ tools, force-routing to a `finalize` node (structured `VerifierVerdict` output, bounded schema-repair retry) once `stage5_max_agent_iterations` is hit. The repo's first genuine multi-turn tool-calling loop. |
| `agent/verifier.py` | `verify_candidate()` — workspace setup, LLM resolution, graph invocation, `VerificationReport` assembly. |
| `driver.py` | Bounded async worker pool over candidates (mirrors `stage4_rag.driver`), persists JSON + Markdown per candidate, writes `stage5_summary.json`. |
| `report_writer.py` | Renders one `VerificationReport` to human-readable Markdown, including an exact reproduction command. |
| `debug.py` | `debug_build_cpg`/`debug_run_script` (bypass the LLM entirely) / `debug_verify` (full agent loop, dry run) — all read/write-controllable independent of a real pipeline run. |
| `runner.py` | `fw-verify` CLI entry point. |

## Invoke

```bash
fw-verify run --db-subfolder data/db/<stem>
fw-verify run --db-subfolder data/db/<stem> --only "<chunk_id>::<finding_id>"
fw-verify run --db-subfolder data/db/<stem> --model ollama:qwen3:8b --keep-workspace

fw-verify debug build-cpg --db-subfolder data/db/<stem> --bin-id <bin_id>
fw-verify debug script --workspace data/db/<stem>/stage5/workspace/<gid> --script-file q.sc
fw-verify debug verify --db-subfolder data/db/<stem> --gid "<gid>" \
    --prompt-file my_prompt.txt --output report.json
```

## Input

`stage3/findings/*.json` (Stage 3) + `stage2/stage2_summary.json` (Stage 2,
to resolve each binary's `normalized/joern/whole.c`).

## Output — `data/db/<stem>/stage5/`

`verifications/<gid>.json` (`common.verification.VerificationReport`) →
`reports/<gid>.md` → `workspace/<gid>/` (kept only if
`FWA_STAGE5_KEEP_WORKSPACE=true` / `--keep-workspace`) →
`stage5_summary.json`.

## Debugging

- `docker build -f docker/Dockerfile.joern -t fw-audit-joern:latest .` —
  the `JOERN_SHA256` build arg must be filled in with a locally-verified
  hash before this builds (see the Dockerfile's own TODO comment) — same
  discipline as `Dockerfile.ghidra`'s `GHIDRA_SHA256`.
- `Stage5InputError` on `run`/`debug verify` → `stage3/findings/` or
  `stage2/stage2_summary.json` missing; run `fw-analyze --analyze` /
  `fw-extract` first.
- `SandboxUnavailableError` → Docker unreachable, or a candidate's
  `bin_id` never resolved a `normalized_joern_c` path (Stage 2 skipped it,
  or the binary was removed since).
- `VerifierModelUnavailableError` → no usable `AgentRole.STAGE5_VERIFIER`
  credential; set `ANTHROPIC_API_KEY` or `FWA_STAGE5_VERIFIER_MODEL`.
- `fw-verify debug build-cpg` / `debug script` bypass the LLM entirely —
  use these first to confirm the Joern image/tool mechanics work before
  trusting the agent loop.
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
