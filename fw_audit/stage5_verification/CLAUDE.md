# CLAUDE.md — Stage 5: Sandboxed Verification (placeholder)

**Not implemented.** `fw_audit/stage5_verification/` is an empty scaffolded
package (`__init__.py` only) — no files, no logic, no tests. Do not assume
any behavior here exists.

## Intended scope (per the pipeline named in root CLAUDE.md)

Sandboxed verification of Stage 3/4's findings — expected to be the first
consumer of `fw_audit/executors/sandbox_executor.py`
(`SandboxExecutor`), currently a **reserved, unimplemented** stub for
*LLM-controlled* execution (an agent writing/running its own
verification code), unlike `DockerExecutor`'s fixed deterministic commands.
See `fw_audit/executors/base.py` for the `Executor` interface every backend
implements.

## Before implementing

1. `SandboxExecutor` needs a real implementation first — do not build
   verification logic against a stub. Confirm scope/isolation requirements
   (never give it the Identifier Agent's zero-execution-rights posture —
   this stage's whole point is controlled code execution).
2. Follow this project's conventions: `runner.py` CLI entry point in
   `pyproject.toml`, `Settings`-driven config, Pydantic schemas in
   `common/`, findings consumed from Stage 3's
   `stage3/findings/<chunk_id>.json` (`common.findings.AnalysisReport`).
3. Write this stage's own `CLAUDE.md`/`README.md` (this file + its sibling)
   with a real file table, invocation, input/output, and debugging
   sections, following `stage3_analysis/CLAUDE.md`'s template.
4. Update the root `CLAUDE.md`/`README.md` status line once real work
   lands here.

See the [project CLAUDE.md](../../CLAUDE.md) for the overall architecture,
the Executor abstraction, and the router table linking every stage's docs.
