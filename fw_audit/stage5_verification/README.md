# Stage 5 — Sandboxed Verification (placeholder, not implemented)

`fw_audit/stage5_verification/` is an empty scaffolded package —
`__init__.py` only, no logic, no CLI, no tests yet.

## Intended scope

Per the root [README.md](../../README.md)'s six-stage pipeline, this stage
sandboxes and verifies the vulnerability findings Stage 3's agent (or a
future Stage 4) produces — proving/disproving a candidate finding by
actually exercising it, rather than trusting the LLM's static read.

It's expected to be the first real consumer of
`fw_audit/executors/sandbox_executor.py` (`SandboxExecutor`) — currently a
reserved stub for *LLM-controlled* execution, distinct from
`DockerExecutor`'s fixed deterministic command sequences used by Stage 1.
See the [project CLAUDE.md](../../CLAUDE.md)'s "Executor abstraction"
section.

## When work starts here

Implement `SandboxExecutor` for real before building verification logic on
top of it — don't build against the stub. Then rewrite this file and its
sibling `CLAUDE.md` to follow `stage3_analysis/README.md`'s structure: a
file table, CLI invocation, input (Stage 3's `stage3/findings/*.json`),
expected output, and debugging commands.

See the [project CLAUDE.md](../../CLAUDE.md) and
[project README.md](../../README.md) for the overall pipeline and links to
every implemented stage's docs.
