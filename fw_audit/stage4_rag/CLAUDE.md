# CLAUDE.md — Stage 4: (placeholder)

**Not implemented.** `fw_audit/stage4_analysis/` is an empty scaffolded
package (`__init__.py` only) — no files, no logic, no tests. Do not assume
any behavior here exists.

## Current status

Reserved slot in the six-stage pipeline named in the root
[CLAUDE.md](../../CLAUDE.md). Note the pipeline's "agentic analysis" step
was actually built as **Component 2 inside Stage 3**
(`fw_audit/stage3_analysis/agent/` — see
[stage3_analysis/CLAUDE.md](../stage3_analysis/CLAUDE.md)), not here. Before
building anything in this package, confirm with the user/plan whether this
slot is still needed or has been superseded, to avoid duplicating Stage 3's
`agent/` worker pool.

## Before implementing

1. Follow this project's `stage1_ingestion`/`stage2_extraction`/
   `stage3_analysis` conventions: a `runner.py` CLI entry point registered
   in `pyproject.toml`, `Settings`-driven config (no bare `os.environ`),
   Pydantic schemas in `common/schemas.py` or `common/findings.py`.
2. Write this stage's own `CLAUDE.md`/`README.md` (this file + its sibling)
   with real file tables, invocation, input/output, and debugging sections
   — following the template the other three stages already use.
3. Update the root `CLAUDE.md`/`README.md` status line once real work
   lands here.

See the [project CLAUDE.md](../../CLAUDE.md) for the overall architecture
and the router table linking every stage's docs.
