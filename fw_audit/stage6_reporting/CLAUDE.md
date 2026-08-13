# CLAUDE.md — Stage 6: Reporting (placeholder)

**Not implemented.** `fw_audit/stage6_reporting/` is an empty scaffolded
package (`__init__.py` only) — no files, no logic, no tests. Do not assume
any behavior here exists.

## Intended scope (per the pipeline named in root CLAUDE.md)

Consumes Stage 3's `stage3/analysis_summary.json` +
`stage3/findings/<chunk_id>.json` (and, once built, Stage 5's verification
verdicts) and renders a final human-readable audit report per firmware.

## Before implementing

1. Read Stage 3's finding schema first —
   `common/findings.py::AnalysisReport`/`Finding`/`AnalysisRunSummary` — this
   stage should consume that contract directly, not re-derive an ad-hoc
   shape.
2. Follow this project's conventions: `runner.py` CLI entry point in
   `pyproject.toml`, `Settings`-driven config (no bare `os.environ`), output
   written under `<db_subfolder>/stage6/` (never into an earlier stage's
   directory — the same discipline `stage3_analysis` follows toward
   `stage2/`).
3. Write this stage's own `CLAUDE.md`/`README.md` (this file + its sibling)
   with a real file table, invocation, input/output, and debugging
   sections, following `stage3_analysis/CLAUDE.md`'s template.
4. Update the root `CLAUDE.md`/`README.md` status line once real work
   lands here.

See the [project CLAUDE.md](../../CLAUDE.md) for the overall architecture
and the router table linking every stage's docs.
