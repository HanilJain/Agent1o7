# Stage 6 — Reporting (placeholder, not implemented)

`fw_audit/stage6_reporting/` is an empty scaffolded package —
`__init__.py` only, no logic, no CLI, no tests yet.

## Intended scope

The final step of the pipeline described in the root
[README.md](../../README.md): turns Stage 3's per-chunk vulnerability
findings (`stage3/findings/<chunk_id>.json`,
`stage3/analysis_summary.json` — see
[stage3_analysis/README.md](../stage3_analysis/README.md)) — and, once
built, Stage 5's sandboxed-verification verdicts — into a consolidated,
human-readable audit report per firmware image.

## When work starts here

Consume `common/findings.py`'s `AnalysisReport`/`Finding`/
`AnalysisRunSummary` schemas directly rather than re-deriving an ad-hoc
shape. Write output under `<db_subfolder>/stage6/`, never into an earlier
stage's directory. Then rewrite this file and its sibling `CLAUDE.md` to
follow `stage3_analysis/README.md`'s structure: a file table, CLI
invocation, input/output, and debugging commands.

See the [project CLAUDE.md](../../CLAUDE.md) and
[project README.md](../../README.md) for the overall pipeline and links to
every implemented stage's docs.
