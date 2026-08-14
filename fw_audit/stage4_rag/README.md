# Stage 4 — (placeholder, not implemented)

`fw_audit/stage4_analysis/` is an empty scaffolded package — `__init__.py`
only, no logic, no CLI, no tests yet.

## Status

This is a reserved slot in the project's six-stage pipeline (see the root
[README.md](../../README.md)). The pipeline's "agentic analysis" step was
actually implemented as **Component 2 inside Stage 3**
(`fw_audit/stage3_analysis/agent/` — see
[stage3_analysis/README.md](../stage3_analysis/README.md)), so check there
first before assuming this package still has unbuilt scope of its own.

## When work starts here

This file and its sibling `CLAUDE.md` should be rewritten to follow the
same structure as `stage1_ingestion/`, `stage2_extraction/`, and
`stage3_analysis/`: a file-by-file table, `fw-<verb>` CLI invocation,
expected input/output, and debugging commands. Until then, treat any
reference to "Stage 4" elsewhere in the docs as aspirational, not current
behavior.

See the [project CLAUDE.md](../../CLAUDE.md) and
[project README.md](../../README.md) for the overall pipeline and links to
every implemented stage's docs.
