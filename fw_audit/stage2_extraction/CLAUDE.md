# CLAUDE.md — Stage 2: Feature Extraction

Read this file first for Stage 2 work. Fully deterministic — **no LLM
anywhere in this package** — so it's a plain async pipeline
(`extract.py::run_extraction()`), not a LangGraph like every other stage.
Root `CLAUDE.md` covers only cross-cutting concerns (Executor, Settings).

## Hard constraints — never violate

- Never import an LLM here. If a task needs one, it belongs in Stage 3+.
- `resolve.py` never calls `Path.resolve()` on a symlink — always re-root it
  manually inside the firmware's rootfs, or a malicious absolute symlink
  escapes onto the host.
- `normalize(normalize(x)) == normalize(x)` is a hard invariant (tested
  directly) — any new pass must preserve idempotency.
- Must invoke Ghidra via `pyghidraRun -H`, never bare `analyzeHeadless` — the
  latter fails `.py` `-postScript`s outright (PyGhidra needs the JVM
  started *by* Python).

## Files

| File | Purpose |
|---|---|
| `stage1_io.py` | Loads `stage1_summary.json`, resolves `rootfs_dir`. |
| `resolve.py` | Untrusted `IdentifiedBinary.path` → verified host bytes: normalize, symlink-walk (re-rooted), basename rescan, ELF check, hash dedupe. **Never raises** — bad paths become `unresolved`. |
| `layout.py` | Path algebra for `stage2/`'s output tree. |
| `ghidra/command.py` | Pure `pyghidraRun -H` command-string composition. |
| `ghidra/client.py` | Runs it via `Executor`, parses `metadata.json` → `DecompiledBinary`. |
| `normalize/prelude.py` | Generates `ghidra_types.h` (types → `typedef`, intrinsics → `#define`) — Joern target only. |
| `normalize/spans.py` | CODE\|STRING\|CHAR\|COMMENT tokenizer — every pass runs through this. |
| `normalize/passes.py` | Pure `(str) -> str` passes (illegal `::` labels, undeclared register vars, dup defs). |
| `normalize/pipeline.py` | `JOERN_PIPELINE`/`build_joern_pipeline`, `CLEAN_PIPELINE`/`build_clean_pipeline`, `normalize()`. |
| `normalize/report.py` | `PassStat` / `NormalizationResult`. |
| `clean/parser.py`, `clean/extract.py` | tree-sitter function-only extraction (needs the `stage2` extra, pinned `tree-sitter==0.23.2`/`tree-sitter-c==0.23.2`) — the LLM-target output. |
| `clean/index.py` | JSON (de)serialization of `cleaned/functions.json`. |
| `extract.py` | `run_extraction()`: load → resolve → decompile → normalize (Joern + clean) → summarize. |
| `runner.py` | `fw-extract` CLI entry point. |

## Invoke

```bash
fw-extract data/db/<firmware-stem>/stage1_summary.json
fw-extract data/db/<firmware-stem>/stage1_summary.json --dry-run
fw-extract data/db/<firmware-stem>/stage1_summary.json --only bin/httpd   # repeatable
fw-extract data/db/<firmware-stem>/stage1_summary.json --run-id ID
```

## Input

`stage1_summary.json` (from `fw-ingest`).

## Output

- `data/db/<stem>/stage2/resolution_report.json`
- `binaries/<bin_id>/raw/` — Ghidra's untouched output.
- `binaries/<bin_id>/normalized/joern/whole.c` — sanitized Joern-target C.
- `binaries/<bin_id>/cleaned/{whole.c,functions.json}` — LLM-target,
  function-only extraction (`whole.c` = kept functions concatenated in
  source order; `functions.json` = per-function `{name, start_line,
  end_line}` index, spans relative to `whole.c` itself). Absent for a
  binary if the `stage2` extra wasn't installed when Stage 2 ran — see
  `DecompiledBinary.warnings`. **This is what Stage 3's chunking reads
  directly** — Stage 3 no longer runs tree-sitter itself.
- `stage2_summary.json` — hand-off to Stage 3, every path relative to
  `db_subfolder` **except** `decompiled_tree_dir` (relative to its parent —
  see that field's docstring).
- Sibling mirror tree `data/db/<stem>_decompiled/` — flat rootfs-mirroring
  `.c` copies of the JOERN output only, human-browsing view.

## Debugging

- Requires `docker build -f docker/Dockerfile.ghidra -t fw-audit-ghidra:latest .`
  (base image `eclipse-temurin:21-jdk-jammy` — OpenJDK 21 isn't
  apt-installable on Debian bookworm).
- "Ghidra was not started with PyGhidra" → bare `analyzeHeadless` was used
  instead of `pyghidraRun -H`.
- Only the load phase raises (`Stage2InputError`); a per-binary
  decompile/normalize failure becomes `DecompiledBinary(status=FAILED)`.
- `FWA_STAGE2_CONCURRENCY` (default 1) — raise cautiously: each JVM reserves
  `FWA_GHIDRA_MAX_MEM` (default `4g`).
- Unit: `pytest -m "not integration" tests/test_stage2_extract.py tests/test_stage2_resolve.py tests/test_ghidra_client.py tests/test_ghidra_command.py tests/test_normalizer*.py tests/test_stage2_clean_extract.py`
- Integration: `test_decompiles_a_real_elf` needs only the Ghidra image;
  `test_stage2_on_real_firmware` also needs a prior `fw-ingest` run;
  `test_clean_pipeline_against_real_committed_wpasupp` (in
  `test_stage2_clean_extract.py`) needs only the committed real data.
- Missing `tree-sitter`/`tree-sitter-c` (the `stage2` extra): cleaning is
  skipped per-binary with a warning in `Stage2Summary.warnings` — the Joern
  artifact and the rest of the run are unaffected.

## Adding a feature here

New normalization passes go in `normalize/passes.py`, run through
`spans.py`'s tokenizer, added to whichever pipeline(s) they apply to
(`JOERN_PIPELINE`/`build_joern_pipeline`, `CLEAN_PIPELINE`/
`build_clean_pipeline`, or both), re-verified for idempotency. Both
pipelines share `_head_passes`/`_body_passes`/`_tail_passes` — see
`pipeline.py`'s module docstring for how they diverge (three
target-specific passes each). Downstream consumption of the cleaned
artifact (chunking, LLM analysis) belongs in Stage 3 — see
`stage3_analysis/CLAUDE.md`.
