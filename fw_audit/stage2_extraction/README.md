# Stage 2 — Feature Extraction

Turns Stage 1's shortlist into decompiled, normalized C artifacts via Ghidra
Headless. Fully deterministic — no LLM anywhere — so it runs as a plain
async pipeline (`extract.py`), not a LangGraph like the other stages.

## What it does

```
load stage1_summary.json + resolve rootfs
  -> resolve each IdentifiedBinary.path to verified bytes (never raises;
     unresolvable paths are recorded, not fatal)
  -> decompile each resolved binary with Ghidra Headless
     (bounded concurrency; one binary's failure never sinks the run)
  -> normalize the decompiled C for Joern (whole-program, CPG-compilable)
  -> validate the normalized Joern output (validate/ — a hard gate so a
     broken whole.c never silently reaches joern-parse; see below)
  -> clean the decompiled C for LLM consumption (function-only extraction,
     persisted to cleaned/ — Stage 3's chunking reads this directly)
  -> write stage2_summary.json
```

**Path resolution:** `IdentifiedBinary.path` is untrusted LLM output — may
carry a leading `/`, be hallucinated, contain `..`, or point at a
busybox-style symlink. `resolve.py` normalizes it, walks symlinks
*re-rooted inside the rootfs* (never resolved onto the host), falls back to
a basename rescan, and dedupes by content hash.

**C normalization:** Ghidra's decompiled C isn't valid, portable C
(non-standard types, `CONCATxy`/`SUBxy` intrinsics, illegal `::` switch
labels, undeclared register vars, illegal-character symbol names, value-only
enumerators, `void`-typed functions used as values, calls before their own
definition, phantom-type intrinsic macros). `normalize/` fixes this with a
generated prelude header (types → `typedef`, intrinsics → `#define`) plus
small span-aware text passes for what a declaration can't express. Stage 2
delivers TWO normalization targets from the same raw C: `normalize/joern/`
(CPG-compilable, prelude inlined) and `cleaned/` (LLM-facing, function-only
— every top-level declaration/prelude/thunk-wall stripped, keeping only
real function bodies; see `clean/`'s module docstring for the real-data
finding that motivated it).

**Validation gate (`validate/`):** a pure Python, dependency-free structural
check runs immediately after every Joern-target `whole.c` is written —
no bash, no Docker, no external tool required for the check logic itself.
Catches every defect class that would break `joern-parse` or silently
corrupt the CPG: an unbalanced quote desyncing the STRING/CHAR tokenizer
(`span_sync` — the root-cause check), illegal characters in a Ghidra
symbol name, a stray `::`, an undefined/phantom-typed intrinsic macro, a
value-only enumerator, a conflicting duplicate global, an unresolved
`#include`, and a few general parse-health signals (brace balance, a
residual `halt_baddata()`). An OPTIONAL second layer runs
`gcc -fsyntax-only` when a compiler happens to be on PATH
(`FWA_STAGE2_VALIDATION_GCC=true`) — never a hard dependency, since no
Docker image this pipeline builds ships a C compiler. Controlled by
`FWA_STAGE2_VALIDATION` (`off`/`warn`/`fail`, default `warn`: record every
issue in `normalized/normalization_report.json` and `Stage2Summary.
warnings`, keep the artifact either way). Standalone, independent of the
rest of the pipeline — needs only the file on disk:
```bash
python -m fw_audit.stage2_extraction.validate path/to/whole.c
python -m fw_audit.stage2_extraction.validate --gcc path/to/whole.c   # opt-in extra layer
fw_audit/stage2_extraction/validate.sh path/to/whole.c                # same thing via a shell wrapper
```
`validate.sh` is a thin `exec`-wrapper around the `python -m` command
above, not an independent implementation — an earlier draft of this gate
was a self-contained `grep -oP`-based script, but that syntax does not run
unmodified on this project's own Windows development environment
(confirmed: Git Bash/MSYS `grep` refuses `-P` outright), and hand-
maintaining the same seven defect-class checks in two languages risks them
silently drifting apart. See `validate.sh`'s own header comment for the
full rationale.

## Files

| File | Contains |
|---|---|
| `stage1_io.py`, `resolve.py` | Load Stage 1's hand-off, resolve untrusted paths to verified bytes. |
| `layout.py` | Output-tree path algebra. |
| `progress.py` | Dependency-free stderr progress bar. |
| `winreparse.py` | Reads `IO_REPARSE_TAG_LX_SYMLINK` reparse points (WSL-extracted rootfs on Windows). |
| `ghidra/command.py`, `ghidra/client.py` | Compose and run the `pyghidraRun -H` invocation. |
| `normalize/` | Prelude generation, tokenizer, structural helpers, passes, pipeline (Joern + clean), report. |
| `clean/` | tree-sitter function-only extraction — the LLM-target output written to `cleaned/` (needs the `stage2` extra, pinned `tree-sitter==0.23.2`/`tree-sitter-c==0.23.2`). `clean/errors.py` carries `CleanUnavailableError`. |
| `validate/` | The validation gate: `structural.py` (Layer A, always on), `syntax.py` (Layer B, optional `gcc`), `policy.py` (off/warn/fail), `result.py` (`ValidationIssue`/`ValidationResult`). |
| `extract.py` | `run_extraction()` orchestrator. |
| `runner.py` | `fw-extract` CLI entry point. |

## How to run

```bash
fw-extract data/db/<firmware-stem>/stage1_summary.json
fw-extract data/db/<firmware-stem>/stage1_summary.json --dry-run         # resolve only, no Ghidra
fw-extract data/db/<firmware-stem>/stage1_summary.json --only bin/httpd  # repeatable
```

## Input

`stage1_summary.json`, written by `fw-ingest`.

## Output

`data/db/<firmware-stem>/stage2/`: `resolution_report.json`,
`binaries/<bin_id>/raw/`, `binaries/<bin_id>/normalized/joern/whole.c`,
`binaries/<bin_id>/normalized/normalization_report.json` (per-pass audit
trail plus every `ValidationResult` from the gate above),
`binaries/<bin_id>/cleaned/{whole.c,functions.json}` (LLM-target, Stage 3
reads this — absent for a binary if the `stage2` extra wasn't installed),
`stage2_summary.json` (`DecompiledBinary.validation_issue_count` summarizes
the gate's findings per binary). Plus a sibling flat mirror tree
`data/db/<firmware-stem>_decompiled/` for human browsing (Joern output only).

## Docker image

A **separate** image from Stage 1's — bundling ~2GB of JDK+Ghidra into
Stage 1's image (started 6+ times per firmware) would tax every start:

```bash
docker build -f docker/Dockerfile.ghidra -t fw-audit-ghidra:latest .
```

~10 min, ~2.2 GB, network required at build time; runtime is
`--network=none`. Base image is `eclipse-temurin:21-jdk-jammy` (OpenJDK 21
isn't apt-installable on Debian bookworm).

## Debugging

- "Ghidra was not started with PyGhidra" → something invoked bare
  `analyzeHeadless` instead of `pyghidraRun -H`.
- `FWA_STAGE2_CONCURRENCY` (default 1) controls parallel decompiles — each
  Ghidra JVM reserves `FWA_GHIDRA_MAX_MEM` (default `4g`), raise carefully.
- A bad/unresolvable binary never fails the whole run — check
  `resolution_report.json`'s `unresolved` list.

## Testing

```bash
pytest -m "not integration" tests/test_stage2_extract.py tests/test_stage2_resolve.py \
  tests/test_ghidra_client.py tests/test_ghidra_command.py tests/test_normalizer*.py \
  tests/test_stage2_clean_extract.py tests/test_stage2_layout.py tests/test_stage2_validation.py
pytest -m integration tests/test_stage2_integration.py tests/test_stage2_clean_extract.py \
  tests/test_normalizer_gcc.py tests/test_stage2_validation.py   # last two need gcc on PATH
```

Cleaning needs the `stage2` extra (`pip install -e ".[stage2]"`); tests
needing it are gated with `pytest.importorskip("tree_sitter_c")` so the
rest of the suite stays green without it.

See the [project CLAUDE.md](../../CLAUDE.md) and
[project README.md](../../README.md) for cross-cutting setup.
