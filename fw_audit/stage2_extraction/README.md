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
  -> write stage2_summary.json
```

**Path resolution:** `IdentifiedBinary.path` is untrusted LLM output — may
carry a leading `/`, be hallucinated, contain `..`, or point at a
busybox-style symlink. `resolve.py` normalizes it, walks symlinks
*re-rooted inside the rootfs* (never resolved onto the host), falls back to
a basename rescan, and dedupes by content hash.

**C normalization:** Ghidra's decompiled C isn't valid, portable C
(non-standard types, `CONCATxy`/`SUBxy` intrinsics, illegal `::` switch
labels, undeclared register vars). `normalize/` fixes this with a generated
prelude header (types → `typedef`, intrinsics → `#define`) plus small
span-aware text passes for what a declaration can't express.

## Files

| File | Contains |
|---|---|
| `stage1_io.py`, `resolve.py` | Load Stage 1's hand-off, resolve untrusted paths to verified bytes. |
| `layout.py` | Output-tree path algebra. |
| `ghidra/command.py`, `ghidra/client.py` | Compose and run the `pyghidraRun -H` invocation. |
| `normalize/` | Prelude generation, tokenizer, passes, pipeline, report. |
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
`stage2_summary.json`. Plus a sibling flat mirror tree
`data/db/<firmware-stem>_decompiled/` for human browsing.

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
  tests/test_ghidra_client.py tests/test_ghidra_command.py tests/test_normalizer*.py
pytest -m integration tests/test_stage2_integration.py   # needs the Ghidra image only
```

See the [project CLAUDE.md](../../CLAUDE.md) and
[project README.md](../../README.md) for cross-cutting setup.
