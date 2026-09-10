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
- `normalize/` must never import `validate/` (siblings, not parent/child —
  `validate/syntax.py` imports `subprocess`, which `normalize/`'s own
  import-purity test forbids transitively). Enforced by
  `test_normalizer.py::test_normalize_does_not_import_validate`.
- `validate/structural.py` (Layer A) must stay dependency-free — no
  `subprocess`, no external tool, no Docker. Only `validate/syntax.py`
  (Layer B, strictly optional) may import `subprocess`/`shutil`.
- `canonicalize_ghidra_symbols` (the first pass in the Joern pipeline after
  line-ending normalization) must NEVER be routed through `spans.
  apply_to_code` — it is the pass that makes the tokenizer trustworthy in
  the first place; doing so would silently reintroduce the exact desync it
  exists to repair. Pinned by `test_p01b_does_not_use_apply_to_code`.

## Files

| File | Purpose |
|---|---|
| `stage1_io.py` | Loads `stage1_summary.json`, resolves `rootfs_dir`. |
| `resolve.py` | Untrusted `IdentifiedBinary.path` → verified host bytes: normalize, symlink-walk (re-rooted), basename rescan, ELF check, hash dedupe. **Never raises** — bad paths become `unresolved`. |
| `layout.py` | Path algebra for `stage2/`'s output tree. |
| `progress.py` | Dependency-free stderr progress bar. |
| `winreparse.py` | Reads `IO_REPARSE_TAG_LX_SYMLINK` reparse points (WSL-extracted rootfs on Windows) — what `resolve.py`'s symlink walk needs on that platform. |
| `ghidra/command.py` | Pure `pyghidraRun -H` command-string composition. |
| `ghidra/client.py` | Runs it via `Executor`, parses `metadata.json` → `DecompiledBinary`. |
| `normalize/prelude.py` | Generates `ghidra_types.h` — self-contained fixed-width types (NO `#include`, see Defect Class 4/7 below), full combinatorial `CONCAT`/`SUB`/`ZEXT`/`SEXT` macro set. Joern target only. |
| `normalize/spans.py` | CODE\|STRING\|CHAR\|COMMENT tokenizer — every pass runs through this, EXCEPT `canonicalize_ghidra_symbols` (see hard constraints above). |
| `normalize/structure.py` | `find_function_bodies`/`find_enum_bodies`/`splice` — the structural primitives body- and enum-scoped passes share. |
| `normalize/context.py` | `BinaryContext`/`build_context` — per-binary thunk/external/known-function-name sets threaded into the context-bound passes. |
| `normalize/passes.py` | Pure `(str) -> str` passes: illegal-character symbol names, value-only enumerators, illegal `::` labels, undeclared register vars, dup defs, `void`-as-value functions, missing forward declarations. |
| `normalize/pipeline.py` | `JOERN_PIPELINE`/`build_joern_pipeline`, `CLEAN_PIPELINE`/`build_clean_pipeline`, `normalize()` — see its module docstring for the full pass ordering rationale. |
| `normalize/report.py` | `PassStat` / `NormalizationResult` / `NormalizationReport` (the latter's `validation` field carries `validate/`'s output as plain dicts, never the dataclass — see hard constraints above). |
| `validate/__init__.py` | Public API (`validate_text`/`validate_file`) + `python -m fw_audit.stage2_extraction.validate <file>` CLI. |
| `validate/structural.py` | Layer A: always-on, dependency-free structural checks (span desync, illegal identifiers, undefined/phantom intrinsics, anonymous enumerators, duplicate globals, `void`-as-value, missing prototypes, unresolved includes, brace balance, residual `halt_baddata`). |
| `validate/syntax.py` | Layer B: optional `gcc -fsyntax-only`, only when a compiler is on PATH. |
| `validate/policy.py` | `apply_policy` — off/warn/fail. |
| `validate/result.py` | `Severity`/`ValidationIssue`/`ValidationResult`. |
| `clean/parser.py`, `clean/extract.py` | tree-sitter function-only extraction (needs the `stage2` extra, pinned `tree-sitter==0.23.2`/`tree-sitter-c==0.23.2`) — the LLM-target output. |
| `clean/index.py` | JSON (de)serialization of `cleaned/functions.json`. |
| `clean/errors.py` | `CleanUnavailableError` — raised when `tree-sitter`/`tree-sitter-c` isn't installed; caught in `extract.py`, never fatal. |
| `extract.py` | `run_extraction()`: load → resolve → decompile → normalize (Joern + clean) → validate → summarize. |
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
- `binaries/<bin_id>/normalized/normalization_report.json` — per-pass audit
  trail plus every `ValidationResult` the gate produced for this binary
  (one per layer actually run — structural always, gcc only if enabled and
  available).
- `binaries/<bin_id>/cleaned/{whole.c,functions.json}` — LLM-target,
  function-only extraction (`whole.c` = kept functions concatenated in
  source order; `functions.json` = per-function `{name, start_line,
  end_line}` index, spans relative to `whole.c` itself). Absent for a
  binary if the `stage2` extra wasn't installed when Stage 2 ran — see
  `DecompiledBinary.warnings`. **This is what Stage 3's chunking reads
  directly** — Stage 3 no longer runs tree-sitter itself.
- `stage2_summary.json` — hand-off to Stage 3, every path relative to
  `db_subfolder` **except** `decompiled_tree_dir` (relative to its parent —
  see that field's docstring). `DecompiledBinary.validation_issue_count`
  summarizes the gate's total issue count for that binary.
- Sibling mirror tree `data/db/<stem>_decompiled/` — flat rootfs-mirroring
  `.c` copies of the JOERN output only, human-browsing view.

## Validation gate settings

- `FWA_STAGE2_VALIDATION` — `off` / `warn` (default) / `fail`. `warn`
  records every issue in `normalization_report.json` and
  `Stage2Summary.warnings` but never fails the run; `fail` additionally
  marks the binary `DecompilationStatus.FAILED` on any ERROR-severity
  issue — the artifact is still written either way (it's the evidence).
- `FWA_STAGE2_VALIDATION_GCC` — `true` to also run `gcc -fsyntax-only`
  when a compiler is on PATH. Default `false`; no Docker image this
  pipeline builds ships a compiler, so this only ever does anything on a
  host that happens to have one.
- `FWA_STAGE2_VALIDATION_CC` — compiler executable name/path for the
  above (default `gcc`).

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
- Suspect a broken `whole.c` reaching Joern? Run the standalone gate
  directly — no Docker, no `fw-extract`, needs only the file:
  `python -m fw_audit.stage2_extraction.validate <path>` (add `--gcc` if a
  compiler is on PATH). Exits 1 on any ERROR-severity issue.
- Unit: `pytest -m "not integration" tests/test_stage2_extract.py tests/test_stage2_resolve.py tests/test_ghidra_client.py tests/test_ghidra_command.py tests/test_normalizer*.py tests/test_stage2_clean_extract.py tests/test_stage2_validation.py`
- Integration: `test_decompiles_a_real_elf` needs only the Ghidra image;
  `test_stage2_on_real_firmware` also needs a prior `fw-ingest` run;
  `test_clean_pipeline_against_real_committed_wpasupp` (in
  `test_stage2_clean_extract.py`) needs only the committed real data;
  `test_normalizer_gcc.py`/`test_stage2_validation.py`'s Layer B tests need
  `gcc` on PATH (skipped otherwise).
- Missing `tree-sitter`/`tree-sitter-c` (the `stage2` extra): cleaning is
  skipped per-binary with a warning in `Stage2Summary.warnings` — the Joern
  artifact and the rest of the run are unaffected.

## Adding a feature here

New normalization passes go in `normalize/passes.py`, run through
`spans.py`'s tokenizer, added to whichever pipeline(s) they apply to
(`JOERN_PIPELINE`/`build_joern_pipeline`, `CLEAN_PIPELINE`/
`build_clean_pipeline`, or both), re-verified for idempotency. Both
pipelines share `_head_passes`/`_body_passes`/`_tail_passes` — see
`pipeline.py`'s module docstring for how they diverge (FOUR
target-specific passes each as of the validation-hardening work:
warnings, prelude, halt_baddata, and prototype-hoisting). Downstream
consumption of the cleaned artifact (chunking, LLM analysis) belongs in
Stage 3 — see `stage3_analysis/CLAUDE.md`.

New Layer A validation checks go in `validate/structural.py` as a
`_check_*(text: str) -> tuple[ValidationIssue, ...]` function added to
`_CHECKS`, stdlib + `normalize.spans`/`normalize.structure` only — never
`normalize/` itself (see hard constraints above) and never `subprocess`.
Run it against CODE spans / `mask_non_code`, not raw `text`, or a comment
mentioning the defect it's checking for (e.g. explaining a historical bug
in prose) becomes a false positive — confirmed the hard way while writing
this gate.

**Known, deliberately out-of-scope residual:** some Ghidra thunk/PLT stubs
use a raw indirect-call-through-register trampoline shape (`(**(code
**)(unaff_gp + -0x7ff0))();`, repeated) that `replace_thunk_bodies`'s
narrow `_is_self_forwarding_stub` shape check does not recognize — such a
stub is left as an ordinary function body, and its Ghidra-written header
can reference real system-header type names (`sockaddr`, `FILE`,
`addrinfo`, ...) this closed-world translation unit never defines.
`hoist_function_prototypes` deliberately VETOES hoisting a prototype for
any name `context.thunk_names`/`context.external_names` flags (see that
function's docstring) rather than emitting a type-broken prototype, so
this surfaces as `missing_prototype` WARNINGs (implicit-int, not a
Joern-CDT parse failure — CDT doesn't type-check) rather than a hard
error. Widening `replace_thunk_bodies`'s stub-shape detection to also
recognize this trampoline pattern would eliminate it, but is a separate,
larger change than the seven defect classes this gate targets.
