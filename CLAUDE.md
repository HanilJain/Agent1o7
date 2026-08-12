# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**fw-audit** — an agentic firmware vulnerability detection system for router firmware. A six-stage pipeline: ingestion → feature extraction → analysis core (clean/chunk/queue) → agentic analysis → sandboxed verification → reporting. Built on **LangGraph** (stateful agent orchestration), **LangChain** (multi-provider LLM abstraction), and **Docker** (sandboxed extraction).

**Current status:** Stages 1 and 2 (`fw_audit/stage1_ingestion/`, `fw_audit/stage2_extraction/`) are implemented. Stage 3 (`fw_audit/stage3_analysis/`) has Component 1's ingestion/whitelisting step implemented; its clean/chunk/queue steps are not yet built. Stages 4–6 are empty placeholder packages (`fw_audit/stage4_analysis/` … `fw_audit/stage6_reporting/`).

## Commands

```bash
# Setup
python -m venv .venv
.venv/Scripts/activate                # Windows (this repo's dev environment)
pip install -e ".[dev]"               # core + test tooling
pip install -e ".[all,dev]"           # + every LLM provider SDK
pip install -e ".[anthropic,dev]"     # or selectively per provider (ollama/anthropic/google)

# Build the Stage 1 sandbox image (required before running real extraction)
docker build -f docker/Dockerfile -t fw-audit-sandbox:latest .
# Build the Stage 2 Ghidra image (separate — see "Two Docker images" below)
docker build -f docker/Dockerfile.ghidra -t fw-audit-ghidra:latest .

# Run Stage 1
fw-ingest path/to/firmware.bin
fw-ingest path/to/firmware.bin --tplink               # explicit TP-Link decrypt flag
fw-ingest path/to/firmware.bin --db-subfolder my-run   # override DB folder name

# Run Stage 2 (consumes Stage 1's stage1_summary.json)
fw-extract data/db/<firmware-stem>/stage1_summary.json
fw-extract data/db/<firmware-stem>/stage1_summary.json --dry-run       # resolve only, no Ghidra
fw-extract data/db/<firmware-stem>/stage1_summary.json --only bin/httpd  # repeatable

# Run Stage 3, Component 1 (consumes Stage 2's stage2_summary.json; ingestion/whitelisting only — clean/chunk/queue not yet implemented)
fw-analyze data/db/<firmware-stem>/stage1_summary.json
fw-analyze data/db/<firmware-stem>/stage1_summary.json --only bin/httpd  # repeatable

# Tests
pytest -m "not integration"           # unit tests — no Docker daemon or LLM needed
pytest -m integration                 # end-to-end against a real firmware image / Ghidra image
pytest                                 # everything (integration tests skip if not set up)
pytest tests/test_graph_integration.py -v              # single file
pytest tests/test_graph_integration.py::test_name -v   # single test
FWA_TEST_FIRMWARE=/path/to/real.bin pytest -m integration -v -s  # integration against a real image

# Lint / type-check (configured in pyproject.toml, no dedicated script)
ruff check .
mypy fw_audit
```

Copy `.env.example` to `.env` before running anything for real. The Identifier Agent is mandatory (no heuristic fallback) — configure at least one LLM provider (Ollama locally, or `ANTHROPIC_API_KEY`/`GOOGLE_API_KEY` + the matching extra) or `fw-ingest` hard-fails at the identify step.

**Current dev/testing default — local Ollama only:** this environment has no cloud LLM key configured. `ollama pull qwen2.5-coder:1.5b` is installed and is the model **every** agentic role should be wired to for now — see "LLM routing" below for how `AgentRole`/`ModelTier`/`ModelSpec` route to it. When adding a *new* agentic task/role during this phase, route it to `ModelTier.FAST_LOCAL` (already pinned to `qwen2.5-coder:1.5b`, `format="json"` forced — see the comment on that spec) rather than introducing a second local model or defaulting to a cloud tier that will hard-fail here. This is temporary: once an `ANTHROPIC_API_KEY`/`GOOGLE_API_KEY` is added for production, `ROLE_TO_TIER` entries should be flipped back to `HIGH_REASONING`/`BALANCED` as appropriate — don't design new code so it can *only* work with the local model.

## Architecture

### Stage 1's privilege split (the core design constraint)

Stage 1 enforces a hard boundary between two components — **neither one both executes code AND reasons over content with an LLM**:

- **Extraction Script** (`stage1_ingestion/extraction/`) — plain script, no LLM, full sandbox execution rights. Runs: unzip → binwalk (attempt 1) → *(if `--tplink` and attempt 1 failed)* tp-link-decrypt → binwalk (attempt 2) → unsquashfs → `tree.txt`. Everything lands in `data/db/<firmware-stem>/`.
- **Identifier Agent** (`stage1_ingestion/identifier/`) — LLM agent, zero execution/filesystem access. Reads `tree.txt` text only and returns a JSON list of `IdentifiedBinary` (path + reason) worth deeper analysis. This JSON is Stage 1's *only* output that bypasses the Database and goes straight to Stage 2 — Stage 2 fetches and verifies the actual binary bytes itself using the `path`, which is **untrusted, unvalidated LLM output** (see `IdentifiedBinary.path`'s docstring in `common/schemas.py`).

When modifying Stage 1, preserve this split: never give the Identifier Agent execution/filesystem access, never make the Extraction Script call an LLM.

### The `tplink_decrypt` trigger policy

Encoded as conditional edges in `stage1_ingestion/graph.py` (`_after_binwalk_1`/`_after_binwalk_2`), not scattered as ad-hoc `if`s, specifically so the four rules can't be silently violated by an edit to one node:

1. Never runs unless the user explicitly passes `--tplink`.
2. Even when flagged, only runs if binwalk attempt 1 did **not** succeed.
3. When triggered, decrypt runs **before** binwalk is re-run.
4. If attempt 1 succeeds, decrypt is skipped entirely — regardless of the flag.

If nothing succeeds, Stage 1 hard-fails via the `fail_unsupported` node rather than degrading silently.

### Stage 2 — Feature Extraction (`fw_audit/stage2_extraction/`)

Turns Stage 1's shortlist into decompiled, normalized artifacts via Ghidra Headless. **Fully deterministic — no LLM anywhere in it** — so it's a plain async pipeline (`extract.py::run_extraction()`), not a LangGraph, unlike every other stage.

- **`stage1_io.py`** — loads `stage1_summary.json` and resolves the rootfs root binaries are relative to, via a fallback chain (`rootfs_dir` field → `tree.txt` line 1 → `<db_subfolder>/tree.txt`) because older summaries may predate the `rootfs_dir` field (see Stage 1's `state.py`).
- **`resolve.py`** — turns each untrusted `IdentifiedBinary.path` into verified host bytes: normalizes separators, manually walks symlinks *re-rooted inside the rootfs* (never `Path.resolve()`, which would follow an absolute symlink onto the host), falls back to a basename rescan, rejects non-ELF hits, and dedupes by content hash (the busybox-applet case — N shortlisted paths that are byte-identical decompile once, not N times). **Never raises** — an unresolvable path becomes a recorded `unresolved` entry, not a failed run.
- **`ghidra/`** — `command.py` composes the `pyghidraRun -H` invocation as a pure string (no I/O, no `fw_audit.executors` import); `client.py` runs it via the `Executor` abstraction and turns the result + the export script's `metadata.json` into a `DecompiledBinary`. Points a `DockerExecutor` at a *separate* image (`FWA_GHIDRA_IMAGE`, default `fw-audit-ghidra:latest`) via the same `settings.model_copy(...)` idiom `DockerExecutor` itself uses — no `Executor` ABC change. **Must be `pyghidraRun -H`, not bare `analyzeHeadless`** — confirmed against a real build that the latter fails a `.py` `-postScript` with "Ghidra was not started with PyGhidra. Python is not available"; PyGhidra needs the JVM started *by* Python (via JPype), not the reverse.
- **`normalize/`** — the Post-Decompilation Handler / C Normalizer. Sanitizes Ghidra's decompiled C (non-standard types, `CONCATxy`/`SUBxy`/`ZEXTxy`/`SEXTxy` intrinsics, illegal `::` switch labels, undeclared `in_*`/`unaff_*`/`extraout_*` register vars) into whole-program C for Joern (`JOERN_PIPELINE`/`build_joern_pipeline`) — the only normalization target Stage 2 produces. LLM-facing preparation of decompiled code is a separate concern, handled by Stage 3 (`stage3_analysis/`) rather than here — Stage 2's own `pipeline.py` docstring names this explicitly: `build_joern_pipeline` parameterizes its target-specific passes "so a future target-specific pipeline (e.g. LLM-facing preparation, planned for a later stage) can reuse [the shared pass groups] without duplicating the shared pass list." A generated prelude header (`prelude.py::PRELUDE_HEADER`) turns every non-standard *type* into a `typedef` and every intrinsic *macro* into a `#define` — zero rewriting risk; `passes.py` handles only what a declaration can't express (illegal tokens, undeclared identifiers, duplicate definitions), as pure `(str) -> str` functions run through `spans.py`'s tokenizer so they never touch a string/char literal or comment. `normalize(normalize(x)) == normalize(x)` is a hard invariant, tested directly.
- **`extract.py`** — the orchestrator: `load → resolve → decompile (bounded by `FWA_STAGE2_CONCURRENCY`, default 1 — each Ghidra JVM reserves `FWA_GHIDRA_MAX_MEM`) → normalize → summarize`. Only the load phase can fail the run outright (`Stage2InputError`); every binary's decompile/normalize failure becomes a `DecompiledBinary(status=FAILED)` and the run continues. The normalize step also mirrors each binary's normalized whole-program C into a flat, rootfs-mirroring tree (`layout.decompiled_tree_dir` — a *sibling* of `db_subfolder`, `.c` appended to each binary's filename); see the `Stage2Summary` note below for the one path-relativity exception this causes.

### Stage 3 — Analysis Core (`fw_audit/stage3_analysis/`)

Bridges Stage 2's decompiled output to the future agentic analysis stage. Four steps — **ingest → clean → chunk → queue** — of which only ingestion is implemented today; the rest are specified but not yet built (see the plan doc referenced in git history if resuming this work). Renamed from the original `stage3_rag` placeholder: this package is not a retrieval layer, it's the Joern-to-LLM conversion bridge Stage 2's `normalize/` explicitly defers to "a later stage" (see above).

- **`stage2_io.py`** — loads `stage2_summary.json` and resolves the decompiled-mirror-tree directory, via a fallback chain (`decompiled_tree_dir` field → recomputed sibling name) for the same reason Stage 2's `stage1_io.py` needs one: the field didn't always exist. Mirrors that module's structure and `Stage3InputError` contract one stage over.
- **`whitelist.py`** — pure, zero I/O: joins Stage 1's `identified_binaries` (intent) against Stage 2's `binaries[]` (verified index) by normalized path, matching on `requested_path`, `rootfs_path`, or any `aliases` entry (the busybox-applet case).
- **`discover.py`** — the only filesystem-touching module besides `stage2_io`/`ingest.py`: locates each matched binary's `.c` file in the mirror tree via `artifacts.decompiled_tree_c` (falling back to recomputing the expected path), with `stage2_extraction.layout.is_contained` as a traversal guard before ever calling `stat()` — `decompiled_tree_c` ultimately derives from Stage 1's untrusted LLM path.
- **`ingest.py`** — the Step 1 orchestrator: `IngestionReport` with a `Target` per analyzable binary and a `SkippedTarget` (with a machine-readable reason code) per whitelisted binary that couldn't be resolved. **Never raises past the load phase** — same discipline as `stage2_extraction.resolve`, a bad/missing binary is expected input, not a bug. Writes `stage3/ingestion_report.json` itself, not only from the CLI.
- **Never writes into `stage2/` or the decompiled mirror tree** — every module here only reads Stage 2's output and writes into its own `<db_subfolder>/stage3/` directory. Steps 2 (in-memory cleaning, reusing Stage 2's repair passes plus new Joern→LLM conversion passes), 3 (tree-sitter AST-aware chunking), and 4 (an `asyncio.Queue` for a future 3-worker agent pool) are designed but not implemented.

### Two Docker images, deliberately separate

`docker/Dockerfile` (Stage 1's sandbox) and `docker/Dockerfile.ghidra` (Stage 2's) are **not merged**: Stage 1 starts its container 6+ times per firmware, so bundling ~2GB of JDK+Ghidra into that image would tax every one of those starts for zero benefit; the Stage 1 image's `tpl-builder` stage is also a known-flaky, network-heavy build (see "Known limitations" below) that Stage 2 must not inherit. Stage 2's runtime stage is built on `eclipse-temurin:21-jdk-jammy`, not `debian:bookworm-slim` — OpenJDK 21 is not installable via apt on Debian bookworm (confirmed against a real build: absent from both the regular archive and `bookworm-backports`), and Temurin's official image sidesteps that entirely.

### The Executor abstraction (`fw_audit/executors/`)

A uniform interface (`Executor.run(command, files=workspace)`) so callers never know which backend answers a command — selected via `FWA_EXECUTOR_BACKEND` through `manager.get_executor()`:

- **`DockerExecutor`** (default, `"docker"`) — plain Docker containers for the Extraction Script's fixed, deterministic command sequence, isolated with `--network=none`. This is production.
- **`SandboxExecutor`** (`"sandbox"`) — reserved, **not implemented**. Intended for future *LLM-controlled* execution (an agent writing/running its own code — Stage 4/5 territory). Stage 1 never touches it, since the Identifier Agent has zero execution rights by design. Don't wire Stage 1 to this.
- **`LocalExecutor`** (`"local"`) — host subprocess, tests/dev only. Never used for untrusted firmware in production.

An unrecognized backend name raises `ValueError` rather than silently falling back to a weaker isolation level.

### LLM routing (`fw_audit/config/llm_config.py`)

Agents request an `AgentRole` (e.g. `STAGE1_BINARY_IDENTIFIER`), which resolves through `ROLE_TO_TIER` to a `ModelTier` (`FAST_LOCAL` / `BALANCED` / `HIGH_REASONING`), which resolves through `TIER_TO_SPEC` to a concrete `ModelSpec` (provider + model). Add new agents by adding a role there rather than hardcoding a model name at the call site. Provider SDKs (`langchain-ollama`/`langchain-anthropic`/`langchain-google-genai`) are imported lazily inside each `_build_*` function, so installing only one extra is enough to use that provider.

**For now, `FAST_LOCAL` = Ollama `qwen2.5-coder:1.5b`** (local, offline, `format="json"` forced — a 1.5B model needs Ollama's constrained decoding to reliably emit valid structured output; verified empirically, see the comment on that `ModelSpec`). `STAGE1_BINARY_IDENTIFIER` is currently routed to `FAST_LOCAL` rather than its originally-designed `HIGH_REASONING` (Anthropic) because no cloud key is configured in this dev environment — this is a stand-in for development/testing, not the intended production routing. It's one call per firmware, so once a cloud key is added, flip that entry back to `HIGH_REASONING` for better accuracy on the untrusted-path-list judgment Stage 2 depends on. Any new agentic role added while still in this local-only phase should default to `FAST_LOCAL` too, so the whole pipeline stays runnable offline until API keys are wired in.

### Config (`fw_audit/config/settings.py`)

Single `Settings` (pydantic-settings) object, cached via `get_settings()`. No module should reach for `os.environ` directly — add new config here. Convention: LLM credentials use their conventional env-var names (`ANTHROPIC_API_KEY`, `OLLAMA_BASE_URL`); app-specific settings use the `FWA_` prefix.

### Cross-stage schemas (`fw_audit/common/schemas.py`)

Pydantic models forming the data contracts passed between stages (`FirmwareMetadata`, `ExtractionArtifact`, `ELFInfo`, `IdentifiedBinary`, `Stage1Summary`, `DecompiledBinary`, `Stage2Summary`, ...). Later stages should import these rather than re-deriving ad-hoc dicts. Note the Component 1/2 split reflected here too: `ELFInfo` is purely descriptive (from the Extraction Script, no judgment), `IdentifiedBinary` is strictly `{"path": str}` — no separate `extension`/`reason` field; when an extension is needed it's derived on demand from `path` via `extension_from_path`, kept as the single source of truth rather than a second field that could drift out of sync.

`Stage2Summary` fixes a defect `Stage1Summary` has: every path inside it is **relative to `db_subfolder`**, not host-absolute, so the Database directory stays relocatable — and it's written by `run_extraction()` itself, not only by the `fw-extract` CLI, so a programmatic caller (Stage 3) gets a summary too. ONE documented exception: `decompiled_tree_dir` (and by extension `DecompiledBinary.artifacts.decompiled_tree_c`) is relative to `db_subfolder`'s *parent*, not `db_subfolder` itself — the decompiled-C mirror tree (`layout.decompiled_tree_dir`) is required to live as a sibling of the run dir, so it cannot be expressed relative to `db_subfolder` without raising. See that field's docstring for the reconstruction formula.

### Why `fw_audit/` wraps everything

`fw_audit/` is the single top-level package (rather than bare `config/`, `common/`, `stage1_ingestion/` at repo root) specifically to avoid Python import-name collisions with generic module names.

## Testing notes

The unit suite mocks both boundaries Stage 1 depends on: `tests/conftest.py::FakeExecutor` stands in for Docker, and the Identifier Agent is monkeypatched — so `pytest -m "not integration"` stays green with no Docker daemon and no LLM provider configured. Stage 2's unit suite mocks the same way (`FakeExecutor` pointed at `ghidra_executor`) and additionally needs no LLM at all. Integration tests need a real firmware image (drop under `tests/fixtures/` or point `FWA_TEST_FIRMWARE` at one), the relevant Docker image(s) built, and — for Stage 1 only — an LLM provider configured. `tests/test_stage2_integration.py::test_decompiles_a_real_elf` needs only the Ghidra image (decompiles `/bin/ls` copied out of the image itself — no firmware fixture required).

## Known limitations

- TP-Link RSA-key extraction (`tp-link-decrypt`) currently fails to build against TP-Link's presently-served firmware samples (upstream firmware-content mismatch, not a defect here). The Docker image falls back to a stub that reports this clearly; `--tplink` runs hard-fail with an honest message until revisited. Everything else in the sandbox image (binwalk, squashfs-tools, sasquatch, unzip) works independently of this.
- `docker/Dockerfile.ghidra` builds successfully and `tests/test_stage2_integration.py::test_decompiles_a_real_elf` passes against real Ghidra 12.1.2 (verified: decompiles `/bin/ls`, 386 functions, normalized Joern output free of `undefined`-family types and `::`). The `GHIDRA_SHA256` currently baked in was computed from an actual downloaded release asset, not pasted — re-verify the same way after any `GHIDRA_VERSION` bump. Three build-time traps already fixed here, worth knowing if you touch this file: OpenJDK 21 isn't installable via apt on Debian bookworm at all (base image is `eclipse-temurin:21-jdk-jammy` instead, not `debian:bookworm-slim`); PyGhidra/JPype must be installed from Ghidra's own bundled wheels (`Ghidra/Features/PyGhidra/pypkg/dist/`) via `pip install --no-index -f <dist_dir> pyghidra`, not a guessed PyPI version pin (Ghidra 12.1.2 bundles pyghidra 3.1.0 + JPype1 1.5.2, not whatever version a stale pin might specify); and every headless invocation — the smoke test in this Dockerfile, and `ghidra/command.py`'s per-binary invocation — MUST go through `pyghidraRun -H`, not bare `analyzeHeadless`, or PyGhidra `.py` scripts fail with "Ghidra was not started with PyGhidra".
