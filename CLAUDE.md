# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. It is the **consolidated project-level** doc — cross-cutting architecture, setup, and a router to per-stage docs. It intentionally does **not** carry stage-internal detail (file-by-file breakdowns, exact CLI flags, per-stage debugging) anymore — that lives in each stage's own `CLAUDE.md`/`README.md`, linked below.

## Project

**fw-audit** — an agentic firmware vulnerability detection system for router firmware. A six-stage pipeline: ingestion → feature extraction (decompile/normalize/clean) → analysis core (chunk/queue) → agentic analysis → sandboxed verification → reporting. Built on **LangGraph** (stateful agent orchestration), **LangChain** (multi-provider LLM abstraction), and **Docker** (sandboxed extraction).

**Current status:** Stages 1–3 are implemented. Stage 2 covers Ghidra decompilation plus BOTH normalization targets: Joern-compilable whole-program C and the LLM-facing "clean" function-only extraction (`stage2_extraction/clean/`, tree-sitter-based) — the latter moved here from Stage 3 so it's computed once and persisted, not recomputed on every Stage 3 run. Stage 3 includes both Component 1 — ingest/chunk/queue, reading Stage 2's persisted cleaned artifact — and Component 2 — the LLM vulnerability-analysis worker pool, `stage3_analysis/agent/`. Stages 4–6 are empty placeholder packages.

## Stage docs — read these first for stage-specific work

**Before touching a stage, executing one of its commands, adding a feature to it, or linking it to another stage, read that stage's own `CLAUDE.md` — not this file's old per-stage sections (removed) and not the whole repo structure.** Each stage doc is self-contained and kept under 500 words: what every file does, how to invoke it, expected input/output, and debugging commands with known errors.

| Stage | Package | Docs |
|---|---|---|
| 1 — Ingestion & Pre-processing | `fw_audit/stage1_ingestion/` | [CLAUDE.md](fw_audit/stage1_ingestion/CLAUDE.md) · [README.md](fw_audit/stage1_ingestion/README.md) |
| 2 — Feature Extraction | `fw_audit/stage2_extraction/` | [CLAUDE.md](fw_audit/stage2_extraction/CLAUDE.md) · [README.md](fw_audit/stage2_extraction/README.md) |
| 3 — Analysis Core (+ agentic analysis) | `fw_audit/stage3_analysis/` | [CLAUDE.md](fw_audit/stage3_analysis/CLAUDE.md) · [README.md](fw_audit/stage3_analysis/README.md) |
| 4 — RAG Sink-to-Source Identifier (in progress) | `fw_audit/stage4_rag/` | [CLAUDE.md](fw_audit/stage4_rag/CLAUDE.md) · [README.md](fw_audit/stage4_rag/README.md) |
| 5 — Sandboxed Verification (empty) | `fw_audit/stage5_verification/` | [CLAUDE.md](fw_audit/stage5_verification/CLAUDE.md) · [README.md](fw_audit/stage5_verification/README.md) |
| 6 — Reporting (empty) | `fw_audit/stage6_reporting/` | [CLAUDE.md](fw_audit/stage6_reporting/CLAUDE.md) · [README.md](fw_audit/stage6_reporting/README.md) |

Adding a new stage: create its package, give it a `runner.py` CLI entry registered in `pyproject.toml`, and write its `CLAUDE.md`/`README.md` pair following the same template (file table, invoke, input, output, debugging) before adding a row above.

## Quick command reference

```bash
python -m venv .venv && .venv/Scripts/activate   # Windows
pip install -e ".[dev]"                            # or ".[all,dev]" for every LLM provider

fw-ingest path/to/firmware.bin                       # Stage 1 — see its CLAUDE.md for flags
fw-extract data/db/<stem>/stage1_summary.json        # Stage 2 — see its CLAUDE.md for flags
fw-analyze data/db/<stem>/stage1_summary.json        # Stage 3 — see its CLAUDE.md for flags

pytest -m "not integration"   # unit tests, no Docker/LLM required
pytest -m integration         # end-to-end, needs Docker image(s) + real firmware
ruff check . && mypy fw_audit
```

Copy `.env.example` to `.env` before running anything for real. Both the Stage 1 Identifier Agent and the Stage 3 vulnerability analyst are **mandatory LLM agents, no heuristic fallback** — configure `ANTHROPIC_API_KEY` (production default: Anthropic Claude Sonnet, `ModelTier.HIGH_REASONING`) or point at local Ollama for offline testing. See "LLM routing" below.

## Cross-cutting architecture (applies across stages)

### The Executor abstraction (`fw_audit/executors/`)

A uniform interface (`Executor.run(command, files=workspace)`) so callers never know which backend answers a command — selected via `FWA_EXECUTOR_BACKEND` through `manager.get_executor()`: **`DockerExecutor`** (default, production — plain Docker, `--network=none`, used by Stage 1's deterministic Extraction Script and Stage 2's Ghidra invocations against separate images), **`SandboxExecutor`** (reserved, **not implemented** — intended for future *LLM-controlled* execution, Stage 5 territory), **`LocalExecutor`** (host subprocess, tests/dev only, never production). An unrecognized backend name raises `ValueError` rather than silently degrading isolation.

### Two Docker images, deliberately separate

`docker/Dockerfile` (Stage 1's sandbox) and `docker/Dockerfile.ghidra` (Stage 2's) are not merged — Stage 1 starts its container 6+ times per firmware, so bundling ~2GB of JDK+Ghidra would tax every start for no benefit, and Stage 1's `tpl-builder` stage is a known-flaky build Stage 2 must not inherit. See each stage's own docs for build commands and known traps.
Note to follow everytime: 
Docker Sandbox : will be used when Agentic AI is deployed which requires tool access. 
Docker Container : Will be used when any script or trandional based work is required. 

### LLM routing (`fw_audit/config/llm_config.py`)

Agents request an `AgentRole` (`STAGE1_BINARY_IDENTIFIER`, `STAGE3_VULN_ANALYST`, ...), which resolves through `ROLE_TO_TIER` to a `ModelTier`, which resolves through `TIER_TO_SPEC` to a `ModelSpec` (provider + model). Add new agentic roles by adding a role here (default `HIGH_REASONING` unless there's a reason not to) — never hardcode a model at the call site. Construction goes through `langchain.chat_models.init_chat_model` via a single `get_llm()`; `resolve_spec(role)` checks `Settings.stage3_analyst_model` (`FWA_STAGE3_ANALYST_MODEL`, role-specific) then `Settings.llm_model` (`FWA_LLM_MODEL`, global) before falling back to the tier tables — both `"<provider>:<model>"` strings. Provider SDKs are resolved lazily; installing one extra (`.[anthropic]`, `.[ollama]`, ...) is enough.

### Config (`fw_audit/config/settings.py`)

Single `Settings` (pydantic-settings) object, cached via `get_settings()`. No module reaches for `os.environ` directly — add new config here. LLM credentials use conventional env-var names (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_BASE_URL`); app-specific settings use the `FWA_` prefix.

### Cross-stage schemas (`fw_audit/common/schemas.py`, `fw_audit/common/findings.py`)

`schemas.py` carries the pipeline-plumbing contracts passed between stages (`FirmwareMetadata`, `IdentifiedBinary`, `Stage1Summary`, `DecompiledBinary`, `Stage2Summary`, `Stage3Summary`, ...) — later stages import these rather than re-deriving ad-hoc dicts. `findings.py` carries Stage 3 Component 2's `AnalysisReport`/`Finding`/`AnalysisRunSummary` — the exact structured-output contract, kept separate from `schemas.py` to avoid bloating it further. `Stage2Summary` paths are relative to `db_subfolder`, with one documented exception (`decompiled_tree_dir` — see its docstring).

### Why `fw_audit/` wraps everything

The single top-level package (rather than bare `config/`, `common/`, `stage1_ingestion/` at repo root) avoids Python import-name collisions with generic module names.

## Testing notes

The unit suite mocks both boundaries each stage depends on (`tests/conftest.py::FakeExecutor` for Docker, monkeypatched agents for LLM calls), so `pytest -m "not integration"` stays green with no Docker daemon and no LLM provider configured. Integration tests need real firmware/Docker images — see each stage's own docs for exact requirements and commands.

## Git/workflow conventions

Commit or push only when asked. Branch off `main` before committing. Follow the stage doc for the stage you're changing before making cross-stage edits — most feature work touches exactly one stage's package plus, at most, `common/schemas.py` or `common/findings.py`.
