# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. It is the **consolidated project-level** doc — cross-cutting architecture, setup, and a router to per-stage docs. It intentionally does **not** carry stage-internal detail (file-by-file breakdowns, exact CLI flags, per-stage debugging) anymore — that lives in each stage's own `CLAUDE.md`/`README.md`, linked below.

## Project

**fw-audit** — an agentic firmware vulnerability detection system for router firmware. A six-stage pipeline: ingestion → feature extraction (decompile/normalize/clean) → analysis core (chunk/queue) → agentic analysis → sandboxed verification → reporting. Built on **LangGraph** (stateful agent orchestration), **LangChain** (multi-provider LLM abstraction), and **Docker** (sandboxed extraction).

**Current status:** Stages 1–4 are implemented, and Stage 5's Joern half is implemented. Stage 2 covers Ghidra decompilation plus BOTH normalization targets: Joern-compilable whole-program C and the LLM-facing "clean" function-only extraction (`stage2_extraction/clean/`, tree-sitter-based) — the latter moved here from Stage 3 so it's computed once and persisted, not recomputed on every Stage 3 run. Stage 3 includes both Component 1 — ingest/chunk/queue, reading Stage 2's persisted cleaned artifact — and Component 2 — the LLM vulnerability-analysis worker pool, `stage3_analysis/agent/`. Stage 4 (RAG Sink-to-Source Identifier) runs all six components (C1–C6) locally — corpus build (`fw-trace build-corpus`) plus the C3→C4→C5 driver (`fw-trace run`) over Stage 3's findings, with a Colab path for C1+C2 kept as an optional alternative. Stage 5 (Sandboxed Verification) is a tool-calling LangGraph agent (`stage5_verification/agent/`) — the repo's first genuine multi-turn tool-calling loop — that builds a Joern CPG for a Stage 3 finding's binary and runs CPGQL queries to confirm/refute it (`fw-verify run`); this is Stage 5's ONLY tool so far — QEMU+GDB dynamic verification is not yet built. Stage 6 is still an empty placeholder package.

## Stage docs — read these first for stage-specific work

**Before touching a stage, executing one of its commands, adding a feature to it, or linking it to another stage, read that stage's own `CLAUDE.md` — not this file's old per-stage sections (removed) and not the whole repo structure.** Each stage doc is self-contained and kept under 500 words: what every file does, how to invoke it, expected input/output, and debugging commands with known errors.

| Stage | Package | Docs |
|---|---|---|
| 1 — Ingestion & Pre-processing | `fw_audit/stage1_ingestion/` | [CLAUDE.md](fw_audit/stage1_ingestion/CLAUDE.md) · [README.md](fw_audit/stage1_ingestion/README.md) |
| 2 — Feature Extraction | `fw_audit/stage2_extraction/` | [CLAUDE.md](fw_audit/stage2_extraction/CLAUDE.md) · [README.md](fw_audit/stage2_extraction/README.md) |
| 3 — Analysis Core (+ agentic analysis) | `fw_audit/stage3_analysis/` | [CLAUDE.md](fw_audit/stage3_analysis/CLAUDE.md) · [README.md](fw_audit/stage3_analysis/README.md) |
| 4 — RAG Sink-to-Source Identifier | `fw_audit/stage4_rag/` | [CLAUDE.md](fw_audit/stage4_rag/CLAUDE.md) · [README.md](fw_audit/stage4_rag/README.md) |
| 5 — Sandboxed Verification (Joern agent implemented; QEMU+GDB not yet) | `fw_audit/stage5_verification/` | [CLAUDE.md](fw_audit/stage5_verification/CLAUDE.md) · [README.md](fw_audit/stage5_verification/README.md) |
| 6 — Reporting (empty) | `fw_audit/stage6_reporting/` | [CLAUDE.md](fw_audit/stage6_reporting/CLAUDE.md) · [README.md](fw_audit/stage6_reporting/README.md) |

Adding a new stage: create its package, give it a `runner.py` CLI entry registered in `pyproject.toml`, and write its `CLAUDE.md`/`README.md` pair following the same template (file table, invoke, input, output, debugging) before adding a row above.

## Quick command reference

```bash
python -m venv .venv && .venv/Scripts/activate   # Windows
pip install -e ".[dev]"                            # or ".[all,dev]" for every LLM provider

fw-ingest path/to/firmware.bin                       # Stage 1 — see its CLAUDE.md for flags
fw-extract data/db/<stem>/stage1_summary.json        # Stage 2 — see its CLAUDE.md for flags
fw-analyze data/db/<stem>/stage1_summary.json        # Stage 3 — see its CLAUDE.md for flags
fw-trace build-corpus --db-subfolder data/db/<stem> --rootfs ... --stage2-binaries ...  # Stage 4
fw-trace run --db-subfolder data/db/<stem>           # Stage 4 — see its CLAUDE.md for flags
fw-verify run --db-subfolder data/db/<stem>          # Stage 5 — see its CLAUDE.md for flags

pytest -m "not integration"   # unit tests, no Docker/LLM required
pytest -m integration         # end-to-end, needs Docker image(s) + real firmware
ruff check . && mypy fw_audit
```

Copy `.env.example` to `.env` before running anything for real. Both the Stage 1 Identifier Agent and the Stage 3 vulnerability analyst are **mandatory LLM agents, no heuristic fallback** — configure `ANTHROPIC_API_KEY` (production default: Anthropic Claude Sonnet, `ModelTier.HIGH_REASONING`) or point at local Ollama for offline testing. See "LLM routing" below.

## Cross-cutting architecture (applies across stages)

### The Executor abstraction (`fw_audit/executors/`)

A uniform interface (`Executor.run(command, files=workspace)`) so callers never know which backend answers a command — selected via `FWA_EXECUTOR_BACKEND` through `manager.get_executor()`: **`DockerExecutor`** (default, production — plain Docker, `--network=none`, used by Stage 1's deterministic Extraction Script and Stage 2's Ghidra invocations against separate images), **`SandboxExecutor`** (*LLM-controlled* execution — Stage 5's Joern verification agent is its first real consumer, `fw_audit/stage5_verification/tools/joern_tool.py`; one-shot per call like `DockerExecutor` but resource-limited via `Settings.stage5_sandbox_*`, since it runs agent-authored script content), **`LocalExecutor`** (host subprocess, tests/dev only, never production). An unrecognized backend name raises `ValueError` rather than silently degrading isolation.

### Three Docker images, deliberately separate

`docker/Dockerfile` (Stage 1's sandbox), `docker/Dockerfile.ghidra` (Stage 2's), and `docker/Dockerfile.joern` (Stage 5's, the first backing `SandboxExecutor` rather than `DockerExecutor`) are not merged — Stage 1 starts its container 6+ times per firmware, so bundling ~2GB of JDK+Ghidra (or a JVM-based Joern install) would tax every start for no benefit, and each tool's failure surface/network profile stays isolated from the others. See each stage's own docs for build commands and known traps.
Note to follow everytime: 
Docker Sandbox : will be used when Agentic AI is deployed which requires tool access. 
Docker Container : Will be used when any script or trandional based work is required. 

### LLM routing (`fw_audit/config/llm_config.py`)

Agents request an `AgentRole` (`STAGE1_BINARY_IDENTIFIER`, `STAGE3_VULN_ANALYST`, ...), which resolves through `ROLE_TO_TIER` to a `ModelTier`, which resolves through `TIER_TO_SPEC` to a `ModelSpec` (provider + model). Add new agentic roles by adding a role here (default `HIGH_REASONING` unless there's a reason not to) — never hardcode a model at the call site. Construction goes through `langchain.chat_models.init_chat_model` via a single `get_llm()`; `resolve_spec(role)` checks `Settings.stage3_analyst_model` (`FWA_STAGE3_ANALYST_MODEL`, role-specific) then `Settings.llm_model` (`FWA_LLM_MODEL`, global) before falling back to the tier tables — both `"<provider>:<model>"` strings. Provider SDKs are resolved lazily; installing one extra (`.[anthropic]`, `.[ollama]`, ...) is enough.

### Config (`fw_audit/config/settings.py`)

Single `Settings` (pydantic-settings) object, cached via `get_settings()`. No module reaches for `os.environ` directly — add new config here. LLM credentials use conventional env-var names (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_BASE_URL`); app-specific settings use the `FWA_` prefix.

### Observability (`fw_audit/observability/`)

LangSmith tracing for the three LLM-driven stages (3, 4, 5). `configure_tracing(settings)` — called once in each of `fw-analyze`/`fw-trace`/`fw-verify`'s `main()` — is the codebase's one sanctioned `os.environ` write (LangSmith is configured by env, not by constructor); `flush_traces()` runs at the end of each `main()` so a short-lived CLI process doesn't drop buffered runs on exit. `trace_context()` (a `contextvars.ContextVar`) carries `run_id`/`chunk_id`/`bin_id`/`global_id` across each stage's `asyncio.create_task` worker-pool fan-out — entered per-unit inside `AnalysisConsumer.__call__`/`stage4_rag.driver._process_one`/`stage5_verification.driver._process_one`, never once around the whole pool, so sibling tasks never see each other's context. `traced()`/`span()`/`aspan()` wrap the non-LangChain work LangSmith can't see on its own (Chroma retrieval, the Qwen3 embedder, Joern's Docker CPG-build/script-run calls); `run_config()` builds the `RunnableConfig` passed to `.ainvoke(messages, config=...)` at every structured-output call site. Every function in this package is a true no-op — same behavior, no `langsmith` import attempted — when `Settings.langsmith_tracing` is `False` (the default, via `LANGSMITH_TRACING`) or the package isn't installed (`pip install "fw-audit[observability]"`); a firmware run never fails because of a tracing misconfiguration. Model-level `tags`/`metadata` are attached as `init_chat_model` constructor kwargs in `llm_config._build_from_spec`, never via `.with_config()` — `with_structured_output()` (used at every LLM call site in this repo) returns a `RunnableBinding` with no `with_config` counterpart, so per-call identity has to be set at construction time or passed through `config=` on `.ainvoke`, not chained on afterward. See each stage's own `CLAUDE.md` for its specific spans/root-run names.

### LangSmith tracing is mandatory for agentic work — never optional at the call site

Every agentic AI workflow — every LangGraph node/graph invocation, every
`.invoke()`/`.ainvoke()` call against an LLM or a `RunnableBinding`
(including `with_structured_output()` chains), every tool call an agent
makes, and every indirect trigger of one of these (a worker-pool task that
fans out into an agent call, a CLI command that drives a graph, a `debug.py`
helper that bypasses the CLI but still invokes the same node/graph code) —
**must be covered by LangSmith tracing.** This applies across all
LLM-driven stages (3, 4, 5, and any future agentic stage), not just the
three that exist today.

Concretely, when adding or touching agentic code:

- A LangGraph `StateGraph` compile/`ainvoke()` is auto-traced by LangChain's
  native LangSmith integration — no manual wrapping needed for the graph
  itself, but confirm `configure_tracing(settings)` runs in that entry
  point's `main()` (see Observability above) or the whole tree is silently
  unrecorded.
- Any raw async/sync work an agent depends on that LangChain's
  auto-instrumentation **cannot** see on its own — a raw `docker run` via
  `Executor.run()`, a non-LangChain retrieval call (Chroma, an embedder),
  any other tool invoked outside the LangChain runnable graph — must be
  wrapped in `traced()`/`span()`/`aspan()` (`fw_audit/observability/`) with
  a `run_type="tool"` span and a descriptive name (`"<stage>.<action>"`,
  e.g. `stage5.build_cpg`), following the precedent in
  `stage5_verification/tools/joern_tool.py`.
- Every `.ainvoke(messages, config=...)` call at an LLM/structured-output
  call site must pass `config=run_config(...)` so the run lands correctly
  nested under its parent span/trace_context — never call `.ainvoke()`
  without `config=` in agentic code.
- An indirect trigger — a driver's worker-pool task, a graph node that
  itself invokes another chain, a debug/bypass helper that still exercises
  agent logic — must still enter `trace_context()` per unit of work (see
  Observability above) so its spans nest correctly and sibling tasks don't
  bleed into each other's trace.
- New agentic roles/stages must follow the same discipline from day one:
  do not ship a new LangGraph node, tool, or `.invoke()` call site without
  first checking whether it needs its own span, and document its
  spans/root-run names in that stage's own `CLAUDE.md` (see Stage 5's for
  the template).
- This must never be able to break a real run: every tracing helper is a
  true no-op when `Settings.langsmith_tracing` is `False` or the
  `observability` extra isn't installed (see Observability above) — never
  make tracing a hard dependency of the workflow actually completing.

### Cross-stage schemas (`fw_audit/common/schemas.py`, `findings.py`, `taint.py`, `verification.py`)

`schemas.py` carries the pipeline-plumbing contracts passed between stages (`FirmwareMetadata`, `IdentifiedBinary`, `Stage1Summary`, `DecompiledBinary`, `Stage2Summary`, `Stage3Summary`, ...) — later stages import these rather than re-deriving ad-hoc dicts. `findings.py` carries Stage 3 Component 2's `AnalysisReport`/`Finding`/`AnalysisRunSummary`; `taint.py` carries Stage 4's `TaintPathReport`; `verification.py` carries Stage 5's `VerificationReport`/`EvaluatorVerdict` — each the exact structured-output contract for its stage's LLM call(s), kept separate from `schemas.py` (and from each other) to avoid bloating any one file, following the same "genuinely different concern" split each module's own docstring explains. `Stage2Summary` paths are relative to `db_subfolder`, with one documented exception (`decompiled_tree_dir` — see its docstring).

### Why `fw_audit/` wraps everything

The single top-level package (rather than bare `config/`, `common/`, `stage1_ingestion/` at repo root) avoids Python import-name collisions with generic module names.

## Testing notes

The unit suite mocks both boundaries each stage depends on (`tests/conftest.py::FakeExecutor` for Docker, monkeypatched agents for LLM calls), so `pytest -m "not integration"` stays green with no Docker daemon and no LLM provider configured. Integration tests need real firmware/Docker images — see each stage's own docs for exact requirements and commands.

## Git/workflow conventions

Commit or push only when asked. Branch off `main` before committing. Follow the stage doc for the stage you're changing before making cross-stage edits — most feature work touches exactly one stage's package plus, at most, `common/schemas.py` or that stage's own `common/*.py` schema module (`findings.py`, `taint.py`, `verification.py`).
