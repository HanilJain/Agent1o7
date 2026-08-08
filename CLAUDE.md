# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**fw-audit** — an agentic firmware vulnerability detection system for router firmware. A six-stage pipeline: ingestion → feature extraction → RAG fusion → agentic analysis → sandboxed verification → reporting. Built on **LangGraph** (stateful agent orchestration), **LangChain** (multi-provider LLM abstraction), and **Docker** (sandboxed extraction).

**Current status:** Only Stage 1 (`fw_audit/stage1_ingestion/`) is implemented. Stages 2–6 are empty placeholder packages (`fw_audit/stage2_extraction/` … `fw_audit/stage6_reporting/`).

## Commands

```bash
# Setup
python -m venv .venv
.venv/Scripts/activate                # Windows (this repo's dev environment)
pip install -e ".[dev]"               # core + test tooling
pip install -e ".[all,dev]"           # + every LLM provider SDK
pip install -e ".[anthropic,dev]"     # or selectively per provider (ollama/anthropic/google)

# Build the sandbox image (required before running real extraction)
docker build -f docker/Dockerfile -t fw-audit-sandbox:latest .

# Run Stage 1
fw-ingest path/to/firmware.bin
fw-ingest path/to/firmware.bin --tplink               # explicit TP-Link decrypt flag
fw-ingest path/to/firmware.bin --db-subfolder my-run   # override DB folder name

# Tests
pytest -m "not integration"           # unit tests — no Docker daemon or LLM needed
pytest -m integration                 # end-to-end against a real firmware image
pytest                                 # everything (integration tests skip if not set up)
pytest tests/test_graph_integration.py -v              # single file
pytest tests/test_graph_integration.py::test_name -v   # single test
FWA_TEST_FIRMWARE=/path/to/real.bin pytest -m integration -v -s  # integration against a real image

# Lint / type-check (configured in pyproject.toml, no dedicated script)
ruff check .
mypy fw_audit
```

Copy `.env.example` to `.env` before running anything for real. The Identifier Agent is mandatory (no heuristic fallback) — configure at least one LLM provider (Ollama locally, or `ANTHROPIC_API_KEY`/`GOOGLE_API_KEY` + the matching extra) or `fw-ingest` hard-fails at the identify step.

## Architecture

### Stage 1's privilege split (the core design constraint)

Stage 1 enforces a hard boundary between two components — **neither one both executes code AND reasons over content with an LLM**:

- **Extraction Script** (`stage1_ingestion/extraction/`) — plain script, no LLM, full sandbox execution rights. Runs: unzip → binwalk (attempt 1) → *(if `--tplink` and attempt 1 failed)* tp-link-decrypt → binwalk (attempt 2) → unsquashfs → `tree.txt`. Everything lands in `data/db/<firmware-stem>/`.
- **Identifier Agent** (`stage1_ingestion/identifier/`) — LLM agent, zero execution/filesystem access. Reads `tree.txt` text only and returns a JSON list of `IdentifiedBinary` (path + reason) worth deeper analysis. This JSON is Stage 1's *only* output that bypasses the Database and goes straight to Stage 2 (Ghidra MCP) — Stage 2 fetches the actual binary bytes itself using the `path`.

When modifying Stage 1, preserve this split: never give the Identifier Agent execution/filesystem access, never make the Extraction Script call an LLM.

### The `tplink_decrypt` trigger policy

Encoded as conditional edges in `stage1_ingestion/graph.py` (`_after_binwalk_1`/`_after_binwalk_2`), not scattered as ad-hoc `if`s, specifically so the four rules can't be silently violated by an edit to one node:

1. Never runs unless the user explicitly passes `--tplink`.
2. Even when flagged, only runs if binwalk attempt 1 did **not** succeed.
3. When triggered, decrypt runs **before** binwalk is re-run.
4. If attempt 1 succeeds, decrypt is skipped entirely — regardless of the flag.

If nothing succeeds, Stage 1 hard-fails via the `fail_unsupported` node rather than degrading silently.

### The Executor abstraction (`fw_audit/executors/`)

A uniform interface (`Executor.run(command, files=workspace)`) so callers never know which backend answers a command — selected via `FWA_EXECUTOR_BACKEND` through `manager.get_executor()`:

- **`DockerExecutor`** (default, `"docker"`) — plain Docker containers for the Extraction Script's fixed, deterministic command sequence, isolated with `--network=none`. This is production.
- **`SandboxExecutor`** (`"sandbox"`) — reserved, **not implemented**. Intended for future *LLM-controlled* execution (an agent writing/running its own code — Stage 4/5 territory). Stage 1 never touches it, since the Identifier Agent has zero execution rights by design. Don't wire Stage 1 to this.
- **`LocalExecutor`** (`"local"`) — host subprocess, tests/dev only. Never used for untrusted firmware in production.

An unrecognized backend name raises `ValueError` rather than silently falling back to a weaker isolation level.

### LLM routing (`fw_audit/config/llm_config.py`)

Agents request an `AgentRole` (e.g. `STAGE1_BINARY_IDENTIFIER`), which resolves through `ROLE_TO_TIER` to a `ModelTier` (`FAST_LOCAL` / `BALANCED` / `HIGH_REASONING`), which resolves through `TIER_TO_SPEC` to a concrete `ModelSpec` (provider + model). Add new agents by adding a role there rather than hardcoding a model name at the call site. Provider SDKs (`langchain-ollama`/`langchain-anthropic`/`langchain-google-genai`) are imported lazily inside each `_build_*` function, so installing only one extra is enough to use that provider.

### Config (`fw_audit/config/settings.py`)

Single `Settings` (pydantic-settings) object, cached via `get_settings()`. No module should reach for `os.environ` directly — add new config here. Convention: LLM credentials use their conventional env-var names (`ANTHROPIC_API_KEY`, `OLLAMA_BASE_URL`); app-specific settings use the `FWA_` prefix.

### Cross-stage schemas (`fw_audit/common/schemas.py`)

Pydantic models forming the data contracts passed between stages (`FirmwareMetadata`, `ExtractionArtifact`, `ELFInfo`, `IdentifiedBinary`). Later stages should import these rather than re-deriving ad-hoc dicts. Note the Component 1/2 split reflected here too: `ELFInfo` is purely descriptive (from the Extraction Script, no judgment), `IdentifiedBinary` carries the Identifier Agent's judgment (`reason`).

### Why `fw_audit/` wraps everything

`fw_audit/` is the single top-level package (rather than bare `config/`, `common/`, `stage1_ingestion/` at repo root) specifically to avoid Python import-name collisions with generic module names.

## Testing notes

The unit suite mocks both boundaries Stage 1 depends on: `tests/conftest.py::FakeExecutor` stands in for Docker, and the Identifier Agent is monkeypatched — so `pytest -m "not integration"` stays green with no Docker daemon and no LLM provider configured. Integration tests need a real firmware image (drop under `tests/fixtures/` or point `FWA_TEST_FIRMWARE` at one), the sandbox image built, and an LLM provider configured.

## Known limitation

TP-Link RSA-key extraction (`tp-link-decrypt`) currently fails to build against TP-Link's presently-served firmware samples (upstream firmware-content mismatch, not a defect here). The Docker image falls back to a stub that reports this clearly; `--tplink` runs hard-fail with an honest message until revisited. Everything else in the sandbox image (binwalk, squashfs-tools, sasquatch, unzip) works independently of this.
