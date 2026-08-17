# fw-audit — Agentic Firmware Vulnerability Detection System

A six-stage agentic pipeline for automated router-firmware vulnerability
auditing: ingestion → feature extraction (decompile + normalize + clean)
→ analysis core (chunk/queue) → agentic analysis → sandboxed verification →
reporting. Built on **LangGraph** (stateful agent orchestration),
**LangChain** (unified LLM abstraction), and **Docker** (sandboxed
extraction).

**Current status:** Stages 1–4 are implemented — Stage 1 (Ingestion),
Stage 2 (Feature Extraction, including the LLM-facing "clean" function-only
extraction), Stage 3 (Analysis Core — both Component 1's ingest/chunk/queue
and Component 2's LLM vulnerability-analysis worker pool), and Stage 4 (RAG
Sink-to-Source Identifier, all six components running locally — see
[MASTERPLAN_STAGE4.md](MASTERPLAN_STAGE4.md)). Stage 5 (Sandboxed
Verification) has its Joern half implemented — a tool-calling agent that
builds a CPG for a Stage 3 finding's binary and runs Joern/CPGQL queries to
confirm or refute it; QEMU+GDB dynamic verification is not yet built. Stage
6 is still a scaffolded empty sub-package (`fw_audit/stage6_reporting/`).

## Stage documentation

Each stage carries its own `CLAUDE.md` (agent-oriented quick reference) and
`README.md` (human-oriented walkthrough) — file inventory, exact CLI
invocation, input/output, and debugging commands. **Read the relevant
stage's docs before working on it or wiring in a new one**, rather than
re-deriving detail from this file or the full source tree:

| Stage | Package | Docs |
|---|---|---|
| 1 — Ingestion & Pre-processing | `fw_audit/stage1_ingestion/` | [CLAUDE.md](fw_audit/stage1_ingestion/CLAUDE.md) · [README.md](fw_audit/stage1_ingestion/README.md) |
| 2 — Feature Extraction | `fw_audit/stage2_extraction/` | [CLAUDE.md](fw_audit/stage2_extraction/CLAUDE.md) · [README.md](fw_audit/stage2_extraction/README.md) |
| 3 — Analysis Core (+ agentic analysis) | `fw_audit/stage3_analysis/` | [CLAUDE.md](fw_audit/stage3_analysis/CLAUDE.md) · [README.md](fw_audit/stage3_analysis/README.md) |
| 4 — RAG Sink-to-Source Identifier | `fw_audit/stage4_rag/` | [CLAUDE.md](fw_audit/stage4_rag/CLAUDE.md) · [README.md](fw_audit/stage4_rag/README.md) |
| 5 — Sandboxed Verification (Joern agent implemented; QEMU+GDB not yet) | `fw_audit/stage5_verification/` | [CLAUDE.md](fw_audit/stage5_verification/CLAUDE.md) · [README.md](fw_audit/stage5_verification/README.md) |
| 6 — Reporting (empty) | `fw_audit/stage6_reporting/` | [CLAUDE.md](fw_audit/stage6_reporting/CLAUDE.md) · [README.md](fw_audit/stage6_reporting/README.md) |

The project-level [CLAUDE.md](CLAUDE.md) covers cross-cutting architecture
that spans stages (the Executor abstraction, LLM routing, Settings,
cross-stage schemas) — this file covers setup, layout, and pointers.

## Pipeline at a glance

- **Stage 1** enforces a hard privilege split: a plain Extraction Script
  (full sandbox rights, zero LLM) unpacks the firmware; an Identifier Agent
  (LLM, zero execution rights) reads the resulting `tree.txt` and shortlists
  binaries worth deeper analysis.
- **Stage 2** is fully deterministic (no LLM) — it decompiles Stage 1's
  shortlist with Ghidra Headless and delivers TWO normalization targets
  from the same raw C: Joern-compilable whole-program C, and LLM-facing
  function-only text (persisted to `cleaned/`, tree-sitter-based).
- **Stage 3** reads Stage 2's persisted cleaned text, chunks it along
  function boundaries, queues the chunks through an in-process
  `asyncio.Queue`, and runs each through an LLM vulnerability analyst,
  producing validated findings per chunk.

See each stage's own docs (table above) for the full mechanics.

## Execution architecture: the Executor abstraction

`fw_audit/executors/` provides a uniform interface so callers never know or
care which backend answers `executor.run(command, files=workspace)`:
**`DockerExecutor`** (production default — deterministic pipelines,
`--network=none`), **`SandboxExecutor`** (LLM-controlled execution —
Stage 5's Joern verification agent is its first real consumer; one-shot per
call, resource-limited), **`LocalExecutor`** (host subprocess, tests/dev
only). Selected via `FWA_EXECUTOR_BACKEND`.

## Project Layout

```
fw_audit/
  executors/               # Executor abstraction (see above)
  config/                  # settings.py, llm_config.py
  common/                  # schemas.py, findings.py, constants.py
  stage1_ingestion/         # Stage 1 — see its CLAUDE.md/README.md
  stage2_extraction/        # Stage 2 — see its CLAUDE.md/README.md
  stage3_analysis/           # Stage 3 — see its CLAUDE.md/README.md
  stage4_rag/                # Stage 4 — see its CLAUDE.md/README.md
  stage5_verification/        # Stage 5 (Joern agent) — see its CLAUDE.md/README.md
  stage6_reporting/          # Scaffolded, not yet implemented
docker/
  Dockerfile               # Stage 1's sandbox image
  Dockerfile.ghidra        # Stage 2's Ghidra image — separate, see Stage 2 docs
  Dockerfile.joern         # Stage 5's Joern sandbox image — separate, see Stage 5 docs
  ghidra_scripts/          # PyGhidra headless export script + build-time smoke test
data/
  firmware/                # Drop raw firmware images here (gitignored)
  db/                      # Per-firmware Database subfolders (gitignored)
tests/
  fixtures/                # Real firmware samples + synthetic fixtures
```

`fw_audit/` is the single top-level package (rather than bare `config/`,
`common/`, `stage1_ingestion/` at repo root) to avoid Python import-name
collisions with generic module names.

## Setup

For a full, detailed walkthrough (system packages, Python env, `.env`,
building all three Docker images including the Joern image's large-download
handling, and a troubleshooting table of known errors) see
**[SETUP.md](SETUP.md)** — Linux-first. The quick version:

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows
# source .venv/bin/activate   # Linux/macOS

pip install -e ".[dev]"       # core + test tooling
pip install -e ".[all,dev]"   # + every LLM provider SDK
# or selectively: pip install -e ".[anthropic,dev]" / ".[ollama,dev]"
```

Copy `.env.example` to `.env` and fill in what you need. Both Stage 1's
Identifier Agent and Stage 3's vulnerability analyst are **mandatory LLM
agents — no heuristic fallback**. Production default is Anthropic Claude
Sonnet (`ANTHROPIC_API_KEY`); for offline testing, install Ollama and set
`FWA_LLM_MODEL=ollama:qwen2.5-coder:1.5b` (or the per-role
`FWA_STAGE3_ANALYST_MODEL`). See `fw_audit/config/llm_config.py` and each
stage's docs for exact routing.

Docker images (build before running the relevant stage for real):

```bash
docker build -f docker/Dockerfile -t fw-audit-sandbox:latest .          # Stage 1
docker build -f docker/Dockerfile.ghidra -t fw-audit-ghidra:latest .    # Stage 2
docker build -f docker/Dockerfile.joern -t fw-audit-joern:latest .      # Stage 5
```

The Joern image needs `docker/.joern-cli.zip` (~1.8GB) pre-fetched to the
host first — see [SETUP.md §4.3](SETUP.md#43-stage-5--joern-verification-sandbox-fw-audit-joernlatest)
for the exact command and why.

## Running the pipeline

```bash
fw-ingest path/to/firmware.bin                        # Stage 1
fw-extract data/db/<firmware-stem>/stage1_summary.json # Stage 2
fw-analyze data/db/<firmware-stem>/stage1_summary.json --analyze # Stage 3
fw-trace build-corpus --db-subfolder data/db/<stem> ...          # Stage 4
fw-trace run --db-subfolder data/db/<stem>                       # Stage 4
fw-verify run --db-subfolder data/db/<stem>                      # Stage 5
```

Full flag reference, expected input/output, and debugging steps for each
command live in that stage's own docs (table above) — not duplicated here.

## Testing

```bash
pytest -m "not integration"   # unit tests; no Docker daemon or LLM needed
pytest -m integration         # end-to-end against real firmware / Docker images
pytest                        # everything (integration tests skip if unset up)
```

The unit suite mocks both the Docker and LLM boundaries every stage
depends on (`tests/conftest.py::FakeExecutor`, monkeypatched agents), so it
stays green without a daemon running or any provider configured. See each
stage's docs for stage-specific integration-test requirements.
