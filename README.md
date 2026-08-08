# fw-audit — Agentic Firmware Vulnerability Detection System

A six-stage agentic pipeline for automated router-firmware vulnerability
auditing: ingestion → feature extraction → RAG fusion → agentic analysis →
sandboxed verification → reporting. Built on **LangGraph** (stateful agent
orchestration), **LangChain** (unified LLM abstraction), **MCP** (tool
integration for later stages), and **Docker** (sandboxed extraction).

**Current status:** Stage 1 (Firmware Ingestion & Pre-processing) is
implemented. Stages 2–6 are scaffolded as empty sub-packages
(`fw_audit/stage2_extraction/` … `fw_audit/stage6_reporting/`).

## Stage 1 — Firmware Ingestion & Pre-processing

Stage 1 enforces a hard privilege boundary between two components — neither
one both executes code AND reasons over content with an LLM:

- **Extraction Script (Component 1)** — a plain script, no LLM, full sandbox
  execution rights. Runs the ordered procedure: unzip → binwalk (attempt 1)
  → *(if `--tplink` and attempt 1 failed)* tp-link-decrypt → binwalk (attempt
  2) → unsquashfs → `tree.txt`. Writes everything to the firmware's Database
  subfolder (`data/db/<firmware-stem>/`).
- **Identifier Agent (Component 2)** — an LLM agent, zero execution/Database
  access. Reads `tree.txt`'s *text only* (handed to it directly, in the same
  run) and returns a JSON list of binaries worth deeper analysis, each with
  its location in the Database subfolder. This JSON is Stage 1's only output
  that bypasses the Database and goes straight to Stage 2 (Ghidra MCP).

### The `tplink-decrypt` trigger policy

Four rules govern when the TP-Link decrypt step runs:

1. Never runs unless the user explicitly passes `--tplink`.
2. Even when flagged, only runs if binwalk attempt 1 did **not** succeed.
3. When triggered, decrypt runs **before** binwalk is re-run.
4. If attempt 1 succeeds, decrypt is skipped entirely — regardless of the flag.

If nothing succeeds (no flag, or decrypt didn't help), Stage 1 **hard-fails**
with *"squashfs filesystem not found or not supported"* rather than degrading
silently.

## Execution architecture: the Executor abstraction

`fw_audit/executors/` provides a uniform interface so callers never know or
care which backend is answering `executor.run(command, files=workspace)`:

- **`DockerExecutor`** — plain Docker containers for **deterministic
  pipelines**. This is what the Extraction Script uses in production: a
  fixed, known command sequence, isolated with `--network=none`.
- **`SandboxExecutor`** — reserved for **future LLM-controlled execution**
  (an agent writing/running its own code — Stage 4/5 territory). Not
  implemented; Stage 1 never touches it, since the Identifier Agent has zero
  execution rights by design.
- **`LocalExecutor`** — host subprocess, for tests and non-firmware dev only.
  Untrusted firmware is never unpacked by this in the real pipeline — only
  `DockerExecutor` is wired into production (`FWA_EXECUTOR_BACKEND=docker`,
  the default).

## Project Layout

```
fw_audit/
  executors/               # Executor abstraction (see above)
    base.py                # Executor ABC, ExecutionResult
    docker_executor.py     # DockerExecutor — production backend
    local_executor.py      # LocalExecutor — tests/dev only
    sandbox_executor.py    # SandboxExecutor — stub, reserved for later stages
    manager.py             # get_executor() — backend selection
  config/
    settings.py            # Settings (pydantic-settings), get_settings()
    llm_config.py          # AgentRole/ModelTier/ModelProvider, get_llm(_for_agent)
  common/
    schemas.py             # FirmwareMetadata, ELFInfo, IdentifiedBinary, ExtractionArtifact
    constants.py            # TARGET_DAEMONS, ELF magic bytes, etc.
  stage1_ingestion/
    extraction/             # Component 1 — sandbox rights, zero LLM imports
      script.py              # ordered procedure steps, against the Executor interface
      binwalk.py              # outcome parsing: success? / encryption-indicating?
    identifier/              # Component 2 — LLM, zero execution/Database access
      agent.py                # tree_text: str -> list[IdentifiedBinary]
      prompts.py
    tools/
      filesystem_tools.py      # tree.txt (size + ELF-descriptor annotated) + ELF header parser
    state.py                   # FirmwareIngestionState (LangGraph state)
    nodes.py                    # LangGraph node functions
    graph.py                     # StateGraph wiring + trigger-policy routing
    runner.py                     # fw-ingest CLI entry point
  stage2_extraction/ … stage6_reporting/   # Scaffolded, not yet implemented
docker/
  Dockerfile               # The fw-audit-sandbox image DockerExecutor targets
data/
  firmware/                # Drop raw firmware images here (gitignored)
  db/                      # Per-firmware Database subfolders (gitignored)
tests/
  fixtures/                # Real firmware samples for integration testing
```

`fw_audit/` is the single top-level package (rather than bare `config/`,
`common/`, `stage1_ingestion/` at repo root) to avoid Python import-name
collisions with generic module names.

## Setup

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows
# source .venv/bin/activate   # Linux/macOS

pip install -e ".[dev]"       # core + test tooling
pip install -e ".[all,dev]"   # + every LLM provider SDK
# or selectively: pip install -e ".[ollama,dev]"
```

Copy `.env.example` to `.env` and fill in what you need.

### Docker: building the sandbox image

The Extraction Script requires the Docker daemon running and the sandbox
image built:

```bash
docker build -f docker/Dockerfile -t fw-audit-sandbox:latest .
```

This is a three-stage build (tp-link-decrypt, sasquatch, runtime) — see
`docker/Dockerfile`'s comments for the specific upstream build quirks it
works around. **Known limitation:** TP-Link RSA-key extraction
(`tp-link-decrypt`) currently fails to build against TP-Link's presently-served
firmware samples (a firmware-content mismatch upstream, not a defect here);
the image falls back to installing a stub that clearly reports this, and
`--tplink` runs will hard-fail with an honest message until that's revisited.
Everything else in the image (binwalk, squashfs-tools, sasquatch, unzip) is
fully functional independent of this.

### LLM: the Identifier Agent is required

Unlike Stage 1's earlier deterministic-only design, the Identifier Agent is
**mandatory** — there is no heuristic fallback. Configure at least one
provider before running `fw-ingest` for real:

- **Ollama** (local): install it, pull a model, set `OLLAMA_BASE_URL` if not
  default.
- **API key**: set `ANTHROPIC_API_KEY` or `GOOGLE_API_KEY` in `.env`, and
  `pip install -e ".[anthropic]"` (or `.[google]`).

Without one, `fw-ingest` will run extraction successfully but hard-fail at
the identify step with a clear "Identifier Agent unavailable" error.

## Running Stage 1

```bash
fw-ingest path/to/firmware.bin
fw-ingest path/to/firmware.bin --tplink              # explicit TP-Link flag
fw-ingest path/to/firmware.bin --db-subfolder my-run  # override DB folder name
```

Output lands under `data/db/<firmware-stem>/` (or `--db-subfolder` if given):

- `tree.txt` — the annotated rootfs directory listing (size + ELF descriptor
  per entry) — this is what's handed to the Identifier Agent.
- `stage1_summary.json` — machine-readable summary, including the
  `identified_binaries` list Stage 2 consumes.

## Testing

```bash
pytest -m "not integration"   # unit tests; no Docker daemon or LLM needed
pytest -m integration         # end-to-end against a real firmware image
pytest                        # everything (integration tests skip if unset up)
```

The unit suite mocks both the Docker and LLM boundaries via a fake `Executor`
(`tests/conftest.py::FakeExecutor`) and a monkeypatched Identifier Agent, so
it stays green without a daemon running or any provider configured.

To run the integration test against a real image, either drop it under
`tests/fixtures/` or point `FWA_TEST_FIRMWARE` at it — it additionally
requires the Docker image built and an LLM provider configured:

```bash
FWA_TEST_FIRMWARE=/path/to/real-firmware.bin pytest -m integration -v -s
```

## LLM Provider Configuration

Agents request an `AgentRole` (e.g. `STAGE1_BINARY_IDENTIFIER`), which
resolves to a `ModelTier` (`FAST_LOCAL` / `BALANCED` / `HIGH_REASONING`),
which resolves to a concrete `ModelSpec` (provider + model). See
`fw_audit/config/llm_config.py` for the routing tables.

| Role | Tier | Default provider/model |
|---|---|---|
| `STAGE1_BINARY_IDENTIFIER` | `HIGH_REASONING` | Anthropic `claude-sonnet-4-5` |
| `DEFAULT` | `BALANCED` | Ollama `kimi-k3` |

The Identifier Agent is one call per firmware, so `HIGH_REASONING`'s cost is
negligible relative to the quality it buys — Stage 2's hand-off depends on it.

Provider SDKs are imported lazily — installing only `langchain-ollama` (for
example) is enough to use local models without the other extras.
