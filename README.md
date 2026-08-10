# fw-audit — Agentic Firmware Vulnerability Detection System

A six-stage agentic pipeline for automated router-firmware vulnerability
auditing: ingestion → feature extraction → RAG fusion → agentic analysis →
sandboxed verification → reporting. Built on **LangGraph** (stateful agent
orchestration), **LangChain** (unified LLM abstraction), **MCP** (tool
integration for later stages), and **Docker** (sandboxed extraction).

**Current status:** Stage 1 (Firmware Ingestion & Pre-processing) and
Stage 2 (Feature Extraction) are implemented. Stages 3–6 are scaffolded as
empty sub-packages (`fw_audit/stage3_rag/` … `fw_audit/stage6_reporting/`).

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
  that bypasses the Database and goes straight to Stage 2 — see below.

### The `tplink-decrypt` trigger policy

Four rules govern when the TP-Link decrypt step runs:

1. Never runs unless the user explicitly passes `--tplink`.
2. Even when flagged, only runs if binwalk attempt 1 did **not** succeed.
3. When triggered, decrypt runs **before** binwalk is re-run.
4. If attempt 1 succeeds, decrypt is skipped entirely — regardless of the flag.

If nothing succeeds (no flag, or decrypt didn't help), Stage 1 **hard-fails**
with *"squashfs filesystem not found or not supported"* rather than degrading
silently.

## Stage 2 — Feature Extraction

Turns Stage 1's shortlist into decompiled, normalized artifacts. Fully
deterministic — no LLM anywhere in it — so it runs as a plain async pipeline
(`stage2_extraction/extract.py`), not a LangGraph like every other stage:

```
load stage1_summary.json + resolve rootfs
  -> resolve each IdentifiedBinary.path to verified bytes (never raises;
     unresolvable paths are recorded, not fatal)
  -> decompile each resolved binary with Ghidra Headless
     (bounded concurrency; one binary's failure never sinks the run)
  -> normalize the decompiled C into two targets: Joern (whole-program,
     CPG-compilable) and LLM (per-function, RAG-chunk-sized)
  -> write stage2/stage2_summary.json
```

**The path-resolution problem:** `IdentifiedBinary.path` is untrusted,
unvalidated LLM output — it may carry a leading `/`, be hallucinated,
contain `..`, or point at a busybox-style symlink. `stage2_extraction/resolve.py`
normalizes it, walks symlinks *re-rooted inside the firmware's rootfs*
(never resolved onto the host), falls back to a basename rescan for a
hallucinated directory, and dedupes by content hash so N shortlisted paths
that are byte-identical (e.g. busybox applets) decompile once, not N times.

**The C-normalization problem:** Ghidra's decompiled C is not valid,
portable C — non-standard types (`undefined4`, `uint`, `code`), intrinsic
macros (`CONCAT44`, `SUB84`, `ZEXT48`), illegal `::` in switch-case labels,
and undeclared register variables (`in_FS_OFFSET`, `unaff_EBX`,
`extraout_EAX`) don't parse in a CPG builder like Joern and are noisy for
an LLM. `stage2_extraction/normalize/` fixes this with a generated prelude
header (every non-standard type becomes a `typedef`, every intrinsic
becomes a `#define` — zero rewriting risk) plus a small set of pure,
span-aware text passes for what a declaration can't express. See
`normalize/__init__.py`'s docstring for the full design rationale.

### Two Docker images

Stage 2 uses a **separate** image from Stage 1's extraction sandbox
(`docker/Dockerfile.ghidra`, not `docker/Dockerfile`) — Stage 1 starts its
container 6+ times per firmware, so bundling ~2GB of JDK+Ghidra into that
image would tax every one of those starts for no benefit, and Stage 1's own
image has a flaky, network-heavy build stage (see "Known limitation" below)
that Stage 2 must not inherit.

```bash
docker build -f docker/Dockerfile.ghidra -t fw-audit-ghidra:latest .
```

> **Verified:** this image builds successfully and
> `tests/test_stage2_integration.py::test_decompiles_a_real_elf` passes
> against real Ghidra 12.1.2 (decompiles `/bin/ls`, 386 functions found).
> The base image is `eclipse-temurin:21-jdk-jammy`, not
> `debian:bookworm-slim` — OpenJDK 21 turned out not to be installable via
> apt on Debian bookworm at all (checked against a real build, not just
> docs: absent from both the regular archive and `bookworm-backports`).
> Every headless invocation goes through `pyghidraRun -H`, never bare
> `analyzeHeadless` — the latter fails a `.py` `-postScript` outright,
> since PyGhidra needs the JVM started *by* Python (via JPype), not the
> reverse. See `docker/Dockerfile.ghidra`'s comments for the full story.

### Running Stage 2

```bash
fw-extract data/db/<firmware-stem>/stage1_summary.json
fw-extract data/db/<firmware-stem>/stage1_summary.json --dry-run         # resolve only, no Ghidra
fw-extract data/db/<firmware-stem>/stage1_summary.json --only bin/httpd  # repeatable
```

Output lands under `data/db/<firmware-stem>/stage2/`:

- `resolution_report.json` — what every `IdentifiedBinary.path` resolved to (or why it didn't).
- `ghidra_types.h` — the generated prelude header (shared by every binary's normalized LLM output).
- `binaries/<bin_id>/raw/` — Ghidra's untouched output (decompiled C, disassembly, `metadata.json`).
- `binaries/<bin_id>/normalized/joern/whole.c` and `normalized/llm/functions/*.c` — sanitized output.
- `stage2_summary.json` — the machine-readable hand-off to Stage 3/4, with every path relative to `db_subfolder`.

Additionally, a flat **decompiled-C mirror tree** is written as a *sibling*
of the run dir — `data/db/<firmware-stem>_decompiled/` — recreating the
firmware's own rootfs layout with `.c` appended to each binary's filename
(never replacing an existing extension: `lib/libfoo.so` → `lib/libfoo.so.c`).
Content is identical to that binary's `normalized/joern/whole.c`; this is a
human-oriented alternate view for browsing, not a replacement for `stage2/`.
It lives outside `db_subfolder` (see `Stage2Summary.decompiled_tree_dir`'s
docstring for the one path-relativity exception this causes), so it is *not*
covered by the "everything relocates with `db_subfolder`" guarantee below.

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
  stage2_extraction/
    stage1_io.py             # load stage1_summary.json + resolve rootfs_dir
    resolve.py                # untrusted IdentifiedBinary.path -> verified host bytes
    layout.py                  # pure path algebra for stage2/'s output tree
    extract.py                   # run_extraction() orchestrator
    runner.py                     # fw-extract CLI entry point
    ghidra/
      command.py                  # pure pyghidraRun -H command composition
      client.py                    # runs it via Executor, parses metadata.json
    normalize/
      prelude.py                   # generates ghidra_types.h
      spans.py                      # CODE|STRING|CHAR|COMMENT tokenizer
      passes.py                      # individual (str) -> str normalization passes
      pipeline.py                     # JOERN_PIPELINE / LLM_PIPELINE / normalize()
      report.py                        # PassStat / NormalizationResult
  stage3_rag/ … stage6_reporting/   # Scaffolded, not yet implemented
docker/
  Dockerfile               # The fw-audit-sandbox image (Stage 1) DockerExecutor targets
  Dockerfile.ghidra        # The fw-audit-ghidra image (Stage 2) — separate, see above
  ghidra_scripts/
    fw_audit_export.py     # the PyGhidra headless export script
    smoke_test.py           # build-time smoke test for Dockerfile.ghidra
data/
  firmware/                # Drop raw firmware images here (gitignored)
  db/                      # Per-firmware Database subfolders (gitignored)
tests/
  fixtures/                # Real firmware samples for integration testing
  fixtures/ghidra/         # Synthetic Ghidra-style C fixtures for the normalizer
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

### Docker: building the Ghidra image (Stage 2)

Stage 2's `pyghidraRun -H` invocations require a **separate** image —
see "Two Docker images" above for why:

```bash
docker build -f docker/Dockerfile.ghidra -t fw-audit-ghidra:latest .
```

~10 minutes, ~2.2 GB. Requires network at build time (apt, the Ghidra
release zip from GitHub, PyGhidra/JPype from Ghidra's own bundled wheels);
runtime is `--network=none` like Stage 1's image. Verified working end to
end — see `docker/Dockerfile.ghidra`'s comments if you bump `GHIDRA_VERSION`
(re-verify `GHIDRA_SHA256` against the new release asset the same way it
was computed originally: download it and `sha256sum` it yourself).

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
pytest -m integration         # end-to-end against a real firmware image / Ghidra image
pytest                        # everything (integration tests skip if unset up)
```

The unit suite mocks both the Docker and LLM boundaries via a fake `Executor`
(`tests/conftest.py::FakeExecutor`) and a monkeypatched Identifier Agent, so
it stays green without a daemon running or any provider configured. Stage 2's
unit suite uses the same `FakeExecutor` idiom and needs no LLM at all.

To run the Stage 1 integration test against a real image, either drop it
under `tests/fixtures/` or point `FWA_TEST_FIRMWARE` at it — it additionally
requires the Stage 1 Docker image built and an LLM provider configured:

```bash
FWA_TEST_FIRMWARE=/path/to/real-firmware.bin pytest -m integration -v -s
```

Stage 2's integration tests need only the `fw-audit-ghidra:latest` image —
`test_decompiles_a_real_elf` decompiles `/bin/ls` copied out of the image
itself, so no firmware fixture is required for it. `test_stage2_on_real_firmware`
additionally expects a prior `fw-ingest <firmware>` run (its
`stage1_summary.json` is what it consumes).

## LLM Provider Configuration

Agents request an `AgentRole` (e.g. `STAGE1_BINARY_IDENTIFIER`), which
resolves to a `ModelTier` (`FAST_LOCAL` / `BALANCED` / `HIGH_REASONING`),
which resolves to a concrete `ModelSpec` (provider + model). See
`fw_audit/config/llm_config.py` for the routing tables.

| Role | Tier | Current provider/model |
|---|---|---|
| `STAGE1_BINARY_IDENTIFIER` | `FAST_LOCAL` | Ollama `qwen2.5-coder:1.5b` |
| `DEFAULT` | `BALANCED` | Ollama `kimi-k3` |

`STAGE1_BINARY_IDENTIFIER` is routed to `FAST_LOCAL` (local, offline) by
default because this dev setup has no cloud API key configured — see the
`ROLE_TO_TIER` comment in `fw_audit/config/llm_config.py`. It's one call per
firmware, so once `ANTHROPIC_API_KEY` (or `GOOGLE_API_KEY`) is set, flipping
that entry to `HIGH_REASONING` (Claude) is worth the negligible extra cost
for better accuracy — Stage 2's hand-off depends on this agent's output.
`FAST_LOCAL` forces Ollama's `format="json"` decoding mode, which was
necessary to get reliable structured output out of a 1.5B model.

Requires Ollama running locally with the model pulled:
`ollama pull qwen2.5-coder:1.5b`.

Provider SDKs are imported lazily — installing only `langchain-ollama` (for
example) is enough to use local models without the other extras.
