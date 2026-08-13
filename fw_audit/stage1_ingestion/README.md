# Stage 1 — Firmware Ingestion & Pre-processing

Unpacks a raw firmware image and identifies which binaries are worth deeper
analysis, using a hard privilege split so no single component both executes
untrusted code and reasons over its content with an LLM.

## What it does

- **Extraction Script** (`extraction/`, Component 1) — plain script, no LLM,
  full sandbox rights. Runs: unzip → binwalk (attempt 1) → *(if `--tplink`
  and attempt 1 failed)* tp-link-decrypt → binwalk (attempt 2) → unsquashfs
  → `tree.txt`. Everything lands in `data/db/<firmware-stem>/`.
- **Identifier Agent** (`identifier/`, Component 2) — LLM agent, zero
  execution/filesystem access. Reads `tree.txt` text only and returns a JSON
  list of `IdentifiedBinary` (just a `path`) worth deeper analysis. This is
  Stage 1's only output that bypasses the Database and goes straight to
  Stage 2 — which re-verifies the path itself, since it's untrusted LLM
  output.

## Files

| File | Contains |
|---|---|
| `extraction/script.py` | The ordered extraction procedure against the `Executor` interface. |
| `extraction/binwalk.py` | Binwalk output parsing (success / encryption indicators). |
| `identifier/agent.py` | The LLM call: `tree_text -> list[IdentifiedBinary]`. |
| `identifier/prompts.py` | Identifier Agent prompts. |
| `tools/filesystem_tools.py` | `tree.txt` generation + ELF header parsing. |
| `state.py`, `nodes.py`, `graph.py` | LangGraph state, nodes, and wiring (incl. the tplink trigger policy). |
| `runner.py` | `fw-ingest` CLI entry point. |

## How to run

```bash
fw-ingest path/to/firmware.bin
fw-ingest path/to/firmware.bin --tplink               # explicit TP-Link flag
fw-ingest path/to/firmware.bin --db-subfolder my-run   # override DB folder name
```

## Input

A raw firmware image file (zip/squashfs-bearing binary blob, TP-Link
encrypted or not).

## Output

`data/db/<firmware-stem>/`:

- `tree.txt` — annotated (size + ELF descriptor) rootfs directory listing.
- `stage1_summary.json` — `identified_binaries`, `rootfs_dir`, `status`,
  `warnings`, `errors` — the machine-readable hand-off Stage 2 consumes.

## The tplink trigger policy

1. Never runs unless `--tplink` is passed.
2. Only runs if binwalk attempt 1 failed.
3. Runs before binwalk is re-run.
4. Skipped entirely if attempt 1 succeeded.

If nothing succeeds, Stage 1 hard-fails rather than degrading silently.

## Debugging

- Needs the Docker daemon and the sandbox image:
  `docker build -f docker/Dockerfile -t fw-audit-sandbox:latest .`
- Needs an LLM provider configured (`ANTHROPIC_API_KEY`, or local Ollama) —
  otherwise fails at the identify step with a clear message.
- **Known limitation:** `tp-link-decrypt` currently fails to build against
  presently-served TP-Link firmware (upstream content mismatch); `--tplink`
  runs hard-fail with an honest error until revisited. Everything else in
  the sandbox image (binwalk, squashfs-tools, sasquatch, unzip) works
  independently of this.

## Testing

```bash
pytest -m "not integration" tests/test_trigger_policy.py tests/test_graph_integration.py \
  tests/test_identifier_agent.py tests/test_extraction_tools.py tests/test_filesystem_tools.py
FWA_TEST_FIRMWARE=/path/to/real.bin pytest -m integration -v -s tests/test_graph_integration.py
```

The unit suite mocks Docker (`FakeExecutor`) and monkeypatches the
Identifier Agent, so it's green with no daemon or LLM configured.

See the [project CLAUDE.md](../../CLAUDE.md) and
[project README.md](../../README.md) for cross-cutting setup (Executor
backends, LLM provider config, Settings).
