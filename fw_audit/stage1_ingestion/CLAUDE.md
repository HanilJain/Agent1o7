# CLAUDE.md — Stage 1: Ingestion & Pre-processing

Read this file first for Stage 1 work — it's kept current here, not in the
root `CLAUDE.md`. Root `CLAUDE.md` covers only cross-cutting concerns
(Executor backends, LLM routing, Settings).

## Hard constraint — never violate

Two components, **neither both executes code AND reasons with an LLM**:

- **Extraction Script** (`extraction/`) — plain script, no LLM, full sandbox
  rights.
- **Identifier Agent** (`identifier/`) — LLM agent, zero execution/filesystem
  access; reads `tree.txt` text only.

Never give the Identifier Agent execution/filesystem access. Never make the
Extraction Script call an LLM. `IdentifiedBinary.path` it returns is
**untrusted, unvalidated LLM output** — Stage 2 re-verifies it.

## Files

| File | Purpose |
|---|---|
| `extraction/script.py` | Ordered procedure: unzip → binwalk#1 → [tplink] → binwalk#2 → unsquashfs → `tree.txt`, driven through the `Executor` interface. |
| `extraction/binwalk.py` | Parses binwalk output: succeeded? encryption-indicating? |
| `identifier/agent.py` | `tree_text: str -> list[IdentifiedBinary]`. |
| `identifier/prompts.py` | Identifier Agent prompt templates. |
| `tools/filesystem_tools.py` | Builds annotated `tree.txt` (size + ELF descriptor per entry) + ELF header parser. |
| `state.py` | `FirmwareIngestionState` (LangGraph state). |
| `nodes.py` | LangGraph node functions. |
| `graph.py` | `StateGraph` wiring + the tplink trigger-policy conditional edges (`_after_binwalk_1`/`_after_binwalk_2`) — encode the 4 rules below so they can't be silently violated by editing one node. |
| `runner.py` | `fw-ingest` CLI entry point. |

## The `--tplink` trigger policy (4 rules, in `graph.py`)

1. Never runs unless `--tplink` is passed.
2. Even when flagged, only runs if binwalk#1 failed.
3. Decrypt runs **before** binwalk is re-run.
4. If binwalk#1 succeeds, decrypt is skipped regardless of the flag.

If nothing succeeds, Stage 1 hard-fails via `fail_unsupported` rather than
degrading silently.

## Invoke

```bash
fw-ingest path/to/firmware.bin
fw-ingest path/to/firmware.bin --tplink
fw-ingest path/to/firmware.bin --db-subfolder my-run
fw-ingest path/to/firmware.bin --run-id ID
```

## Input

Raw firmware image file path (any format binwalk/tp-link-decrypt can unpack).

## Output — `data/db/<firmware-stem>/`

- `tree.txt` — annotated rootfs listing, handed to the Identifier Agent.
- `stage1_summary.json` — `identified_binaries`, `rootfs_dir`, `status`,
  `warnings`, `errors`. This is Stage 2's actual input, not the Database.

## Debugging

- Requires Docker daemon + `docker build -f docker/Dockerfile -t fw-audit-sandbox:latest .`
- Requires an LLM provider (`ANTHROPIC_API_KEY`, or Ollama) — missing one
  fails cleanly: *"Identifier Agent unavailable"*.
- `"squashfs filesystem not found or not supported"` → both binwalk attempts
  (and decrypt, if `--tplink`) failed. Try `--tplink` for TP-Link images.
- `--tplink` currently hard-fails — `tp-link-decrypt` doesn't build against
  presently-served TP-Link samples (known upstream issue).
- Unit: `pytest -m "not integration" tests/test_trigger_policy.py tests/test_graph_integration.py tests/test_identifier_agent.py tests/test_extraction_tools.py tests/test_filesystem_tools.py`
- Integration: `FWA_TEST_FIRMWARE=/path/to/real.bin pytest -m integration -v -s tests/test_graph_integration.py`
- Unit suite mocks Docker (`FakeExecutor`) and monkeypatches the Identifier
  Agent — no daemon or provider needed.

## Adding a feature here

Extend `graph.py`'s conditional edges for new trigger policies, not ad-hoc
`if`s in nodes. Never let an Identifier Agent capability add
execution/filesystem access. See root `CLAUDE.md` for the Executor
abstraction and `AgentRole.STAGE1_BINARY_IDENTIFIER` routing.
