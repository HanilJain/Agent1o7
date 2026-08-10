"""Integration tests for the Stage 1 LangGraph workflow.

Three tiers:
* Fake-executor + fake-identifier tests — always run; no live Docker daemon
  or LLM required. Validate the full node sequence wires together and that
  the hard-fail paths (Docker unavailable, Identifier unavailable) work.
* `test_graph_runs_on_real_firmware` — marked `integration`; skipped unless
  a real firmware image is available via `FWA_TEST_FIRMWARE` or
  `tests/fixtures/`. Requires BOTH a running Docker daemon with the
  fw-audit-sandbox image built AND a configured LLM provider — this is the
  one test this suite cannot make pass on its own.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fw_audit.common.schemas import IdentifiedBinary
from fw_audit.stage1_ingestion.extraction.script import BINWALK_1_DIR
from fw_audit.stage1_ingestion.graph import get_graph
from fw_audit.stage1_ingestion.state import IngestionStatus, initial_state


def _init_state(work_dir: Path, *, is_tplink: bool = False) -> dict:
    firmware_path = work_dir.parent / "raw_input.bin"
    firmware_path.write_bytes(b"dummy firmware")
    return initial_state(
        run_id="graphtest",
        firmware_path=str(firmware_path),
        db_subfolder=str(work_dir),
        is_tplink=is_tplink,
    )


def _patch_executor(monkeypatch, executor):
    monkeypatch.setattr("fw_audit.stage1_ingestion.nodes.get_executor", lambda: executor)


def _patch_identifier(monkeypatch, fn):
    monkeypatch.setattr("fw_audit.stage1_ingestion.nodes._identify", fn)


async def test_graph_completes_full_happy_path(monkeypatch, work_dir, fake_executor):
    """binwalk attempt 1 succeeds -> tree.txt -> Identifier Agent -> COMPLETED."""

    def on_run(command, files):
        if BINWALK_1_DIR in command:
            (files / BINWALK_1_DIR / "bin").mkdir(parents=True, exist_ok=True)
            (files / BINWALK_1_DIR / "bin" / "httpd").write_bytes(b"\x7fELF")
        return None

    executor = fake_executor(on_run)
    _patch_executor(monkeypatch, executor)

    async def fake_identify(tree_text: str):
        assert "httpd" in tree_text  # the real tree.txt content was handed over
        return [IdentifiedBinary(path="bin/httpd")]

    _patch_identifier(monkeypatch, fake_identify)

    state = _init_state(work_dir)
    result = await get_graph().ainvoke(state)

    assert result["status"] == IngestionStatus.COMPLETED
    assert result["errors"] == []
    assert result["tree_txt_path"] is not None
    assert Path(result["tree_txt_path"]).is_file()
    assert result["identified_binaries"] == [
        IdentifiedBinary(path="bin/httpd")
    ]


async def test_rootfs_dir_is_published(monkeypatch, work_dir, fake_executor):
    """Stage 2 resolves every IdentifiedBinary.path relative to rootfs_dir and
    cannot reconstruct it by convention (see generate_tree's four-way search)
    — it must come back in the state dict, not just live inside tree.txt."""

    def on_run(command, files):
        if BINWALK_1_DIR in command:
            (files / BINWALK_1_DIR / "bin").mkdir(parents=True, exist_ok=True)
            (files / BINWALK_1_DIR / "bin" / "httpd").write_bytes(b"\x7fELF")
        return None

    executor = fake_executor(on_run)
    _patch_executor(monkeypatch, executor)

    async def fake_identify(tree_text: str):
        return []

    _patch_identifier(monkeypatch, fake_identify)

    state = _init_state(work_dir)
    result = await get_graph().ainvoke(state)

    assert result["status"] == IngestionStatus.COMPLETED
    assert result["rootfs_dir"] is not None
    assert Path(result["rootfs_dir"]).is_dir()
    # tree.txt's first line is str(rootfs_dir) (filesystem_tools.write_tree_txt) —
    # the two must agree, since Stage 2's fallback path parses that line.
    tree_first_line = Path(result["tree_txt_path"]).read_text(encoding="utf-8").splitlines()[0]
    assert tree_first_line == result["rootfs_dir"]


async def test_graph_fails_gracefully_on_missing_firmware(work_dir: Path):
    # initialize() checks firmware existence before ever calling get_executor(),
    # so this needs no executor/identifier patching.
    state = initial_state(
        run_id="missingtest",
        firmware_path=str(work_dir / "does_not_exist.bin"),
        db_subfolder=str(work_dir / "db"),
    )
    result = await get_graph().ainvoke(state)

    assert result["status"] == IngestionStatus.FAILED
    assert len(result["errors"]) > 0
    assert result["identified_binaries"] == []


async def test_graph_fails_when_executor_unavailable(monkeypatch, work_dir, fake_executor):
    executor = fake_executor()
    executor.available = lambda: False
    _patch_executor(monkeypatch, executor)

    state = _init_state(work_dir)
    result = await get_graph().ainvoke(state)

    assert result["status"] == IngestionStatus.FAILED
    assert any("unavailable" in e.lower() for e in result["errors"])


async def test_graph_hard_fails_when_identifier_unavailable(monkeypatch, work_dir, fake_executor):
    """Decision 2: the Identifier Agent is required — no LLM reachable is a hard failure."""
    from fw_audit.stage1_ingestion.identifier.agent import IdentifierUnavailableError

    def on_run(command, files):
        if BINWALK_1_DIR in command:
            (files / BINWALK_1_DIR / "bin").mkdir(parents=True, exist_ok=True)
            (files / BINWALK_1_DIR / "bin" / "httpd").write_bytes(b"\x7fELF")
        return None

    executor = fake_executor(on_run)
    _patch_executor(monkeypatch, executor)

    async def failing_identify(tree_text: str):
        raise IdentifierUnavailableError("no LLM provider configured")

    _patch_identifier(monkeypatch, failing_identify)

    state = _init_state(work_dir)
    result = await get_graph().ainvoke(state)

    assert result["status"] == IngestionStatus.FAILED
    assert any("Identifier Agent unavailable" in e for e in result["errors"])
    # The extraction side still succeeded — tree.txt exists even though the
    # overall run is a hard failure. Only the identify step failed.
    assert result["tree_txt_path"] is not None


@pytest.mark.integration
async def test_graph_runs_on_real_firmware(real_firmware_path: Path | None, work_dir: Path):
    if real_firmware_path is None:
        pytest.skip(
            "No real firmware image found. Set FWA_TEST_FIRMWARE or place an "
            "image under tests/fixtures/ to run this test. Also requires a "
            "running Docker daemon with the fw-audit-sandbox image built, "
            "and a configured LLM provider (Ollama or an API key)."
        )

    state = initial_state(
        run_id="realfw", firmware_path=str(real_firmware_path), db_subfolder=str(work_dir)
    )
    result = await get_graph().ainvoke(state)

    assert result["status"] in (IngestionStatus.COMPLETED, IngestionStatus.FAILED)
    if result["status"] == IngestionStatus.COMPLETED:
        assert result["tree_txt_path"] is not None
        assert Path(result["tree_txt_path"]).is_file()
        print(f"\nIdentified binaries ({len(result['identified_binaries'])}):")
        for b in result["identified_binaries"][:10]:
            print(f"  {b.path}")
