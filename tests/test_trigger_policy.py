"""The four-rule tplink-decrypt trigger policy, exercised end-to-end through
the compiled graph with a fake Executor and a fake Identifier Agent — no
live Docker daemon or LLM required.

Rules (from the Stage 1 policy doc):
    1. tplink_decrypt never runs unless --tplink was passed.
    2. Even when flagged, it only runs if binwalk attempt 1 did not succeed.
    3. When triggered, decrypt runs BEFORE binwalk is re-run.
    4. If binwalk attempt 1 succeeds, tplink_decrypt is skipped entirely,
       regardless of the flag.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fw_audit.stage1_ingestion.extraction.script import BINWALK_1_DIR, BINWALK_2_DIR
from fw_audit.stage1_ingestion.graph import get_graph
from fw_audit.stage1_ingestion.state import IngestionStatus, initial_state


def _make_binwalk_success_fs(workspace: Path, out_dir_name: str) -> None:
    """Simulate a successful binwalk extraction: an unpacked rootfs with bin/."""
    (workspace / out_dir_name / "bin").mkdir(parents=True, exist_ok=True)
    (workspace / out_dir_name / "bin" / "sh").write_bytes(b"\x7fELF")


@pytest.fixture(autouse=True)
def _patch_identifier(monkeypatch):
    """Every trigger-policy test only cares about the extraction routing;
    stub the Identifier Agent so runs that reach it still complete."""

    async def fake_identify(tree_text: str):
        return []

    monkeypatch.setattr("fw_audit.stage1_ingestion.nodes._identify", fake_identify)


def _patch_executor(monkeypatch, executor):
    monkeypatch.setattr("fw_audit.stage1_ingestion.nodes.get_executor", lambda: executor)


def _init_state(work_dir: Path, *, is_tplink: bool) -> dict:
    # Mirrors production layout: the raw firmware lives OUTSIDE the Database
    # subfolder (db_subfolder=work_dir), not inside it — stage_firmware()
    # copies it in as its first step.
    firmware_path = work_dir.parent / "raw_input.bin"
    firmware_path.write_bytes(b"dummy firmware")
    return initial_state(
        run_id="policytest",
        firmware_path=str(firmware_path),
        db_subfolder=str(work_dir),
        is_tplink=is_tplink,
    )


async def test_rule1_no_flag_binwalk_fails_never_decrypts(monkeypatch, work_dir, fake_executor):
    """Rule 1: no --tplink -> tplink_decrypt must never run, even on failure."""

    def on_run(command, files):
        return None  # every command "succeeds" at the process level, but produces no rootfs

    executor = fake_executor(on_run)
    _patch_executor(monkeypatch, executor)

    state = _init_state(work_dir, is_tplink=False)
    result = await get_graph().ainvoke(state)

    assert result["status"] == IngestionStatus.FAILED
    assert not any("tp-link-decrypt" in cmd for cmd, _ in executor.calls)
    assert "squashfs filesystem not found or not supported" in result["errors"][0]


async def test_rule2_flagged_and_attempt1_fails_triggers_decrypt(monkeypatch, work_dir, fake_executor):
    """Rule 2: flagged AND attempt 1 failed -> decrypt runs; attempt 2 then succeeds."""

    def on_run(command, files):
        if "tp-link-decrypt" in command:
            (files / "decrypted").mkdir(exist_ok=True)
            (files / "decrypted" / "input.bin").write_bytes(b"decrypted")
        elif BINWALK_2_DIR in command:
            _make_binwalk_success_fs(files, BINWALK_2_DIR)
        # attempt 1 (BINWALK_1_DIR): no fs created -> binwalk_succeeded() is False
        return None

    executor = fake_executor(on_run)
    _patch_executor(monkeypatch, executor)

    state = _init_state(work_dir, is_tplink=True)
    result = await get_graph().ainvoke(state)

    assert result["status"] == IngestionStatus.COMPLETED
    assert any("tp-link-decrypt" in cmd for cmd, _ in executor.calls)


async def test_rule2_not_flagged_attempt1_fails_never_decrypts(monkeypatch, work_dir, fake_executor):
    """Rule 2's converse restated: unflagged failure still never decrypts (same as rule 1)."""
    executor = fake_executor(lambda command, files: None)
    _patch_executor(monkeypatch, executor)

    state = _init_state(work_dir, is_tplink=False)
    result = await get_graph().ainvoke(state)

    assert result["status"] == IngestionStatus.FAILED
    assert not any("tp-link-decrypt" in cmd for cmd, _ in executor.calls)


async def test_rule3_decrypt_runs_before_binwalk_attempt2(monkeypatch, work_dir, fake_executor):
    """Rule 3: decrypt, THEN re-run binwalk — not the reverse."""

    def on_run(command, files):
        if BINWALK_2_DIR in command:
            _make_binwalk_success_fs(files, BINWALK_2_DIR)
        return None

    executor = fake_executor(on_run)
    _patch_executor(monkeypatch, executor)

    state = _init_state(work_dir, is_tplink=True)
    await get_graph().ainvoke(state)

    decrypt_index = next(i for i, (cmd, _) in enumerate(executor.calls) if "tp-link-decrypt" in cmd)
    binwalk2_index = next(
        i for i, (cmd, _) in enumerate(executor.calls) if BINWALK_2_DIR in cmd
    )
    assert decrypt_index < binwalk2_index


async def test_rule4_attempt1_succeeds_skips_decrypt_even_when_flagged(
    monkeypatch, work_dir, fake_executor
):
    """Rule 4: binwalk attempt 1 succeeding skips decrypt REGARDLESS of the flag."""

    def on_run(command, files):
        if BINWALK_1_DIR in command:
            _make_binwalk_success_fs(files, BINWALK_1_DIR)
        return None

    executor = fake_executor(on_run)
    _patch_executor(monkeypatch, executor)

    state = _init_state(work_dir, is_tplink=True)  # flagged, but attempt 1 succeeds
    result = await get_graph().ainvoke(state)

    assert result["status"] == IngestionStatus.COMPLETED
    assert not any("tp-link-decrypt" in cmd for cmd, _ in executor.calls)


async def test_decrypt_then_second_failure_hard_fails(monkeypatch, work_dir, fake_executor):
    """Flagged, attempt 1 fails, decrypt runs, but attempt 2 ALSO fails -> hard fail."""
    executor = fake_executor(lambda command, files: None)  # nothing ever produces a rootfs
    _patch_executor(monkeypatch, executor)

    state = _init_state(work_dir, is_tplink=True)
    result = await get_graph().ainvoke(state)

    assert result["status"] == IngestionStatus.FAILED
    assert any("tp-link-decrypt" in cmd for cmd, _ in executor.calls)
    assert "squashfs filesystem not found or not supported" in result["errors"][0]
