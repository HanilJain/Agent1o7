"""Shared pytest fixtures for the fw_audit test suite."""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path
from typing import Callable

import pytest

from fw_audit.executors.base import ExecutionResult, Executor
from fw_audit.stage2_extraction.clean.extract import (
    extract_functions,
    respan_for_concatenated_text,
)
from fw_audit.stage2_extraction.clean.index import to_index_json_dict

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def work_dir(tmp_path: Path) -> Path:
    """A scratch working directory for a single test."""
    d = tmp_path / "work"
    d.mkdir()
    return d


@pytest.fixture
def synthetic_elf_bytes() -> bytes:
    """A minimal, well-formed ELF32 LE MIPS header (no sections/segments).

    Just enough for `is_elf`/`parse_elf_header` to succeed without needing a
    real compiled binary or external toolchain.
    """
    e_ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    rest = struct.pack("<HHIIIIIHHHHHH", 2, 8, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0)
    return e_ident + rest + b"\x00" * 16


class FakeExecutor(Executor):
    """An `Executor` whose behaviour a test fully controls.

    `on_run(command, files) -> ExecutionResult | None` is called for every
    `run()`; return `None` to fall through to the default (`ok=True`, empty
    output). Every call is recorded in `.calls` for assertions. Tests that
    need `binwalk_succeeded()`-style filesystem checks to pass should have
    their `on_run` callback write the expected files under `files` — this
    fake does no I/O on its own.
    """

    def __init__(
        self, on_run: Callable[[str, Path | None], ExecutionResult | None] | None = None
    ) -> None:
        self.calls: list[tuple[str, Path | None]] = []
        self._on_run = on_run

    def available(self) -> bool:
        return True

    async def run(
        self, command: str, *, files: Path | None = None, timeout: int | None = None
    ) -> ExecutionResult:
        self.calls.append((command, files))
        if self._on_run is not None:
            result = self._on_run(command, files)
            if result is not None:
                return result
        return ExecutionResult(command=command, returncode=0, stdout="", stderr="", timed_out=False)


@pytest.fixture
def fake_executor() -> type[FakeExecutor]:
    """The `FakeExecutor` class itself, so tests can instantiate with their own `on_run`."""
    return FakeExecutor


def write_cleaned_artifact(stage2_dir: Path, bin_id: str, source_text: str) -> dict[str, str]:
    """Write a real `cleaned/whole.c` + `cleaned/functions.json` for
    `bin_id` under `stage2_dir/binaries/<bin_id>/cleaned/`, using the
    actual production extraction code (`stage2_extraction.clean`) rather
    than hand-rolling a fixture shape that could drift from what Stage 2
    really produces.

    Skips tree-sitter's `_repair` no longer applies here (moved upstream
    into `normalize.pipeline.build_clean_pipeline`, run before
    `extract_functions` in real Stage 2 code) — test fixtures pass already-
    clean C, so calling `extract_functions` directly on `source_text` is
    equivalent for these purposes.

    Returns the `{"cleaned_c": ..., "cleaned_index_json": ...}` fragment,
    paths relative to `stage2_dir`'s parent (`db_subfolder`) — the exact
    shape a `DecompilationArtifacts`/binary fixture's `artifacts` dict
    needs, mirroring `decompiled_tree_c`'s convention in these same
    fixtures.
    """
    source = extract_functions(source_text, bin_id=bin_id)
    respanned = respan_for_concatenated_text(source.functions)
    source = source.model_copy(update={"functions": respanned})

    cleaned_dir = stage2_dir / "binaries" / bin_id / "cleaned"
    cleaned_dir.mkdir(parents=True, exist_ok=True)
    (cleaned_dir / "whole.c").write_text(source.to_text(), encoding="utf-8")
    (cleaned_dir / "functions.json").write_text(
        json.dumps(to_index_json_dict(source), indent=2), encoding="utf-8"
    )
    return {
        "cleaned_c": f"stage2/binaries/{bin_id}/cleaned/whole.c",
        "cleaned_index_json": f"stage2/binaries/{bin_id}/cleaned/functions.json",
    }


@pytest.fixture
def real_firmware_path() -> Path | None:
    """Locate a user-supplied real firmware image for integration testing.

    Resolution order:
    1. `FWA_TEST_FIRMWARE` env var, if set and the path exists.
    2. The first file under `tests/fixtures/` that isn't `.gitkeep`/hidden.

    Returns None (causing dependent tests to skip) if nothing is found.
    """
    env_path = os.environ.get("FWA_TEST_FIRMWARE")
    if env_path and Path(env_path).is_file():
        return Path(env_path)

    if FIXTURES_DIR.is_dir():
        for candidate in sorted(FIXTURES_DIR.iterdir()):
            if candidate.is_file() and not candidate.name.startswith("."):
                return candidate
    return None
