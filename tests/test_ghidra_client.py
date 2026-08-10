"""Tests for fw_audit.stage2_extraction.ghidra.client.

`FakeExecutor`'s `on_run` writes canned `raw/metadata.json` (etc.) under
`files` — the same idiom `tests/test_graph_integration.py` uses for binwalk.
"""

from __future__ import annotations

import json
from pathlib import Path

from fw_audit.common.schemas import DecompilationStatus, ELFArch, ELFInfo
from fw_audit.config.settings import Settings
from fw_audit.executors.base import ExecutionResult
from fw_audit.stage2_extraction.ghidra.client import decompile_binary
from fw_audit.stage2_extraction.resolve import Resolution, ResolvedBinary


def _resolved(host_path: Path, *, arch: ELFArch = ELFArch.MIPS) -> ResolvedBinary:
    return ResolvedBinary(
        requested="bin/httpd",
        host_path=host_path,
        rootfs_rel="bin/httpd",
        sha256="a" * 64,
        size_bytes=1024,
        elf=ELFInfo(
            path="bin/httpd",
            absolute_path=str(host_path),
            size_bytes=1024,
            arch=arch,
            is_64bit=False,
            is_little_endian=True,
        ),
        resolution=Resolution.DIRECT,
    )


def _out_dir(files: Path, bin_id: str) -> Path:
    return files / "stage2" / "binaries" / bin_id / "raw"


def _write_metadata(out_dir: Path, *, status: str = "succeeded", functions=None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "program": {"name": "httpd"},
        "analysis": {
            "status": status,
            "elapsed_seconds": 1.0,
            "skipped_functions": [],
            "decompile_failures": [],
        },
        "functions": functions or [],
        "imports": [],
        "exports": [],
        "strings": [],
    }
    (out_dir / "metadata.json").write_text(json.dumps(payload), encoding="utf-8")


def _setup_rootfs(work_dir: Path) -> tuple[Path, Path]:
    rootfs = work_dir / "binwalk_1" / "squashfs-root"
    (rootfs / "bin").mkdir(parents=True)
    host_path = rootfs / "bin" / "httpd"
    host_path.write_bytes(b"\x7fELF")
    return rootfs, host_path


async def test_decompile_binary_happy_path(work_dir, fake_executor):
    rootfs, host_path = _setup_rootfs(work_dir)

    def on_run(command, files):
        out_dir = _out_dir(files, "bin_httpd")
        _write_metadata(
            out_dir,
            functions=[
                {
                    "name": "main",
                    "entry_point": "00401000",
                    "size": 100,
                    "signature": "void main(void)",
                    "calls": [],
                    "called_by": [],
                    "decompiled": True,
                }
            ],
        )
        (out_dir / "decompiled").mkdir(parents=True, exist_ok=True)
        (out_dir / "decompiled" / "whole.c").write_text("void main(void) {}\n", encoding="utf-8")
        return None

    result = await decompile_binary(
        _resolved(host_path),
        run_id="run1",
        bin_id="bin_httpd",
        workspace=work_dir,
        rootfs_dir=rootfs,
        stage2_dir=work_dir / "stage2",
        settings=Settings(_env_file=None),
        executor=fake_executor(on_run),
    )

    assert result.status == DecompilationStatus.SUCCEEDED
    assert result.function_count == 1
    assert result.decompiled_function_count == 1
    assert result.artifacts.raw_c is not None
    assert result.artifacts.metadata_json is not None
    # Artifact paths are relative to db_subfolder, per the Stage2Summary contract.
    assert not Path(result.artifacts.raw_c).is_absolute()


async def test_decompile_binary_nonzero_exit_is_failed(work_dir, fake_executor):
    rootfs, host_path = _setup_rootfs(work_dir)

    def on_run(command, files):
        return ExecutionResult(
            command=command, returncode=1, stdout="", stderr="segfault in analyzer", timed_out=False
        )

    result = await decompile_binary(
        _resolved(host_path),
        run_id="run1",
        bin_id="bin_httpd",
        workspace=work_dir,
        rootfs_dir=rootfs,
        stage2_dir=work_dir / "stage2",
        settings=Settings(_env_file=None),
        executor=fake_executor(on_run),
    )

    assert result.status == DecompilationStatus.FAILED
    assert any("segfault in analyzer" in e for e in result.errors)


async def test_decompile_binary_timeout_is_timed_out(work_dir, fake_executor):
    rootfs, host_path = _setup_rootfs(work_dir)

    def on_run(command, files):
        return ExecutionResult(
            command=command, returncode=None, stdout="", stderr="", timed_out=True
        )

    result = await decompile_binary(
        _resolved(host_path),
        run_id="run1",
        bin_id="bin_httpd",
        workspace=work_dir,
        rootfs_dir=rootfs,
        stage2_dir=work_dir / "stage2",
        settings=Settings(_env_file=None),
        executor=fake_executor(on_run),
    )

    assert result.status == DecompilationStatus.TIMED_OUT
    assert any("timed out" in e for e in result.errors)


async def test_decompile_binary_ok_but_no_metadata_is_failed(work_dir, fake_executor):
    """command ok + no metadata.json = a bug in the export script or
    invocation, not a binary-specific failure — must be reported as such."""
    rootfs, host_path = _setup_rootfs(work_dir)

    def on_run(command, files):
        return None  # default success, but writes nothing

    result = await decompile_binary(
        _resolved(host_path),
        run_id="run1",
        bin_id="bin_httpd",
        workspace=work_dir,
        rootfs_dir=rootfs,
        stage2_dir=work_dir / "stage2",
        settings=Settings(_env_file=None),
        executor=fake_executor(on_run),
    )

    assert result.status == DecompilationStatus.FAILED
    assert any("produced no metadata.json" in e for e in result.errors)


async def test_decompile_binary_malformed_metadata_is_partial(work_dir, fake_executor):
    rootfs, host_path = _setup_rootfs(work_dir)

    def on_run(command, files):
        out_dir = _out_dir(files, "bin_httpd")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "metadata.json").write_text("{not valid json", encoding="utf-8")
        return None

    result = await decompile_binary(
        _resolved(host_path),
        run_id="run1",
        bin_id="bin_httpd",
        workspace=work_dir,
        rootfs_dir=rootfs,
        stage2_dir=work_dir / "stage2",
        settings=Settings(_env_file=None),
        executor=fake_executor(on_run),
    )

    assert result.status == DecompilationStatus.PARTIAL
    assert any("malformed" in e for e in result.errors)


async def test_decompile_binary_partial_analysis_status_maps_to_partial(work_dir, fake_executor):
    rootfs, host_path = _setup_rootfs(work_dir)

    def on_run(command, files):
        _write_metadata(_out_dir(files, "bin_httpd"), status="partial")
        return None

    result = await decompile_binary(
        _resolved(host_path),
        run_id="run1",
        bin_id="bin_httpd",
        workspace=work_dir,
        rootfs_dir=rootfs,
        stage2_dir=work_dir / "stage2",
        settings=Settings(_env_file=None),
        executor=fake_executor(on_run),
    )

    assert result.status == DecompilationStatus.PARTIAL


async def test_decompile_binary_retries_with_processor_on_loader_failure(work_dir, fake_executor):
    """A loader-failure on the processor-unspecified first attempt triggers
    a second attempt with -processor forced, using the resolved ELF arch."""
    rootfs, host_path = _setup_rootfs(work_dir)
    calls: list[str] = []

    def on_run(command, files):
        calls.append(command)
        if "-processor" not in command:
            return ExecutionResult(
                command=command,
                returncode=1,
                stdout="",
                stderr="Unable to identify a suitable loader",
                timed_out=False,
            )
        _write_metadata(_out_dir(files, "bin_httpd"))
        return None

    result = await decompile_binary(
        _resolved(host_path, arch=ELFArch.MIPS),
        run_id="run1",
        bin_id="bin_httpd",
        workspace=work_dir,
        rootfs_dir=rootfs,
        stage2_dir=work_dir / "stage2",
        settings=Settings(_env_file=None),
        executor=fake_executor(on_run),
    )

    assert len(calls) == 2
    assert "-processor" not in calls[0]
    # _resolved()'s ELFInfo is little-endian MIPS (is_little_endian=True).
    assert "-processor MIPS:LE:32:default" in calls[1]
    assert result.status == DecompilationStatus.SUCCEEDED


async def test_decompile_binary_no_retry_when_elf_unknown(work_dir, fake_executor):
    """No language ID to try -> no retry attempt at all, just report the failure."""
    rootfs, host_path = _setup_rootfs(work_dir)
    calls: list[str] = []

    def on_run(command, files):
        calls.append(command)
        return ExecutionResult(
            command=command,
            returncode=1,
            stdout="",
            stderr="Unable to identify a suitable loader",
            timed_out=False,
        )

    result = await decompile_binary(
        _resolved(host_path, arch=ELFArch.UNKNOWN),
        run_id="run1",
        bin_id="bin_httpd",
        workspace=work_dir,
        rootfs_dir=rootfs,
        stage2_dir=work_dir / "stage2",
        settings=Settings(_env_file=None),
        executor=fake_executor(on_run),
    )

    assert len(calls) == 1
    assert result.status == DecompilationStatus.FAILED


async def test_decompile_binary_carries_resolution_metadata_through(work_dir, fake_executor):
    rootfs, host_path = _setup_rootfs(work_dir)

    def on_run(command, files):
        _write_metadata(_out_dir(files, "bin_httpd"))
        return None

    resolved = _resolved(host_path)
    result = await decompile_binary(
        resolved,
        run_id="run1",
        bin_id="bin_httpd__deadbeefcafe",
        workspace=work_dir,
        rootfs_dir=rootfs,
        stage2_dir=work_dir / "stage2",
        settings=Settings(_env_file=None),
        executor=fake_executor(on_run),
    )

    assert result.bin_id == "bin_httpd__deadbeefcafe"
    assert result.rootfs_path == resolved.rootfs_rel
    assert result.requested_path == resolved.requested
    assert result.sha256 == resolved.sha256
