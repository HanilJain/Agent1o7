"""Tests for `fw_audit.stage5_verification.tools.joern_tool` — command
composition and result-record assembly, using the shared `FakeExecutor`
fixture (no live Docker/Joern required)."""

from __future__ import annotations

from pathlib import Path

from fw_audit.config.settings import Settings
from fw_audit.executors.base import ExecutionResult
from fw_audit.stage5_verification.tools.joern_tool import (
    CPG_FILENAME,
    SOURCE_FILENAME,
    build_cpg_async,
    joern_parse_command,
    joern_script_command,
    run_joern_script_async,
)


def test_joern_parse_command_shape():
    assert joern_parse_command() == f"joern-parse {SOURCE_FILENAME} --output {CPG_FILENAME}"


def test_joern_script_command_shape():
    # Positional CPG argument, not `--param cpgPath=` — verified against a
    # real Joern 4.0.420 build; `--param` only binds to a script-declared
    # `@main` signature, which a plain expression script doesn't have. See
    # this module's docstring for the full story.
    assert (
        joern_script_command("query_000.sc")
        == f"joern --script query_000.sc {CPG_FILENAME}"
    )


async def test_build_cpg_async_ok_when_executor_succeeds_and_cpg_file_exists(
    fake_executor, tmp_path: Path
):
    workspace = tmp_path
    (workspace / CPG_FILENAME).write_bytes(b"fake cpg")

    executor = fake_executor()
    record = await build_cpg_async(
        workspace_dir=workspace, executor=executor, settings=Settings(_env_file=None)
    )

    assert record.ok
    assert record.command == joern_parse_command()
    assert len(executor.calls) == 1
    assert executor.calls[0] == (joern_parse_command(), workspace)


async def test_build_cpg_async_not_ok_when_cpg_file_never_written(fake_executor, tmp_path: Path):
    """Even if the executor reports returncode 0, a missing cpg.bin on disk
    means the build did not actually succeed — guards against a Joern
    invocation that silently no-ops."""
    executor = fake_executor()
    record = await build_cpg_async(
        workspace_dir=tmp_path, executor=executor, settings=Settings(_env_file=None)
    )
    assert not record.ok


async def test_build_cpg_async_reports_executor_failure(fake_executor, tmp_path: Path):
    def on_run(command, files):
        return ExecutionResult(
            command=command, returncode=1, stdout="", stderr="parse error", timed_out=False
        )

    executor = fake_executor(on_run)
    record = await build_cpg_async(
        workspace_dir=tmp_path, executor=executor, settings=Settings(_env_file=None)
    )
    assert not record.ok
    assert record.stderr == "parse error"


async def test_run_joern_script_async_writes_script_file_and_returns_attempt(
    fake_executor, tmp_path: Path
):
    def on_run(command, files):
        return ExecutionResult(
            command=command, returncode=0, stdout="query output", stderr="", timed_out=False
        )

    executor = fake_executor(on_run)
    attempt = await run_joern_script_async(
        "cpg.method.l",
        attempt_index=0,
        workspace_dir=tmp_path,
        executor=executor,
        settings=Settings(_env_file=None),
    )

    assert attempt.ok
    assert attempt.script == "cpg.method.l"
    assert attempt.stdout == "query output"
    assert (tmp_path / "query_000.sc").read_text(encoding="utf-8") == "cpg.method.l"
    assert executor.calls[0][0] == joern_script_command("query_000.sc")


async def test_run_joern_script_async_reports_failure(fake_executor, tmp_path: Path):
    def on_run(command, files):
        return ExecutionResult(
            command=command, returncode=1, stdout="", stderr="syntax error", timed_out=False
        )

    executor = fake_executor(on_run)
    attempt = await run_joern_script_async(
        "bad scala",
        attempt_index=3,
        workspace_dir=tmp_path,
        executor=executor,
        settings=Settings(_env_file=None),
    )

    assert not attempt.ok
    assert attempt.stderr == "syntax error"
    assert attempt.attempt_index == 3
    assert (tmp_path / "query_003.sc").is_file()
