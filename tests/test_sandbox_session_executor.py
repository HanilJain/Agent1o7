"""Tests for `SandboxExecutor`'s session capability
(`start`/`exec_in_session`/`stop`) — Stage 5 FVVW v3 Phase 0.

Same discipline as `tests/test_sandbox_executor.py`: argv composition is
tested by monkeypatching `run_command`, no live Docker daemon required.
These tests exist specifically to guard the invariant that `run()` itself
is untouched by this addition — Joern's call sites must see zero behavior
change.
"""

from __future__ import annotations

from pathlib import Path

from fw_audit.config.settings import Settings
from fw_audit.executors.base import SessionHandle
from fw_audit.executors.docker_executor import CONTAINER_WORKDIR
from fw_audit.executors.sandbox_executor import SandboxExecutor
from fw_audit.stage1_ingestion.tools.extraction_tools import CommandResult


def _ok(binary: str, args: list[str], stdout: str = "") -> CommandResult:
    return CommandResult(
        command=[binary, *args], returncode=0, stdout=stdout, stderr="", timed_out=False
    )


async def test_start_composes_backgrounded_docker_run(monkeypatch, tmp_path: Path):
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["binary"] = binary
        captured["args"] = args
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(
        Settings(_env_file=None), image="fw-audit-verification-sandbox:latest"
    )
    handle = await executor.start(files=tmp_path)

    assert isinstance(handle, SessionHandle)
    assert handle.container_name.startswith("fw-audit-sandbox-session-")
    assert handle.workspace_dir == tmp_path.resolve()
    assert handle.network_name is None

    argv = captured["args"]
    assert argv[:3] == ["run", "-d", "--init"]
    assert "--network=none" in argv
    assert "--name" in argv
    assert "-v" in argv
    mount_arg = argv[argv.index("-v") + 1]
    assert mount_arg.endswith(f":{CONTAINER_WORKDIR}")
    assert "fw-audit-verification-sandbox:latest" in argv
    # Must keep the container alive — no `--rm`, and the entrypoint is a
    # long-running placeholder command, not the caller's actual work.
    assert "--rm" not in argv
    assert argv[-2:] == ["sleep", "infinity"]


async def test_start_with_network_grant_passes_named_network(monkeypatch, tmp_path: Path):
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["args"] = args
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    handle = await executor.start(files=tmp_path, network="fvvw-run-abc123")

    assert handle.network_name == "fvvw-run-abc123"
    assert "--network=fvvw-run-abc123" in captured["args"]
    assert "--network=none" not in captured["args"]


async def test_start_without_files_omits_mount(monkeypatch):
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["args"] = args
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    handle = await executor.start()

    assert handle.workspace_dir is None
    assert "-v" not in captured["args"]


async def test_start_raises_on_failure(monkeypatch):
    async def fake_run_command(binary, args, *, settings=None):
        return CommandResult(
            command=[binary, *args],
            returncode=1,
            stdout="",
            stderr="no such image",
            timed_out=False,
        )

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    try:
        await executor.start()
        raise AssertionError("expected RuntimeError")
    except RuntimeError as exc:
        assert "no such image" in str(exc)


async def test_exec_in_session_composes_docker_exec(monkeypatch):
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["binary"] = binary
        captured["args"] = args
        return _ok(binary, args, stdout="hello")

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    handle = SessionHandle(container_name="fw-audit-sandbox-session-abc123")
    result = await executor.exec_in_session(handle, "echo hello")

    assert result.ok
    assert result.stdout == "hello"
    assert captured["args"] == ["exec", "fw-audit-sandbox-session-abc123", "sh", "-c", "echo hello"]


async def test_exec_in_session_applies_custom_timeout(monkeypatch):
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["settings"] = settings
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    handle = SessionHandle(container_name="c1")
    await executor.exec_in_session(handle, "gdb-multiarch -batch -x recipe.gdb", timeout=77)

    assert captured["settings"].subprocess_timeout_seconds == 77


async def test_stop_removes_container(monkeypatch):
    calls: list[list[str]] = []

    async def fake_run_command(binary, args, *, settings=None):
        calls.append(args)
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    handle = SessionHandle(container_name="fw-audit-sandbox-session-xyz")
    await executor.stop(handle)

    assert calls == [["rm", "-f", "fw-audit-sandbox-session-xyz"]]


async def test_stop_also_removes_granted_network(monkeypatch):
    calls: list[list[str]] = []

    async def fake_run_command(binary, args, *, settings=None):
        calls.append(args)
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    handle = SessionHandle(container_name="c1", network_name="fvvw-run-abc123")
    await executor.stop(handle)

    assert ["rm", "-f", "c1"] in calls
    assert ["network", "rm", "fvvw-run-abc123"] in calls


async def test_stop_is_best_effort_on_failure(monkeypatch):
    """A failed `docker rm`/`docker network rm` must not raise — the caller
    has nothing further to retry, same posture as
    `_cleanup_orphaned_container`'s failed cleanup."""

    async def fake_run_command(binary, args, *, settings=None):
        return CommandResult(
            command=[binary, *args],
            returncode=1,
            stdout="",
            stderr="no such container",
            timed_out=False,
        )

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    handle = SessionHandle(container_name="already-gone")
    await executor.stop(handle)  # must not raise


def test_run_method_untouched_by_session_capability(monkeypatch, tmp_path: Path):
    """Regression guard: adding start/exec_in_session/stop must not change
    `run()`'s own composed argv (still one-shot `--rm`, no session
    machinery involved)."""
    import asyncio

    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["args"] = args
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    asyncio.run(executor.run("echo hi", files=tmp_path))

    argv = captured["args"]
    assert argv[:4] == ["run", "--rm", "--init", "--network=none"]
    assert "-d" not in argv
