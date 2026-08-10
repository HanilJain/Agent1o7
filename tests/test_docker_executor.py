"""Tests for fw_audit.executors.docker_executor.

argv composition is tested by monkeypatching `run_command` — no live Docker
daemon required for these. `available()` does hit a real (sub)process, so
its assertions are behavior-shape only (return type), not daemon-state.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fw_audit.config.settings import Settings
from fw_audit.executors.docker_executor import (
    CONTAINER_WORKDIR,
    DockerExecutor,
    to_container_path,
)
from fw_audit.stage1_ingestion.tools.extraction_tools import CommandResult


def _ok(binary: str, args: list[str]) -> CommandResult:
    return CommandResult(
        command=[binary, *args], returncode=0, stdout="", stderr="", timed_out=False
    )


async def test_run_composes_docker_run_argv(monkeypatch, tmp_path: Path):
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["binary"] = binary
        captured["args"] = args
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.docker_executor.run_command", fake_run_command)

    settings = Settings(_env_file=None, FWA_DOCKER_IMAGE="fw-audit-sandbox:latest")
    executor = DockerExecutor(settings)
    result = await executor.run("binwalk -e fw.bin", files=tmp_path)

    assert result.ok
    assert captured["binary"] == "docker"
    argv = captured["args"]
    assert argv[:5] == ["run", "--rm", "--init", "--network=none", "--name"]
    assert "-v" in argv
    mount_arg = argv[argv.index("-v") + 1]
    assert mount_arg.endswith(f":{CONTAINER_WORKDIR}")
    assert "fw-audit-sandbox:latest" in argv
    assert argv[-3:] == ["sh", "-c", "binwalk -e fw.bin"]


async def test_run_without_files_omits_mount(monkeypatch):
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["args"] = args
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.docker_executor.run_command", fake_run_command)

    executor = DockerExecutor(Settings(_env_file=None))
    await executor.run("echo hi")

    assert "-v" not in captured["args"]


async def test_run_forces_empty_command_prefix(monkeypatch):
    """The `docker` invocation itself must never be routed through settings.command_prefix."""
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["settings"] = settings
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.docker_executor.run_command", fake_run_command)

    settings = Settings(_env_file=None, FWA_COMMAND_PREFIX="wsl")
    executor = DockerExecutor(settings)
    await executor.run("echo hi")

    assert captured["settings"].command_prefix == []


def test_to_container_path_translates_relative_to_mount(tmp_path: Path):
    sub = tmp_path / "bin" / "httpd"
    sub.parent.mkdir(parents=True)
    sub.write_bytes(b"x")
    assert to_container_path(sub, tmp_path) == f"{CONTAINER_WORKDIR}/bin/httpd"


def test_to_container_path_root_itself(tmp_path: Path):
    assert to_container_path(tmp_path, tmp_path) == CONTAINER_WORKDIR


def test_to_container_path_outside_mount_raises(tmp_path: Path):
    outside = tmp_path.parent / "elsewhere"
    with pytest.raises(ValueError, match="not inside the mounted workspace"):
        to_container_path(outside, tmp_path)


def test_available_returns_bool():
    # Behavior-shape assertion only: whatever the real Docker daemon state is
    # on the test machine, `available()` must return a plain bool, never raise.
    result = DockerExecutor(Settings(_env_file=None)).available()
    assert isinstance(result, bool)


def test_available_false_when_docker_binary_missing():
    settings = Settings(_env_file=None, FWA_DOCKER_BIN="definitely_not_a_real_docker_xyz")
    assert DockerExecutor(settings).available() is False


async def test_run_names_the_container_uniquely(monkeypatch, tmp_path: Path):
    """Each run gets its own `--name`, so a timeout can address it for cleanup."""
    seen_names: list[str] = []

    async def fake_run_command(binary, args, *, settings=None):
        seen_names.append(args[args.index("--name") + 1])
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.docker_executor.run_command", fake_run_command)

    executor = DockerExecutor(Settings(_env_file=None))
    await executor.run("echo one", files=tmp_path)
    await executor.run("echo two", files=tmp_path)

    assert len(seen_names) == 2
    assert seen_names[0] != seen_names[1]
    assert all(name.startswith("fw-audit-") for name in seen_names)


async def test_timeout_issues_force_remove_of_orphaned_container(monkeypatch, tmp_path: Path):
    """On a timed-out run, DockerExecutor best-effort `docker rm -f`s the
    container it named, since dockerd (not the killed CLI process) owns it."""
    calls: list[list[str]] = []

    async def fake_run_command(binary, args, *, settings=None):
        calls.append(args)
        if args and args[0] == "run":
            return CommandResult(
                command=[binary, *args], returncode=None, stdout="", stderr="", timed_out=True
            )
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.docker_executor.run_command", fake_run_command)

    executor = DockerExecutor(Settings(_env_file=None))
    result = await executor.run("sleep 9999", files=tmp_path)

    assert result.timed_out
    rm_calls = [c for c in calls if c[0] == "rm"]
    assert len(rm_calls) == 1
    assert rm_calls[0][1] == "-f"
    run_name = calls[0][calls[0].index("--name") + 1]
    assert rm_calls[0][2] == run_name


async def test_timeout_cleanup_failure_appended_to_stderr_not_raised(monkeypatch, tmp_path: Path):
    async def fake_run_command(binary, args, *, settings=None):
        if args and args[0] == "run":
            return CommandResult(
                command=[binary, *args],
                returncode=None,
                stdout="",
                stderr="original",
                timed_out=True,
            )
        return CommandResult(
            command=[binary, *args],
            returncode=1,
            stdout="",
            stderr="no such container",
            timed_out=False,
        )

    monkeypatch.setattr("fw_audit.executors.docker_executor.run_command", fake_run_command)

    executor = DockerExecutor(Settings(_env_file=None))
    result = await executor.run("sleep 9999", files=tmp_path)

    assert result.timed_out
    assert "original" in result.stderr
    assert "cleanup" in result.stderr
    assert "no such container" in result.stderr
