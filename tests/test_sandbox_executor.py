"""Tests for fw_audit.executors.sandbox_executor.

Same discipline as `tests/test_docker_executor.py`: argv composition is
tested by monkeypatching `run_command` — no live Docker daemon required.
`available()` does hit a real (sub)process, so its assertion is
behavior-shape only.
"""

from __future__ import annotations

from pathlib import Path

from fw_audit.config.settings import Settings
from fw_audit.executors.docker_executor import CONTAINER_WORKDIR
from fw_audit.executors.sandbox_executor import SandboxExecutor
from fw_audit.stage1_ingestion.tools.extraction_tools import CommandResult


def _ok(binary: str, args: list[str]) -> CommandResult:
    return CommandResult(
        command=[binary, *args], returncode=0, stdout="", stderr="", timed_out=False
    )


async def test_run_composes_docker_run_argv_with_resource_limits(monkeypatch, tmp_path: Path):
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["binary"] = binary
        captured["args"] = args
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    settings = Settings(
        _env_file=None,
        FWA_STAGE5_SANDBOX_MEMORY="2g",
        FWA_STAGE5_SANDBOX_CPUS="1.5",
        FWA_STAGE5_SANDBOX_PIDS_LIMIT="128",
    )
    executor = SandboxExecutor(settings, image="fw-audit-joern:latest")
    result = await executor.run("joern-parse whole.c --output cpg.bin", files=tmp_path)

    assert result.ok
    assert captured["binary"] == "docker"
    argv = captured["args"]
    assert argv[:5] == ["run", "--rm", "--init", "--network=none", "--name"]
    assert "--memory=2g" in argv
    assert "--cpus=1.5" in argv
    assert "--pids-limit=128" in argv
    assert "-v" in argv
    mount_arg = argv[argv.index("-v") + 1]
    assert mount_arg.endswith(f":{CONTAINER_WORKDIR}")
    assert "fw-audit-joern:latest" in argv
    assert argv[-3:] == ["sh", "-c", "joern-parse whole.c --output cpg.bin"]


async def test_run_defaults_to_settings_docker_image_when_no_image_given(
    monkeypatch, tmp_path: Path
):
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["args"] = args
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    settings = Settings(_env_file=None, FWA_DOCKER_IMAGE="some-other-image:latest")
    executor = SandboxExecutor(settings)
    await executor.run("echo hi")

    assert "some-other-image:latest" in captured["args"]


async def test_run_without_files_omits_mount(monkeypatch):
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        captured["args"] = args
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    await executor.run("echo hi")

    assert "-v" not in captured["args"]


async def test_run_names_the_container_uniquely(monkeypatch, tmp_path: Path):
    seen_names: list[str] = []

    async def fake_run_command(binary, args, *, settings=None):
        seen_names.append(args[args.index("--name") + 1])
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    await executor.run("echo one", files=tmp_path)
    await executor.run("echo two", files=tmp_path)

    assert len(seen_names) == 2
    assert seen_names[0] != seen_names[1]
    assert all(name.startswith("fw-audit-sandbox-") for name in seen_names)


async def test_timeout_issues_force_remove_of_orphaned_container(monkeypatch, tmp_path: Path):
    calls: list[list[str]] = []

    async def fake_run_command(binary, args, *, settings=None):
        calls.append(args)
        if args and args[0] == "run":
            return CommandResult(
                command=[binary, *args], returncode=None, stdout="", stderr="", timed_out=True
            )
        return _ok(binary, args)

    monkeypatch.setattr("fw_audit.executors.sandbox_executor.run_command", fake_run_command)

    executor = SandboxExecutor(Settings(_env_file=None))
    result = await executor.run("sleep 9999", files=tmp_path)

    assert result.timed_out
    rm_calls = [c for c in calls if c[0] == "rm"]
    assert len(rm_calls) == 1
    assert rm_calls[0][1] == "-f"


def test_available_returns_bool():
    result = SandboxExecutor(Settings(_env_file=None)).available()
    assert isinstance(result, bool)


def test_available_false_when_docker_binary_missing():
    settings = Settings(_env_file=None, FWA_DOCKER_BIN="definitely_not_a_real_docker_xyz")
    assert SandboxExecutor(settings).available() is False
