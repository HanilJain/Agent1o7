"""Regression test for `stage5_verification.tools.joern_tool.joern_executor`
— it must always point at `Settings.stage5_joern_image`, never silently
fall back to `Settings.docker_image` (Stage 1's sandbox image, which has no
Joern installed). See that function's docstring for the bug this guards."""

from __future__ import annotations

from fw_audit.config.settings import Settings
from fw_audit.executors.docker_executor import DockerExecutor
from fw_audit.executors.local_executor import LocalExecutor
from fw_audit.stage5_verification.tools.joern_tool import joern_executor


def test_joern_executor_overrides_docker_image_on_default_backend():
    """FWA_EXECUTOR_BACKEND=docker (the default) must not silently reuse
    Settings.docker_image (fw-audit-sandbox:latest)."""
    settings = Settings(
        _env_file=None,
        FWA_DOCKER_IMAGE="fw-audit-sandbox:latest",
        FWA_STAGE5_JOERN_IMAGE="fw-audit-joern:latest",
    )
    executor = joern_executor(settings)

    assert isinstance(executor, DockerExecutor)
    assert executor._settings.docker_image == "fw-audit-joern:latest"


def test_joern_executor_applies_stage5_joern_timeout():
    settings = Settings(_env_file=None, FWA_STAGE5_JOERN_TIMEOUT_SECONDS=42)
    executor = joern_executor(settings)
    assert executor._settings.subprocess_timeout_seconds == 42


def test_joern_executor_respects_local_backend_for_dev():
    settings = Settings(_env_file=None, FWA_EXECUTOR_BACKEND="local")
    executor = joern_executor(settings)
    assert isinstance(executor, LocalExecutor)


async def test_joern_executor_docker_run_command_targets_joern_image(monkeypatch, tmp_path):
    """End-to-end argv check: the composed `docker run` command must name
    the Joern image, not Stage 1's sandbox image."""
    captured: dict = {}

    async def fake_run_command(binary, args, *, settings=None):
        from fw_audit.stage1_ingestion.tools.extraction_tools import CommandResult

        captured["args"] = args
        return CommandResult(
            command=[binary, *args], returncode=0, stdout="", stderr="", timed_out=False
        )

    monkeypatch.setattr("fw_audit.executors.docker_executor.run_command", fake_run_command)

    settings = Settings(
        _env_file=None,
        FWA_DOCKER_IMAGE="fw-audit-sandbox:latest",
        FWA_STAGE5_JOERN_IMAGE="fw-audit-joern:latest",
    )
    executor = joern_executor(settings)
    await executor.run("joern-parse whole.c --output cpg.bin", files=tmp_path)

    assert "fw-audit-joern:latest" in captured["args"]
    assert "fw-audit-sandbox:latest" not in captured["args"]
