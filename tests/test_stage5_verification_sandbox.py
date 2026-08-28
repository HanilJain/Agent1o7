"""Tests for `stage5_verification.tools.verification_sandbox` — Stage 5
FVVW v3 Phase 0. Mirrors `tests/test_stage5_joern_executor.py`'s shape:
the regression this guards is the same class of bug (silently resolving
the WRONG image) but for the new verification-sandbox image instead of the
Joern image, and additionally guards that the two never collide.
"""

from __future__ import annotations

from fw_audit.config.settings import Settings
from fw_audit.executors.docker_executor import DockerExecutor
from fw_audit.executors.local_executor import LocalExecutor
from fw_audit.executors.sandbox_executor import SandboxExecutor
from fw_audit.stage5_verification.tools.verification_sandbox import (
    verification_executor,
    verification_session_executor,
)


def test_verification_executor_overrides_docker_image_on_default_backend():
    settings = Settings(
        _env_file=None,
        FWA_DOCKER_IMAGE="fw-audit-sandbox:latest",
        FWA_STAGE5_VERIFICATION_IMAGE="fw-audit-verification-sandbox:latest",
    )
    executor = verification_executor(settings)

    assert isinstance(executor, DockerExecutor)
    assert executor._settings.docker_image == "fw-audit-verification-sandbox:latest"


def test_verification_executor_never_resolves_joern_image():
    settings = Settings(
        _env_file=None,
        FWA_STAGE5_JOERN_IMAGE="fw-audit-joern:latest",
        FWA_STAGE5_VERIFICATION_IMAGE="fw-audit-verification-sandbox:latest",
    )
    executor = verification_executor(settings)
    assert executor._settings.docker_image != "fw-audit-joern:latest"
    assert executor._settings.docker_image == "fw-audit-verification-sandbox:latest"


def test_verification_executor_applies_qemu_timeout():
    settings = Settings(_env_file=None, FWA_STAGE5_QEMU_TIMEOUT_SECONDS=42)
    executor = verification_executor(settings)
    assert executor._settings.subprocess_timeout_seconds == 42


def test_verification_executor_respects_local_backend_for_dev():
    settings = Settings(_env_file=None, FWA_EXECUTOR_BACKEND="local")
    executor = verification_executor(settings)
    assert isinstance(executor, LocalExecutor)


def test_verification_session_executor_returns_sandbox_executor_regardless_of_backend():
    """The dynamic track always needs a real session; FWA_EXECUTOR_BACKEND
    (which governs the one-shot `verification_executor()`/`joern_executor()`
    resolution) must NOT affect this — there is no session equivalent for
    the local/docker backends to select."""
    for backend in ("docker", "local", "sandbox"):
        settings = Settings(
            _env_file=None,
            FWA_EXECUTOR_BACKEND=backend,
            FWA_STAGE5_VERIFICATION_IMAGE="fw-audit-verification-sandbox:latest",
        )
        session_executor = verification_session_executor(settings)
        assert isinstance(session_executor, SandboxExecutor)
        assert session_executor._image == "fw-audit-verification-sandbox:latest"


async def test_verification_executor_docker_run_command_targets_verification_image(
    monkeypatch, tmp_path
):
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
        FWA_STAGE5_VERIFICATION_IMAGE="fw-audit-verification-sandbox:latest",
    )
    executor = verification_executor(settings)
    await executor.run("binwalk -e fw.bin", files=tmp_path)

    assert "fw-audit-verification-sandbox:latest" in captured["args"]
    assert "fw-audit-joern:latest" not in captured["args"]
    assert "fw-audit-sandbox:latest" not in captured["args"]
