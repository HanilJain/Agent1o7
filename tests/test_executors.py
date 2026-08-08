"""Interface conformance for the Executor abstraction.

Covers `fw_audit.executors`: `LocalExecutor`, `DockerExecutor`, and
`SandboxExecutor` all satisfy the same `Executor` contract, and
`manager.get_executor()` dispatches on `Settings.executor_backend`.
"""

from __future__ import annotations

import pytest

from fw_audit.config.settings import Settings
from fw_audit.executors import (
    DockerExecutor,
    Executor,
    ExecutionResult,
    LocalExecutor,
    SandboxExecutor,
    get_executor,
)


@pytest.mark.parametrize("cls", [DockerExecutor, LocalExecutor, SandboxExecutor])
def test_all_backends_subclass_executor(cls):
    assert issubclass(cls, Executor)


@pytest.mark.parametrize("cls", [DockerExecutor, LocalExecutor, SandboxExecutor])
def test_all_backends_share_constructor_signature(cls):
    # get_executor() dispatches via executor_cls(settings) uniformly; every
    # backend must accept an optional Settings positionally.
    instance = cls(Settings(_env_file=None))
    assert isinstance(instance, Executor)
    instance_default = cls()
    assert isinstance(instance_default, Executor)


def test_execution_result_ok_property():
    assert ExecutionResult(command="x", returncode=0, stdout="", stderr="", timed_out=False).ok
    assert not ExecutionResult(
        command="x", returncode=1, stdout="", stderr="", timed_out=False
    ).ok
    assert not ExecutionResult(
        command="x", returncode=0, stdout="", stderr="", timed_out=True
    ).ok


def test_get_executor_dispatches_docker():
    settings = Settings(_env_file=None, FWA_EXECUTOR_BACKEND="docker")
    assert isinstance(get_executor(settings), DockerExecutor)


def test_get_executor_dispatches_local():
    settings = Settings(_env_file=None, FWA_EXECUTOR_BACKEND="local")
    assert isinstance(get_executor(settings), LocalExecutor)


def test_get_executor_dispatches_sandbox():
    settings = Settings(_env_file=None, FWA_EXECUTOR_BACKEND="sandbox")
    assert isinstance(get_executor(settings), SandboxExecutor)


def test_get_executor_case_insensitive():
    settings = Settings(_env_file=None, FWA_EXECUTOR_BACKEND="LOCAL")
    assert isinstance(get_executor(settings), LocalExecutor)


def test_get_executor_unknown_backend_raises():
    settings = Settings(_env_file=None, FWA_EXECUTOR_BACKEND="not-a-real-backend")
    with pytest.raises(ValueError, match="Unknown FWA_EXECUTOR_BACKEND"):
        get_executor(settings)


def test_default_backend_is_docker():
    assert Settings(_env_file=None).executor_backend == "docker"


async def test_local_executor_runs_a_real_command():
    executor = LocalExecutor(Settings(_env_file=None))
    result = await executor.run("python --version")
    assert result.ok
    assert "Python" in (result.stdout + result.stderr)


async def test_local_executor_missing_binary_reports_failure():
    executor = LocalExecutor(Settings(_env_file=None))
    result = await executor.run("definitely_not_a_real_binary_xyz")
    assert not result.ok
    assert result.returncode is None


async def test_local_executor_empty_command():
    executor = LocalExecutor(Settings(_env_file=None))
    result = await executor.run("")
    assert not result.ok


async def test_sandbox_executor_run_raises_not_implemented():
    executor = SandboxExecutor()
    with pytest.raises(NotImplementedError, match="reserved for future"):
        await executor.run("echo hi")


def test_sandbox_executor_unavailable():
    assert SandboxExecutor().available() is False
